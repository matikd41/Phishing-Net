const express = require('express');
const mysql = require('mysql2/promise');
const path = require('path');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const fsp = require('fs/promises');

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname)));

// Connect to MariaDB
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'bePreV4t#oc7',
  database: 'phishing_net',
  port: 3306
});

const upload = multer({
  dest: path.join(__dirname, 'quarantine'),
  limits: { fileSize: 25 * 1024 * 1024 }
});

function hashFile(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    fs.createReadStream(filePath)
      .on('data', (chunk) => hash.update(chunk))
      .on('end', () => resolve(hash.digest('hex')))
      .on('error', reject);
  });
}

// POST endpoint: up to 5 files per scan
app.post('/api/scans', upload.array('files', 5), async (req, res) => {
  const { emailAddress, subject, emailContent, attachedLink } = req.body;
  const files = req.files || [];

  const cleanup = () =>
    Promise.all(files.map((f) => fsp.unlink(f.path).catch(() => {})));

  if (!emailAddress) {
    await cleanup();
    return res.status(400).json({ error: 'Email address is required.' });
  }

  try {
    const fileHashes = await Promise.all(files.map((f) => hashFile(f.path)));

    const sql = `
      INSERT INTO scan_log (EmailAddress, Subject, EmailContent, AttachedLink, AttachedFile, RiskScore)
      VALUES (?, ?, ?, ?, ?, ?)
    `;

    const [result] = await pool.query(sql, [
      emailAddress,
      subject || null,
      emailContent || null,
      attachedLink || null,
      fileHashes.length ? fileHashes.join(',') : null,
      0.00
    ]);

    res.status(201).json({
      message: 'Scan logged successfully!',
      scanId: result.insertId,
      fileHashes
    });
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to save scan data' });
  } finally {
    await cleanup();
  }
});

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: err.message });
  }
  next(err);
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});