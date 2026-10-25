const express = require('express');
const mysql = require('mysql2/promise');
const path = require('path');

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

// POST endpoint
app.post('/api/scans', async (req, res) => {
  const { emailAddress, subject, emailContent, attachedLink, attachedFile, riskScore } = req.body;

  if (!emailAddress) {
    return res.status(400).json({ error: 'Email address is required.' });
  }

  try {
    const sql = `
      INSERT INTO scan_log (EmailAddress, Subject, EmailContent, AttachedLink, AttachedFile, RiskScore) 
      VALUES (?, ?, ?, ?, ?, ?)
    `;
    
    const [result] = await pool.query(sql, [
      emailAddress, 
      subject || null,    
      emailContent || null,
      attachedLink || null, 
      attachedFile || null,
      riskScore || 0.00 
    ]);

    res.status(201).json({
      message: 'Scan logged successfully!',
      scanId: result.insertId
    });
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to save scan data' });
  }
});

// Start the express server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});