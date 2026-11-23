const express = require('express');
const mysql = require('mysql2/promise');
const path = require('path');
const virusTotalRouter = require('./Sandbox/VirusTotal/router');

const app = express();
const PORT = Number(process.env.PORT) || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname)));
app.use('/api/virustotal', virusTotalRouter);

// Connect to MariaDB
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'phishing_net',
  port: Number(process.env.DB_PORT) || 3306
});

async function ensureSchema() {
  const [columns] = await pool.query(
    `SELECT COLUMN_NAME
     FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE()
       AND TABLE_NAME = 'scan_log'
       AND COLUMN_NAME = 'ExecutedAt'`
  );

  if (columns.length === 0) {
    await pool.query(
      `ALTER TABLE scan_log
       ADD COLUMN ExecutedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP`
    );
  }
}

ensureSchema().catch((error) => {
  console.error('Database schema initialization failed:', error);
});

// GET accounts
app.get('/api/accounts', async (_req, res) => {
  try {
    const [accounts] = await pool.query(
      `SELECT AccountId, Email, FirstName, LastName
       FROM user_accounts
       ORDER BY FirstName, LastName, Email`
    );
    res.json(accounts);
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to load accounts' });
  }
});

// POST account
app.post('/api/accounts', async (req, res) => {
  const { email, firstName, lastName } = req.body || {};

  if (
    typeof email !== 'string' ||
    typeof firstName !== 'string' ||
    typeof lastName !== 'string'
  ) {
    return res.status(400).json({
      error: 'Email, first name, and last name must be strings.'
    });
  }

  const normalizedEmail = email.trim();
  const normalizedFirstName = firstName.trim();
  const normalizedLastName = lastName.trim();

  if (!normalizedEmail || !normalizedFirstName || !normalizedLastName) {
    return res.status(400).json({
      error: 'Email, first name, and last name are required.'
    });
  }

  try {
    const [result] = await pool.query(
      `INSERT INTO user_accounts (Email, FirstName, LastName)
       VALUES (?, ?, ?)`,
      [normalizedEmail, normalizedFirstName, normalizedLastName]
    );

    res.status(201).json({
      message: 'Account created successfully!',
      accountId: result.insertId
    });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'An account with that email already exists.' });
    }

    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to create account' });
  }
});

// POST endpoint
app.post('/api/scans', async (req, res) => {
  const { accountId, emailAddress, subject, emailContent, attachedLink, attachedFile, riskScore } = req.body || {};

  if (!emailAddress) {
    return res.status(400).json({ error: 'Email address is required.' });
  }

  if (!Number.isInteger(accountId) || accountId < 1) {
    return res.status(400).json({ error: 'A logged-in account is required.' });
  }

  try {
    const sql = `
      INSERT INTO scan_log (AccountId, EmailAddress, Subject, EmailContent, AttachedLink, AttachedFile, RiskScore, ExecutedAt)
      VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `;
    
    const [result] = await pool.query(sql, [
      accountId,
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
    if (error.code === 'ER_NO_REFERENCED_ROW_2') {
      return res.status(400).json({ error: 'The specified account does not exist.' });
    }

    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to save scan data' });
  }
});

// GET scans for one logged-in account
app.get('/api/accounts/:accountId/scans', async (req, res) => {
  const accountId = Number(req.params.accountId);

  if (!Number.isInteger(accountId) || accountId < 1) {
    return res.status(400).json({ error: 'A valid account ID is required.' });
  }

  try {
    const [scans] = await pool.query(
      `SELECT Id, AccountId, EmailAddress, Subject, EmailContent,
              AttachedLink, AttachedFile, RiskScore, ExecutedAt
       FROM scan_log
       WHERE AccountId = ?
       ORDER BY ExecutedAt DESC, Id DESC`,
      [accountId]
    );
    res.json(scans);
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to load scans' });
  }
});

// Start the express server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});