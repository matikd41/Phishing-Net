const express = require('express');
const multer = require('multer');
const { getAnalysis, getFileReport, uploadFile } = require('./virusTotal');

const MAX_FILE_SIZE = 32 * 1024 * 1024;
const router = express.Router();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_SIZE, files: 1, fields: 1, parts: 2 }
});

router.post('/scan', upload.single('file'), async (req, res) => {
  if (req.body.consent !== 'true') {
    return res.status(400).json({ error: 'Explicit VirusTotal upload consent is required.' });
  }
  if (!req.file) {
    return res.status(400).json({ error: 'Choose one attachment to scan.' });
  }

  try {
    const scan = await uploadFile(req.file);
    return res.status(202).json({
      ...scan,
      fileName: req.file.originalname,
    });
  } catch (error) {
    console.error('VirusTotal upload failed:', error.message);
    return res.status(error.statusCode || 502).json({ error: error.message });
  }
});

router.get('/files', async (req, res) => {
  const sha256 = req.query.sha256;
  if (typeof sha256 !== 'string' || !/^[a-fA-F0-9]{64}$/.test(sha256)) {
    return res.status(400).json({ error: 'Invalid file SHA-256.' });
  }

  try {
    return res.json(await getFileReport(sha256.toLowerCase()));
  } catch (error) {
    if (error.statusCode === 404 || error.virusTotalCode === 'NotAvailableYet') {
      return res.json({ sha256: sha256.toLowerCase(), status: 'queued', stats: null });
    }
    console.error('VirusTotal file report lookup failed:', error.message);
    return res.status(error.statusCode || 502).json({ error: error.message });
  }
});

router.get('/analyses', async (req, res) => {
  const analysisId = req.query.analysisId;
  if (typeof analysisId !== 'string' || analysisId.length > 512 || /[\u0000-\u001f\u007f]/.test(analysisId)) {
    return res.status(400).json({ error: 'Invalid VirusTotal analysis ID.' });
  }

  try {
    return res.json(await getAnalysis(analysisId));
  } catch (error) {
    console.error('VirusTotal analysis lookup failed:', error.message);
    return res.status(error.statusCode || 502).json({ error: error.message });
  }
});

router.use((error, req, res, next) => {
  if (!(error instanceof multer.MulterError)) {
    return next(error);
  }

  if (error.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ error: 'Attachment exceeds the 32 MB upload limit.' });
  }

  return res.status(400).json({ error: 'Upload one attachment at a time.' });
});

module.exports = router;
