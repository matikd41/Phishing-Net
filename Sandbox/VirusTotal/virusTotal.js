const { createHash } = require('node:crypto');

const VIRUSTOTAL_API = 'https://www.virustotal.com/api/v3';
const REQUEST_TIMEOUT_MS = 120000;

class VirusTotalError extends Error {
  constructor(message, statusCode = 502, virusTotalCode = null) {
    super(message);
    this.name = 'VirusTotalError';
    this.statusCode = statusCode;
    this.virusTotalCode = virusTotalCode;
  }
}

async function request(endpoint, options = {}) {
  const apiKey = process.env.VIRUS_TOTAL_API;
  if (!apiKey) {
    throw new VirusTotalError('VirusTotal scanning is not configured on the server.', 503);
  }

  let response;
  try {
    response = await fetch(`${VIRUSTOTAL_API}${endpoint}`, {
      ...options,
      headers: {
        'x-apikey': apiKey,
        ...options.headers
      },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS)
    });
  } catch (error) {
    throw new VirusTotalError(`Could not connect to VirusTotal: ${error.message}`);
  }

  let result;
  try {
    result = await response.json();
  } catch {
    if (!response.ok) {
      throw new VirusTotalError(`VirusTotal request failed (HTTP ${response.status}).`);
    }
    throw new VirusTotalError('VirusTotal returned an invalid response.');
  }

  if (!response.ok) {
    const error = result.error || {};
    const detail = typeof error.message === 'string'
      ? `: ${error.message.slice(0, 300)}`
      : '';
    throw new VirusTotalError(
      `VirusTotal request failed (HTTP ${response.status}${error.code ? `, ${error.code}` : ''})${detail}`,
      response.status,
      error.code || null
    );
  }

  if (!result.data) {
    throw new VirusTotalError('VirusTotal response did not contain scan data.');
  }

  return result.data;
}

async function uploadFile(file) {
  const form = new FormData();
  const content = new Blob([file.buffer], {
    type: file.mimetype || 'application/octet-stream'
  });
  form.append('file', content, file.originalname);

  let result;
  try {
    result = await request('/files', {
      method: 'POST',
      body: form
    });
  } catch (error) {
    if (error.statusCode !== 409 ||
        !['AlreadyExistsError', 'AlreadySubmittedError'].includes(error.virusTotalCode)) {
      throw error;
    }

    const sha256 = createHash('sha256').update(file.buffer).digest('hex');
    try {
      return await getFileReport(sha256);
    } catch (reportError) {
      if (reportError.statusCode !== 404 && reportError.virusTotalCode !== 'NotAvailableYet') {
        throw reportError;
      }
      return { sha256, status: 'queued', stats: null, existingReport: true };
    }
  }

  if (!result.id) {
    throw new VirusTotalError('VirusTotal did not return an analysis ID.');
  }

  return { analysisId: result.id, status: 'queued' };
}

async function getFileReport(sha256) {
  const result = await request(`/files/${sha256}`);
  const attributes = result.attributes || {};
  const stats = attributes.last_analysis_stats || null;
  return {
    sha256,
    status: stats ? 'completed' : 'queued',
    stats,
    existingReport: true
  };
}

async function getAnalysis(analysisId) {
  let result;
  try {
    result = await request(`/analyses/${encodeURIComponent(analysisId)}`);
  } catch (error) {
    if (error.virusTotalCode !== 'NotAvailableYet') throw error;
    return { analysisId, status: 'queued', stats: null };
  }
  const attributes = result.attributes || {};

  return {
    analysisId: result.id,
    status: attributes.status || 'unknown',
    stats: attributes.stats || null
  };
}

module.exports = { VirusTotalError, getAnalysis, getFileReport, uploadFile };
