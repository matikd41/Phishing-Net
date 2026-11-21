const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const express = require('express');
const { afterEach, test } = require('node:test');
const virusTotalRouter = require('./router');
const { getAnalysis, uploadFile } = require('./virusTotal');

const originalApiKey = process.env.VIRUS_TOTAL_API;
const originalFetch = global.fetch;

afterEach(() => {
  if (originalApiKey === undefined) {
    delete process.env.VIRUS_TOTAL_API;
  } else {
    process.env.VIRUS_TOTAL_API = originalApiKey;
  }
  global.fetch = originalFetch;
});

test('uploads file contents to the VirusTotal v3 endpoint', async () => {
  process.env.VIRUS_TOTAL_API = 'test-key';
  global.fetch = async (url, options) => {
    assert.equal(url, 'https://www.virustotal.com/api/v3/files');
    assert.equal(options.headers['x-apikey'], 'test-key');
    assert.equal(options.body.get('file').name, 'sample.txt');
    assert.equal(await options.body.get('file').text(), 'sample attachment');
    return Response.json({ data: { id: 'analysis_123' } }, { status: 200 });
  };

  assert.deepEqual(await uploadFile({
    buffer: Buffer.from('sample attachment'),
    mimetype: 'text/plain',
    originalname: 'sample.txt'
  }), { analysisId: 'analysis_123', status: 'queued' });
});

test('uses the existing VirusTotal file report when upload returns AlreadyExistsError', async () => {
  process.env.VIRUS_TOTAL_API = 'test-key';
  const fileContents = Buffer.from('already-known sample');
  const sha256 = createHash('sha256').update(fileContents).digest('hex');
  let callCount = 0;
  global.fetch = async (url) => {
    callCount += 1;
    if (callCount === 1) {
      assert.equal(url, 'https://www.virustotal.com/api/v3/files');
      return Response.json({
        error: { code: 'AlreadyExistsError', message: 'File already exists' }
      }, { status: 409 });
    }

    assert.equal(url, `https://www.virustotal.com/api/v3/files/${sha256}`);
    return Response.json({
      data: {
        id: sha256,
        attributes: { last_analysis_stats: { malicious: 1, harmless: 60 } }
      }
    });
  };

  assert.deepEqual(await uploadFile({
    buffer: fileContents,
    mimetype: 'text/plain',
    originalname: 'known.txt'
  }), {
    sha256,
    status: 'completed',
    stats: { malicious: 1, harmless: 60 },
    existingReport: true
  });
  assert.equal(callCount, 2);
});

test('returns a queued file hash when VirusTotal says submission is already in progress', async () => {
  process.env.VIRUS_TOTAL_API = 'test-key';
  const fileContents = Buffer.from('submission in progress');
  const sha256 = createHash('sha256').update(fileContents).digest('hex');
  let callCount = 0;
  global.fetch = async (url) => {
    callCount += 1;
    if (callCount === 1) {
      return Response.json({
        error: {
          code: 'AlreadySubmittedError',
          message: 'Already being submitted for scanning'
        }
      }, { status: 409 });
    }

    assert.equal(url, `https://www.virustotal.com/api/v3/files/${sha256}`);
    return Response.json({
      error: { code: 'NotAvailableYet', message: 'File report is not available yet' }
    }, { status: 400 });
  };

  assert.deepEqual(await uploadFile({
    buffer: fileContents,
    originalname: 'processing.txt'
  }), {
    sha256,
    status: 'queued',
    stats: null,
    existingReport: true
  });
  assert.equal(callCount, 2);
});

test('retrieves a completed report when an existing file returns AlreadySubmittedError', async () => {
  process.env.VIRUS_TOTAL_API = 'test-key';
  const fileContents = Buffer.from('scan being processed elsewhere');
  const sha256 = createHash('sha256').update(fileContents).digest('hex');
  let callCount = 0;
  global.fetch = async (url) => {
    callCount += 1;
    if (callCount === 1) {
      return Response.json({
        error: {
          code: 'AlreadySubmittedError',
          message: 'Already being submitted for scanning'
        }
      }, { status: 409 });
    }

    assert.equal(url, `https://www.virustotal.com/api/v3/files/${sha256}`);
    return Response.json({
      data: {
        id: sha256,
        attributes: { last_analysis_stats: { malicious: 0, harmless: 70 } }
      }
    });
  };

  assert.deepEqual(await uploadFile({
    buffer: fileContents,
    originalname: 'processing.txt'
  }), {
    sha256,
    status: 'completed',
    stats: { malicious: 0, harmless: 70 },
    existingReport: true
  });
  assert.equal(callCount, 2);
});

test('returns analysis status and statistics', async () => {
  process.env.VIRUS_TOTAL_API = 'test-key';
  global.fetch = async (url) => {
    assert.equal(url, 'https://www.virustotal.com/api/v3/analyses/analysis_123');
    return Response.json({
      data: {
        id: 'analysis_123',
        attributes: { status: 'completed', stats: { malicious: 2, harmless: 60 } }
      }
    });
  };

  assert.deepEqual(await getAnalysis('analysis_123'), {
    analysisId: 'analysis_123',
    status: 'completed',
    stats: { malicious: 2, harmless: 60 }
  });
});

test('analysis lookup accepts and safely encodes Base64 characters in IDs', async () => {
  process.env.VIRUS_TOTAL_API = 'test-key';
  const analysisId = 'abc+/==';
  global.fetch = async (url) => {
    assert.equal(
      url,
      'https://www.virustotal.com/api/v3/analyses/abc%2B%2F%3D%3D'
    );
    return Response.json({
      data: { id: analysisId, attributes: { status: 'completed', stats: {} } }
    });
  };

  assert.deepEqual(await getAnalysis(analysisId), {
    analysisId,
    status: 'completed',
    stats: {}
  });
});

test('keeps analyses pending when VirusTotal responds NotAvailableYet', async () => {
  process.env.VIRUS_TOTAL_API = 'test-key';
  global.fetch = async () => Response.json({
    error: { code: 'NotAvailableYet', message: 'Analysis is still being processed' }
  }, { status: 400 });

  assert.deepEqual(await getAnalysis('analysis_123'), {
    analysisId: 'analysis_123',
    status: 'queued',
    stats: null
  });
});

test('does not make a request when the API key is missing', async () => {
  delete process.env.VIRUS_TOTAL_API;
  global.fetch = async () => {
    throw new Error('fetch should not be called');
  };

  await assert.rejects(
    uploadFile({ buffer: Buffer.from('sample'), originalname: 'sample.txt' }),
    { statusCode: 503, message: 'VirusTotal scanning is not configured on the server.' }
  );
});

test('requires upload consent and refuses uploads when server configuration is missing', async (t) => {
  delete process.env.VIRUS_TOTAL_API;
  const app = express();
  app.use('/api/virustotal', virusTotalRouter);
  const server = app.listen(0, '127.0.0.1');
  t.after(() => server.close());
  await new Promise((resolve) => server.once('listening', resolve));
  const address = server.address();
  const url = `http://127.0.0.1:${address.port}/api/virustotal/scan`;

  const withoutConsent = new FormData();
  withoutConsent.append('file', new Blob(['test file']), 'test.txt');
  let response = await fetch(url, { method: 'POST', body: withoutConsent });
  assert.equal(response.status, 400);

  const withConsent = new FormData();
  withConsent.append('file', new Blob(['test file']), 'test.txt');
  withConsent.append('consent', 'true');
  response = await fetch(url, { method: 'POST', body: withConsent });
  assert.equal(response.status, 503);
});

test('analysis route accepts URL-reserved characters in VirusTotal IDs', async (t) => {
  process.env.VIRUS_TOTAL_API = 'test-key';
  global.fetch = async (url) => {
    if (String(url).startsWith('http://127.0.0.1:')) {
      return originalFetch(url);
    }
    assert.equal(url, 'https://www.virustotal.com/api/v3/analyses/abc%2B%2F%3D%3D');
    return Response.json({
      data: {
        id: 'abc+/==',
        attributes: { status: 'completed', stats: { malicious: 0 } }
      }
    });
  };

  const app = express();
  app.use('/api/virustotal', virusTotalRouter);
  const server = app.listen(0, '127.0.0.1');
  t.after(() => server.close());
  await new Promise((resolve) => server.once('listening', resolve));
  const address = server.address();
  const url = new URL('/api/virustotal/analyses', `http://127.0.0.1:${address.port}`);
  url.searchParams.set('analysisId', 'abc+/==');

  const response = await fetch(url);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    analysisId: 'abc+/==',
    status: 'completed',
    stats: { malicious: 0 }
  });
});
