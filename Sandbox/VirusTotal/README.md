# VirusTotal attachment scanning

This feature sends selected attachment contents from the app server to VirusTotal API v3. It does not execute files or save uploads to disk. Uploads are held in memory temporarily and limited to 32 MB each.

## Configuration

Set `VIRUS_TOTAL_API` in the environment where the Node.js server runs. Keep the key server-side; never put it in `index.html` or commit it to source control.

PowerShell example for the current terminal:

```powershell
$env:VIRUS_TOTAL_API = "<your VirusTotal API key>"
node api.js
```

## User consent

The browser requires a separate unchecked-by-default consent checkbox before sending attachments. The notice explains that file contents go to VirusTotal and may be shared with its security community. Do not upload confidential or personal files.

If VirusTotal reports that an uploaded file already exists or is already being submitted (HTTP 409), the integration retrieves its existing file report by SHA-256. If VirusTotal says the report is not available yet, the page polls by hash for up to 60 seconds and displays the detection statistics when published.

## API

- `POST /api/virustotal/scan` — multipart form with `file` and `consent=true`; returns an analysis ID for a new scan or a SHA-256 while an existing submission is processing.
- `GET /api/virustotal/analyses?analysisId=...` — returns the analysis status and detection statistics. The ID is passed as a query parameter because VirusTotal IDs can contain URL-reserved characters.
- `GET /api/virustotal/files?sha256=...` — checks the existing VirusTotal report for a file while a duplicate submission is still being processed.

The UI polls for completion for up to 60 seconds. If VirusTotal is still processing the file, the analysis ID or file hash is shown for follow-up. VirusTotal API quotas and account limits apply.

## Side-by-side test page

Open `/Sandbox/VirusTotal/test.html` on the running app to test a message and an optional attachment. The input and result panels are side by side on desktop and stack on narrow screens. During a scan, the page shows an animated progress indicator, upload percentage, and scanning status. The test page does not log the message to the scan database.
