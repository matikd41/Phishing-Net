# Phishing Net

Phishing Net is a browser-based phishing-risk interface backed by an Express API and a local MariaDB/MySQL database. The repository also contains Python tools for preparing email datasets and training phishing classifiers.

The web page calculates a simple client-side heuristic estimate from urgent/account-verification language, links, and potentially risky attachment types. It is a demonstration, not a trained model prediction or a substitute for security review. A completed check is also logged through the API.

## Features

- Responsive risk-check form for email content
- Sender, subject, body, link, and attachment inputs
- Drag-and-drop attachment-name collection
- Consent-gated VirusTotal v3 attachment scanning
- Heuristic demo check with visible indicators and a reset action for the next message
- Low (0-34%), medium (35-64%), and high (65-100%) risk states
- Express endpoint that logs submitted scan details
- Dataset parsing, cleaning, balancing, feature extraction, and holdout evaluation tools
- TF-IDF and pretrained sentence-embedding model training options

## Project structure

```text
index.html                   Browser interface
api.js                       Express server and scan-log API
package.json                 Node.js dependencies
Sandbox/
  VirusTotal/                VirusTotal integration and side-by-side test page
  UrlScanIO/                 Reserved for a future URLScan.io integration
DATA/
  parse_emails.py            Parses public email sources into parsed_public.csv
  parse_ou.py                Parses the private OU holdout set
  build_dataset.py           Cleans and balances the public training data
  features.py                Text and hand-made email features
  make_phishfuzzer_extra.py  Filters PhishFuzzer JSON data
  add_phishfuzzer.py         Creates the augmented dataset
Models/
  train_model.py             Trains and evaluates the TF-IDF baseline
  train_embed.py             Trains and evaluates the sentence-embedding model
```

## Run the web app

### Requirements

- Node.js and npm
- MariaDB or MySQL
- A VirusTotal API key in the server environment variable `VIRUS_TOTAL_API` (for attachment scanning)
- A database named `phishing_net`
- A `scan_log` table matching the columns used in `api.js`

Install Node dependencies:

```powershell
npm install
```

Create the database table. The API expects this shape:

```sql
CREATE TABLE scan_log (
  Id INT AUTO_INCREMENT PRIMARY KEY,
  EmailAddress VARCHAR(255) NOT NULL,
  Subject TEXT NULL,
  EmailContent TEXT NULL,
  AttachedLink TEXT NULL,
  AttachedFile TEXT NULL,
  RiskScore DECIMAL(5,2) NULL
);
```

The server reads database connection settings from `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, and `DB_PORT`. Set `VIRUS_TOTAL_API` in the server environment to enable attachment scanning; keep the API key out of browser code and source control.

Start the server:

```powershell
node api.js
```

Open `http://localhost:3000`.

## API

### POST `/api/scans`

Logs one submitted scan.

Example request:

```json
{
  "emailAddress": "sender@example.com",
  "subject": "Account verification required",
  "emailContent": "Please verify your account immediately.",
  "attachedLink": "https://example.com/login",
  "attachedFile": "document.html",
  "riskScore": 98
}
```

Example success response:

```json
{
  "message": "Scan logged successfully!",
  "scanId": 123
}
```

The scan log stores attachment names, not file contents or VirusTotal results.

## VirusTotal attachment scanning

The browser requires an explicit consent checkbox before uploading selected attachments. The server sends each attachment to VirusTotal API v3 and polls for results for up to 60 seconds. Files are held in memory only, limited to 32 MB each, and not saved to disk. If VirusTotal is still processing after the wait, the page displays the analysis ID.

Submitted file contents leave this app and may be shared with VirusTotal's security community. Do not submit confidential or personal files. API quotas and account limits apply. See [Sandbox/VirusTotal/README.md](./Sandbox/VirusTotal/README.md) for endpoint details and setup.

For a wide, side-by-side input/output testing view, open `http://localhost:3000/Sandbox/VirusTotal/test.html`. The page shows upload percentage and scanning progress while VirusTotal processes an attachment.

`Sandbox/UrlScanIO/` is reserved for a future URL scanning feature; it is not currently connected.

Run the VirusTotal integration tests with:

```powershell
npm test
```

## Dataset workflow

Run the Python scripts from the `DATA` directory because they use relative input and output paths.

### 1. Add raw email data

The public parser expects raw email folders:

```text
DATA/raw/nazario/
DATA/raw/spamassassin/
```

The OU holdout parser expects:

```text
DATA/raw/ou/phish/
DATA/raw/ou/legit/
```

Private holdout emails should be reviewed and redacted before use.

### 2. Parse public emails

```powershell
cd DATA
python parse_emails.py
```

This creates `parsed_public.csv`.

### 3. Parse the private OU holdout

```powershell
python parse_ou.py
```

This creates `ou_holdout.csv` and removes configured recipient details, own addresses, selected redaction words, and long numbers. Some information still requires manual review.

### 4. Clean and balance the dataset

```powershell
python build_dataset.py
```

This creates `dataset.csv` and `cleaning_report.txt`.

### Optional: add PhishFuzzer examples

Place the source JSON files in `DATA/raw/phishfuzzer/`, then run:

```powershell
python make_phishfuzzer_extra.py
python add_phishfuzzer.py
```

This produces `phishfuzzer_extra.csv` and `dataset_plus.csv`. The augmented set preserves groups so real emails and their AI-written variants remain together during cross-validation.

## Train a model

The Python training scripts require:

```text
pandas
numpy
scikit-learn
joblib
```

Run the training scripts from `DATA` so their relative dataset paths resolve correctly. Add both Python directories to `PYTHONPATH` so the scripts can import `features.py` and `train_model.py`:

```powershell
cd DATA
$env:PYTHONPATH="$PWD;$PWD\..\Models;$env:PYTHONPATH"
python ..\Models\train_model.py
python ..\Models\train_model.py dataset_plus.csv
```

The default baseline training file is `dataset.csv`, and the OU holdout is `ou_holdout.csv`. The script:

1. Uses grouped five-fold cross-validation
2. Evaluates once against the OU holdout
3. Prints accuracy, precision, recall, F1, ROC AUC, and confusion-matrix details
4. Saves `phishing_model.pkl` or `phishing_model_plus.pkl`

To use sentence embeddings:

```powershell
pip install sentence-transformers torch
cd DATA
$env:PYTHONPATH="$PWD;$PWD\..\Models;$env:PYTHONPATH"
python ..\Models\train_embed.py
python ..\Models\train_embed.py dataset.csv
```

The embedding model is `sentence-transformers/all-MiniLM-L6-v2`. It creates embedding caches and saves `phishing_model_embed.pkl`.

## Privacy and safety

- Do not commit raw email archives, private OU email data, redaction lists, credentials, or database dumps.
- Review `ou_holdout.csv` after parsing to verify that personal or identifying details are not exposed.
- Do not open suspicious links or execute attached files while testing.
- The UI estimate is a demo heuristic, not a trained model prediction or a substitute for security review.
- The ML scripts are experimental and should not be used as the sole basis for security decisions.

## Technology

- HTML, CSS, and vanilla JavaScript
- Node.js and Express
- MariaDB/MySQL with `mysql2`
- Python
- pandas, NumPy, and scikit-learn
- Optional Sentence Transformers
