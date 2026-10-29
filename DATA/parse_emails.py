"""
parse_emails.py  -  Task 1, Step 2
Reads the raw emails in raw/ and puts them all into ONE table: parsed_public.csv
No cleaning yet . Uses only built-in Python, 
"""


import csv
import html
import mailbox
import re
import sys
from email import message_from_bytes, policy
from email.header import decode_header, make_header
from pathlib import Path
 
RAW = Path("raw")
OUTPUT = "parsed_public.csv"
COLUMNS = ["subject", "body", "body_html", "attachments", "from", "reply_to",
           "return_path", "headers_raw", "label", "source"]
 
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))  # some emails are very long
 
 
def clean_header(value):
    """Turn encoded headers like =?utf-8?B?...?= into readable text."""
    if value is None:
        return ""
    try:
        return str(make_header(decode_header(str(value)))).strip()
    except Exception:
        return str(value).strip()
 
 
def html_to_text(raw_html):
    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", raw_html)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()
 
 
def decode_part(part):
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:  # unknown charset name
        return payload.decode("utf-8", errors="replace")
 
 
def get_body(msg):
    """Prefer the plain-text part; if there is only HTML, strip the tags."""
    plain, html_parts = [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        if part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype == "text/plain":
            plain.append(decode_part(part))
        elif ctype == "text/html":
            html_parts.append(decode_part(part))
    if plain:
        return "\n".join(plain).strip()
    if html_parts:
        return html_to_text("\n".join(html_parts))
    return ""


def get_html(msg):
    """Raw HTML parts of the email body (not attachments), tags kept so links survive."""
    parts = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        if part.get_content_disposition() == "attachment":
            continue
        if part.get_content_type() == "text/html":
            parts.append(decode_part(part))
    return "\n".join(parts).strip()


def get_attachments(msg):
    """Names of attached files, e.g. 'invoice.pdf;form.html'."""
    names = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename:
            names.append(clean_header(filename))
    return ";".join(names)
 
 
def to_row(msg, label, source):
    headers_raw = "\n".join(f"{k}: {v}" for k, v in msg.items())
    return {
        "subject": clean_header(msg.get("Subject")),
        "body": get_body(msg),
        "body_html": get_html(msg),
        "attachments": get_attachments(msg),
        "from": clean_header(msg.get("From")),
        "reply_to": clean_header(msg.get("Reply-To")),
        "return_path": clean_header(msg.get("Return-Path")),
        "headers_raw": headers_raw,
        "label": label,
        "source": source,
    }
 
 
def read_nazario(writer):
    count = skipped = 0
    folder = RAW / "nazario"
    if not folder.exists():
        print(f"Could not find the folder {folder.resolve()}")
        return
    files = [p for p in sorted(folder.rglob("*")) if p.is_file()]
    print(f"Files found in {folder}: {[p.name for p in files]}")
    for path in files:
        if path.name.upper().startswith(("README", "LICENSE")):
            continue
        file_count = 0
        for msg in mailbox.mbox(str(path)):
            try:
                writer.writerow(to_row(msg, 1, f"nazario_{path.stem}"))
                count += 1
                file_count += 1
            except Exception:
                skipped += 1
        print(f"  {path.name}: {file_count} emails")
    print(f"Nazario (phishing): {count} emails read, {skipped} could not be parsed")
 
 
def read_spamassassin(writer):
    count = skipped = 0
    for path in sorted((RAW / "spamassassin").rglob("*")):
        if not path.is_file() or path.name == "cmds" or path.name.endswith(".bz2") or path.suffix == ".tar":
            continue
        folder = path.parent.name  # easy_ham, easy_ham_2 or hard_ham
        try:
            msg = message_from_bytes(path.read_bytes(), policy=policy.compat32)
            writer.writerow(to_row(msg, 0, f"spamassassin_{folder}"))
            count += 1
        except Exception:
            skipped += 1
    print(f"SpamAssassin (legitimate): {count} emails read, {skipped} could not be parsed")
 
 
if __name__ == "__main__":
    with open(OUTPUT, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        read_nazario(writer)
        read_spamassassin(writer)
    print(f"Saved {OUTPUT}")
