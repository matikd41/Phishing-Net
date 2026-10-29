"""
parse_ou.py  -  Task 1, Step 3
Reads your OU emails (.eml files) and saves them to ou_holdout.csv.
This file is the HELD-OUT set: it is never used for training.

Folder layout expected (inside DATA):
    raw/ou/phish/   <- OU phishing emails (.eml)  -> label 1
    raw/ou/legit/   <- real OU emails (.eml)      -> label 0

Needs parse_emails.py in the same folder (it reuses its functions).
Run:   python parse_ou.py
"""

import csv
import re
from email import message_from_bytes, policy
from pathlib import Path

from parse_emails import to_row, COLUMNS

VERSION = "v5 (hides your own address everywhere, replaces long numbers)"

OU = Path("raw") / "ou"
OUTPUT = "ou_holdout.csv"

# Basic automatic redaction. Names and other personal details still need a manual check.
PHONE = re.compile(r"\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b")
RECIPIENT_HEADERS = ("To", "Cc", "Bcc", "Delivered-To", "X-Original-To")
TYPED_PHISH = OU / "phish_typed.csv"  # phishing examples typed from screenshots (no headers)
REDACT_WORDS = OU / "redact_words.txt"  # one word or phrase per line: your name, student ID, etc.
LONG_NUMBER = re.compile(r"\d{6,}")  # long numbers (IDs, account numbers, tracking codes) get replaced


def load_redact_words():
    if not REDACT_WORDS.exists():
        return []
    words = [w.strip() for w in REDACT_WORDS.read_text(encoding="utf-8-sig").splitlines() if w.strip()]
    return sorted(words, key=len, reverse=True)  # longest first, so full names go before first names


WORDS = load_redact_words()


def redact(msg):
    """Hide recipient addresses (you and your teammates). The sender is kept: it is evidence."""
    for h in RECIPIENT_HEADERS:
        if msg.get(h):
            msg.replace_header(h, "[REDACTED_RECIPIENT]")
    return msg


def hide_self(text, own_addresses):
    """Hide your own address, including the 'name=oakland.edu' form used in bounce addresses."""
    for addr in own_addresses:
        local, _, domain = addr.partition("@")
        for form in (addr, f"{local}={domain}", local):
            text = re.sub(re.escape(form), "[REDACTED_SELF]", text, flags=re.IGNORECASE)
    for w in WORDS:
        text = re.sub(re.escape(w), "[REDACTED]", text, flags=re.IGNORECASE)
    return text


def redact_text(text, recipient_addresses):
    for addr in recipient_addresses:
        if addr:
            text = text.replace(addr, "[REDACTED_RECIPIENT]")
    for w in WORDS:
        text = re.sub(re.escape(w), "[REDACTED]", text, flags=re.IGNORECASE)
    text = PHONE.sub("[REDACTED_PHONE]", text)
    # Long numbers (tracking codes, IDs, account numbers) carry no phishing signal and may identify you.
    return LONG_NUMBER.sub("[NUMBER]", text)


def read_folder(folder, label, writer):
    count = 0
    if not folder.exists():
        print(f"  folder not found: {folder}")
        return 0
    for path in sorted(folder.glob("*.eml")):
        msg = message_from_bytes(path.read_bytes(), policy=policy.compat32)
        find = lambda s: set(re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", s))
        own = find(" ".join(str(msg.get(h, "")) for h in ("Delivered-To", "X-Original-To")))
        senders = find(" ".join(str(msg.get(h, "")) for h in ("From", "Return-Path", "Reply-To", "Sender"))) - own
        recipients = find(" ".join(str(msg.get(h, "")) for h in RECIPIENT_HEADERS)) - senders
        msg = redact(msg)
        row = to_row(msg, label, "ou")
        for col in ("subject", "body", "body_html", "attachments", "headers_raw"):
            row[col] = redact_text(row[col], recipients)
        # Your own address and listed words are hidden everywhere, including sender fields
        row["split"] = "holdout"
        row["file"] = path.name
        for col in ("from", "reply_to", "return_path", "file"):
            row[col] = hide_self(row[col], own)
        for col in ("subject", "body", "body_html", "attachments", "headers_raw"):
            row[col] = hide_self(row[col], own)
        writer.writerow(row)
        count += 1
    print(f"  {folder}: {count} emails")
    return count


def read_typed(writer):
    """Phishing examples copied by hand from screenshots. Only text is known, so headers stay empty."""
    if not TYPED_PHISH.exists():
        print(f"  no typed examples ({TYPED_PHISH} not found)")
        return 0
    count = 0
    with open(TYPED_PHISH, newline="", encoding="utf-8-sig") as f:
        for i, r in enumerate(csv.DictReader(f), start=1):
            if not (r.get("subject") or r.get("body")):
                continue
            writer.writerow({
                "subject": r.get("subject", "").strip(),
                "body": r.get("body", "").strip(),
                "from": r.get("from", "").strip(),
                "reply_to": "", "return_path": "", "headers_raw": "",
                "label": 1, "source": "ou_phishtank_typed",
                "split": "holdout", "file": f"phish_typed_row{i}",
            })
            count += 1
    print(f"  {TYPED_PHISH}: {count} typed phishing examples (text only, no headers)")
    return count


REVIEW = []

if __name__ == "__main__":
    print(f"parse_ou.py {VERSION}")
    print(f"Words to hide from {REDACT_WORDS}: {len(WORDS)}"
          + ("" if WORDS else "  (none - create this file to hide your name, student ID, etc.)"))
    if not WORDS:
        near = [p.name for p in OU.glob("redact_words*")]
        if near:
            print(f"  found {near} - rename it to exactly redact_words.txt")
    if not TYPED_PHISH.exists():
        near = [str(p) for p in Path("raw").rglob("phish_typed*")]
        if near:
            print(f"  phish_typed found at {near} - move/rename it to {TYPED_PHISH}")
    with open(OUTPUT, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS + ["split", "file"])
        writer.writeheader()
        n_phish = read_folder(OU / "phish", 1, writer)
        n_typed = read_typed(writer)
        n_legit = read_folder(OU / "legit", 0, writer)
    if REVIEW:
        print("\nPlease check these by hand:")
        for line in REVIEW:
            print("  " + line)
    print(f"\nOU holdout: {n_phish} phishing (.eml) + {n_typed} phishing (typed), "
          f"{n_legit} legitimate. Saved {OUTPUT}")
