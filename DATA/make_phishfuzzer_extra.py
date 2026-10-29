"""
make_phishfuzzer_extra.py  -  takes the useful part of the PhishFuzzer dataset and saves phishfuzzer_extra.csv

Source: "The Phish, The Spam, and The Valid" (arXiv 2511.21448), repo github.com/DataPhish/PhishFuzzer
        (no license file in the repo at the time of download, Oct 2026; cite the paper)

Kept:  English emails whose Source is "Manual" (real emails collected 2022-2026 by the authors)
       + their AI-written variants, for BOTH classes:
         Valid    -> label 0
         Phishing -> label 1
Dropped: their old public emails (SpamAssassin 2002, CEAS 2008, Nazario - we already have Nazario), and Spam.

Needs (in raw/phishfuzzer/):
    PhishFuzzer_emails_original_seed_v1.json
    PhishFuzzer_emails_entity_rephrased_v1.json
Run:   python make_phishfuzzer_extra.py
"""

import csv
import html
import json
from pathlib import Path

FOLDER = Path("raw") / "phishfuzzer"
SEED_FILE = FOLDER / "PhishFuzzer_emails_original_seed_v1.json"
VARIANT_FILE = FOLDER / "PhishFuzzer_emails_entity_rephrased_v1.json"
OUTPUT = "phishfuzzer_extra.csv"
COLUMNS = ["subject", "body", "body_html", "attachments", "from", "reply_to", "return_path",
           "headers_raw", "label", "source", "group"]
LABELS = {"Valid": 0, "Phishing": 1}


def as_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return [str(i).strip() for i in x if str(i).strip()]
    x = str(x).strip()
    return [x] if x and x.lower() not in ("none", "nan", "[]") else []


def to_row(e, kind, group):
    urls = as_list(e.get("URL"))
    # Their links are in a separate field, so they go in as HTML links for the link features
    links = "\n".join(f'<a href="{html.escape(u, quote=True)}">link</a>' for u in urls)
    return {
        "subject": str(e.get("Subject") or "").strip(),
        "body": str(e.get("Body") or "").strip(),
        "body_html": links,
        "attachments": ";".join(as_list(e.get("File"))),
        "from": str(e.get("Sender") or "").strip(),
        "reply_to": "", "return_path": "", "headers_raw": "",
        "label": LABELS[e["Type"]],
        "source": f"phishfuzzer_{kind}_{e['Type'].lower()}",   # e.g. phishfuzzer_real_valid, phishfuzzer_ai_phishing
        "group": f"pf_{group}",   # a real email and its 6 variants share one group
    }


seeds = json.load(open(SEED_FILE, encoding="utf-8"))
variants = json.load(open(VARIANT_FILE, encoding="utf-8"))

keep = {e["No."]: e for e in seeds
        if e.get("Type") in LABELS
        and str(e.get("Source", "")).startswith("Manual")
        and e.get("Language") == "en"}

rows = [to_row(e, "real", sid) for sid, e in keep.items()]
rows += [to_row(v, "ai", v["Original_ID"]) for v in variants
         if v.get("Original_ID") in keep and v.get("Type") in LABELS]

with open(OUTPUT, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=COLUMNS)
    w.writeheader()
    w.writerows(rows)

from collections import Counter
print(f"Saved {OUTPUT}: {len(rows)} emails")
for k, n in sorted(Counter(r["source"] for r in rows).items()):
    print(f"  {k}: {n}")
