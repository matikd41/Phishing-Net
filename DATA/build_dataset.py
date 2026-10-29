"""
build_dataset.py  -  Task 1, Steps 4 and 5
Cleans parsed_public.csv, balances the two classes, and saves dataset.csv.
Also writes cleaning_report.txt with the row counts after every step (for the report).

Needs (in the same folder):  parsed_public.csv  (from parse_emails.py)
Optional:                    ou_holdout.csv     (from parse_ou.py, used only to make sure
                                                 no OU email leaks into training)
Run:   python build_dataset.py
Only built-in Python, nothing to install.
"""

import csv
import random
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

INPUT = "parsed_public.csv"
HOLDOUT = "ou_holdout.csv"
OUTPUT = "dataset.csv"
REPORT = "cleaning_report.txt"
COLUMNS = ["subject", "body", "body_html", "attachments", "from", "reply_to",
           "return_path", "headers_raw", "label", "source"]
SEED = 42                 # fixed so every teammate gets exactly the same dataset.csv
MIN_BODY_CHARS = 20       # bodies shorter than this count as empty
MAX_BAD_CHAR_SHARE = 0.05 # more than 5% broken characters (U+FFFD) = broken encoding
MIN_MOJIBAKE_HITS = 5     # text like "Ã©" or "â€™" = encoding read the wrong way
MAX_NON_LATIN_SHARE = 0.30  # mostly non-Latin letters (Chinese, Russian, ...) = not English
TARGET_RATIO = 1.0        # legitimate : phishing after balancing (1.0 = equal)

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
BAD_CHAR = "�"
MOJIBAKE = re.compile(r"Ã.|â€|Â")
LONG_NUMBER = re.compile(r"\d{6,}")

report_lines = []


def log(text=""):
    print(text)
    report_lines.append(text)


def count(rows):
    c = Counter(r["label"] for r in rows)
    return f"{len(rows):>5} rows  (phishing={c.get('1', 0)}, legitimate={c.get('0', 0)})"


def step(name, rows, keep):
    kept, removed = [], []
    for r in rows:  # one pass, so rules that remember what they've seen work correctly
        (kept if keep(r) else removed).append(r)
    c = Counter(r["label"] for r in removed)
    log(f"- {name}: removed {len(removed)} (phishing={c.get('1', 0)}, legitimate={c.get('0', 0)})")
    log(f"    left: {count(kept)}")
    return kept


def norm(text):
    return re.sub(r"\s+", " ", text).strip().lower()


def non_latin_share(text):
    letters = [ch for ch in text if ch.isalpha()]
    if not letters:
        return 0.0
    return sum(ord(ch) > 0x024F for ch in letters) / len(letters)


# ---------------------------------------------------------------- load
rows = list(csv.DictReader(open(INPUT, encoding="utf-8", newline="")))
log("BUILD DATASET REPORT")
log(f"Input: {INPUT}")
log(f"Start: {count(rows)}")
log("")
log("STEP 4 - CLEANING")

# 1. mbox bookkeeping messages (not real emails)
rows = step("Mail-folder system messages ('FOLDER INTERNAL DATA')", rows,
            lambda r: "FOLDER INTERNAL DATA" not in r["subject"])

# 2. empty bodies
rows = step(f"Empty or near-empty bodies (< {MIN_BODY_CHARS} characters)", rows,
            lambda r: len(r["body"].strip()) >= MIN_BODY_CHARS)

# 3. broken encodings
rows = step(f"Broken encoding (> {MAX_BAD_CHAR_SHARE:.0%} unreadable characters)", rows,
            lambda r: r["body"].count(BAD_CHAR) / len(r["body"]) <= MAX_BAD_CHAR_SHARE)
rows = step(f"Garbled encoding (>= {MIN_MOJIBAKE_HITS} patterns like 'Ã©' or 'â€™')", rows,
            lambda r: len(MOJIBAKE.findall(r["body"])) < MIN_MOJIBAKE_HITS)

# 4. non-English (OU mail is English, so these would only add noise)
rows = step(f"Mostly non-Latin text (> {MAX_NON_LATIN_SHARE:.0%} of letters)", rows,
            lambda r: non_latin_share(r["body"]) <= MAX_NON_LATIN_SHARE)

# 5. same rule as ou_holdout.csv so both files look alike to the model
changed = 0
for r in rows:
    for col in ("subject", "body"):
        new = LONG_NUMBER.sub("[NUMBER]", r[col])
        if new != r[col]:
            changed += 1
        r[col] = new
log(f"- Long numbers (6+ digits) replaced with [NUMBER], same as ou_holdout.csv: {changed} fields changed")
# 6. duplicates (same body after lowercasing and collapsing spaces); keep the first copy
seen = set()


def first_copy(r):
    key = norm(r["body"])
    if key in seen:
        return False
    seen.add(key)
    return True


rows = step("Duplicate bodies (kept first copy)", rows, first_copy)

# 7. same text with both labels would confuse the model
labels_by_body = defaultdict(set)
for r in rows:
    labels_by_body[norm(r["body"])].add(r["label"])
rows = step("Same body labelled both phishing and legitimate", rows,
            lambda r: len(labels_by_body[norm(r["body"])]) == 1)

# 8. nothing from the OU held-out set may appear in training
if Path(HOLDOUT).exists():
    ou_bodies = {norm(r["body"]) for r in csv.DictReader(open(HOLDOUT, encoding="utf-8", newline=""))}
    rows = step("Overlap with OU held-out set", rows, lambda r: norm(r["body"]) not in ou_bodies)
else:
    log(f"- Overlap with OU held-out set: skipped ({HOLDOUT} not found)")

log(f"After cleaning: {count(rows)}")

# ---------------------------------------------------------------- balance
log("")
log("STEP 5 - BALANCING")
random.seed(SEED)
phish = [r for r in rows if r["label"] == "1"]
legit = [r for r in rows if r["label"] == "0"]
log(f"Before: phishing={len(phish)}, legitimate={len(legit)}")

if len(legit) > len(phish) * TARGET_RATIO:
    target = int(len(phish) * TARGET_RATIO)
    # keep every hard_ham email (legitimate mail that looks spammy = most useful), sample the rest
    hard = [r for r in legit if "hard_ham" in r["source"]]
    easy = [r for r in legit if "hard_ham" not in r["source"]]
    legit = hard + random.sample(easy, max(target - len(hard), 0))
    log(f"Legitimate sampled down to {len(legit)} (all {len(hard)} hard_ham kept, "
        f"easy_ham sampled at random, seed={SEED})")
elif len(phish) > len(legit) * TARGET_RATIO:
    phish = random.sample(phish, int(len(legit) * TARGET_RATIO))
    log(f"Phishing sampled down to {len(phish)} (random, seed={SEED})")

final = phish + legit
random.shuffle(final)
log(f"Final: {count(final)}")
log("")
log("Rows per source:")
for src, n in sorted(Counter(r["source"] for r in final).items()):
    log(f"  {src}: {n}")

# ---------------------------------------------------------------- save
with open(OUTPUT, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=COLUMNS, extrasaction="ignore")
    w.writeheader()
    w.writerows(final)
log("")
log(f"Saved {OUTPUT}")
Path(REPORT).write_text("\n".join(report_lines) + "\n", encoding="utf-8")
print(f"Saved {REPORT}")
