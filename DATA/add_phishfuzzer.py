"""
add_phishfuzzer.py  -  dataset.csv + phishfuzzer_extra.csv  ->  dataset_plus.csv
dataset.csv is NOT changed, so the old baseline can always be re-run.

Same cleaning rules as build_dataset.py for the new rows:
  empty bodies removed, long numbers -> [NUMBER], duplicates removed (also against dataset.csv),
  and nothing that also appears in ou_holdout.csv.
Adds a 'group' column so a real email and its AI variants stay together in cross-validation.

Run:   python add_phishfuzzer.py
"""

import re
import pandas as pd

LONG_NUMBER = re.compile(r"\d{6,}")
MIN_BODY_CHARS = 20


def norm(text):
    return re.sub(r"\s+", " ", str(text)).strip().lower()


base = pd.read_csv("dataset.csv")
extra = pd.read_csv("phishfuzzer_extra.csv")
ou = pd.read_csv("ou_holdout.csv")
print(f"dataset.csv: {len(base)}   phishfuzzer_extra.csv: {len(extra)}")

base["group"] = ["base_" + str(i) for i in range(len(base))]   # every old email is its own group

for col in ("subject", "body"):
    extra[col] = extra[col].fillna("").astype(str).str.replace(LONG_NUMBER, "[NUMBER]", regex=True)

before = len(extra)
extra = extra[extra["body"].str.strip().str.len() >= MIN_BODY_CHARS]
print(f"- empty or near-empty bodies removed: {before - len(extra)}")

seen = set(base["body"].map(norm)) | set(ou["body"].map(norm))
before = len(extra)
extra = extra[~extra["body"].map(norm).isin(seen)]
extra = extra[~extra["body"].map(norm).duplicated()]
print(f"- duplicates (inside the new data, or already in dataset.csv / ou_holdout.csv) removed: {before - len(extra)}")

plus = pd.concat([base, extra[base.columns]], ignore_index=True)
plus = plus.sample(frac=1, random_state=42).reset_index(drop=True)
plus.to_csv("dataset_plus.csv", index=False)

print(f"\nSaved dataset_plus.csv: {len(plus)} emails "
      f"(phishing={int((plus.label == 1).sum())}, legitimate={int((plus.label == 0).sum())})")
print(plus[plus["source"].str.startswith("phishfuzzer")]["source"].value_counts().to_string())
