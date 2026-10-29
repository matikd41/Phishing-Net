"""
features.py  -  Task 2: text + content features
Content only. Nothing about the sender (From, Reply-To, display name, SPF/DKIM/DMARC),
because OU phishing comes from real, compromised oakland.edu accounts.

Used two ways:
  1. python features.py        -> prints every feature by class, for dataset.csv AND ou_holdout.csv
  2. from features import ...  -> Task 3 builds the model with build_preprocessor()

Needs: pandas, numpy, scikit-learn
"""

import re
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MaxAbsScaler

# ------------------------------------------------------------------ lists
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "s.id", "shorte.st", "bl.ink",
}

# Free form builders and free hosting: attackers can't host pages on oakland.edu, so they use these.
FORM_OR_FREE_HOST = (
    "forms.gle", "forms.google.com", "sites.google.com", "typeform.com", "jotform.com",
    "formstack.com", "wufoo.com", "firebaseapp.com", "web.app", "weebly.com", "wixsite.com",
    "000webhostapp.com", "glitch.me", "netlify.app", "pages.dev", "workers.dev", "r2.dev",
    "herokuapp.com", "azurewebsites.net", "blob.core.windows.net", "storage.googleapis.com",
    "webflow.io", "godaddysites.com", "square.site", "ipfs.io", "dweb.link",
)

RISKY_EXTENSIONS = (
    ".html", ".htm", ".shtml", ".xhtml", ".zip", ".rar", ".7z", ".exe", ".scr", ".js", ".vbs",
    ".bat", ".cmd", ".iso", ".img", ".lnk", ".hta", ".jar", ".docm", ".xlsm", ".pptm", ".one",
)

URGENCY_CREDENTIAL = [
    r"verif\w*", r"re-?validat\w*", r"validat\w*", r"password\w*", r"passcode", r"log ?in",
    r"sign ?in", r"suspend\w*", r"deactivat\w*", r"locked", r"expir\w*", r"urgent\w*",
    r"immediate\w*", r"final notice", r"action required", r"confirm\w*", r"update your",
    r"unusual activity", r"security alert", r"quota", r"mailbox", r"permanently deleted",
    r"within (?:24|48) hours", r"next few hours", r"avoid (?:losing|any|disruption|suspension)",
]

JOB_SCAM = [
    r"part[- ]time", r"remote", r"per week", r"weekly", r"hrs?/week", r"hours (?:weekly|per week)",
    r"virtual assistant", r"research assistant", r"administrative assistant", r"personal assistant",
    r"bookkeeper", r"remuneration", r"compensation", r"flexible", r"how to apply", r"apply",
    r"\$\s?\d{2,4}\s*(?:per week|weekly|/week|a week)",
]

URGENCY_RE = re.compile(r"\b(?:" + "|".join(URGENCY_CREDENTIAL) + r")\b", re.IGNORECASE)
JOB_RE = re.compile(r"(?:" + "|".join(JOB_SCAM) + r")", re.IGNORECASE)

# ------------------------------------------------------------------ link helpers
# Plain-text links; allows the [NUMBER] token so links like u[NUMBER].ct.sendgrid.net are not cut off.
TEXT_URL_RE = re.compile(r"""(?:https?://|www\.)(?:\[NUMBER\]|[^\s"'<>()\[\]{}])+""", re.IGNORECASE)
HREF_RE = re.compile(r"""href\s*=\s*["']?\s*((?:https?://|www\.)[^"'\s>]+)""", re.IGNORECASE)
IP_HOST_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
ORG_DOMAINS_RE = re.compile(r"\b(?:monkey\.org|oakland\.edu)\b", re.IGNORECASE)
# Recipient names / redaction tags that only exist on one side (Nazario's 'jose', OU's [REDACTED...])
ONE_SIDED_TOKENS_RE = re.compile(r"\bjose\b|\[REDACTED[A-Z_]*\]", re.IGNORECASE)
YEAR_RE = re.compile(r"\b(?:19|20)\d{2}\b")
UNDERSCORES_RE = re.compile(r"[_=\-*~]{3,}")


def _s(x):
    return "" if pd.isna(x) else str(x)


def extract_urls(subject, body, body_html):
    urls = TEXT_URL_RE.findall(_s(subject) + " " + _s(body))
    urls += HREF_RE.findall(_s(body_html))
    return urls


def url_host(url):
    u = re.sub(r"^https?://", "", url.strip(), flags=re.IGNORECASE)
    host = re.split(r"[/?#:]", u, maxsplit=1)[0].lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def is_form_or_free_host(url):
    host = url_host(url)
    if host == "docs.google.com" and "/forms" in url.lower():
        return True
    return any(host == d or host.endswith("." + d) for d in FORM_OR_FREE_HOST)


# ------------------------------------------------------------------ hand-made features
NUMERIC_FEATURES = [
    "has_ip_url", "has_shortener", "has_form_or_free_host", "has_risky_attachment",
    "urgency_count", "job_count",
]


# job_count is still computed and reported, but NOT given to the model: in the training data it is
# reversed (more common in legit mailing lists than in Nazario phishing, which has few job scams).
MODEL_NUMERIC_FEATURES = [f for f in NUMERIC_FEATURES if f != "job_count"]


def numeric_features(df):
    """One row of hand-made features per email."""
    out = []
    for subj, body, html, att in zip(df["subject"], df["body"], df["body_html"], df["attachments"]):
        urls = extract_urls(subj, body, html)
        hosts = [url_host(u) for u in urls]
        names = [n.strip().lower() for n in _s(att).split(";") if n.strip()]
        text = _s(subj) + " " + _s(body)
        out.append({
            "has_ip_url": int(any(IP_HOST_RE.match(h) for h in hosts)),
            "has_shortener": int(any(h in SHORTENERS for h in hosts)),
            "has_form_or_free_host": int(any(is_form_or_free_host(u) for u in urls)),
            "has_risky_attachment": int(any(n.endswith(RISKY_EXTENSIONS) for n in names)),
            "urgency_count": len(URGENCY_RE.findall(text)),
            "job_count": len(JOB_RE.findall(text)),
        })
    return pd.DataFrame(out, index=df.index)


# ------------------------------------------------------------------ text for TF-IDF
def clean_text(subject, body):
    """Subject + body with format/era/organization clues removed, so the text model learns wording.
    Removed: quoted earlier messages ('>' lines), links, email addresses, organization domains,
    years, '____' separators, and one-sided names/redaction tags."""
    body = "\n".join(line for line in _s(body).splitlines() if not line.lstrip().startswith(">") and not line.rstrip().endswith("wrote:"))
    t = _s(subject) + " \n " + body
    t = TEXT_URL_RE.sub(" ", t)
    t = EMAIL_RE.sub(" ", t)
    t = ORG_DOMAINS_RE.sub(" ", t)
    t = ONE_SIDED_TOKENS_RE.sub(" ", t)
    t = YEAR_RE.sub(" ", t)
    t = UNDERSCORES_RE.sub(" ", t)
    t = t.replace("[NUMBER]", " numbertoken ")
    return t


def make_feature_table(df):
    """Everything the model needs, as one table: a 'text' column + the numeric features."""
    table = numeric_features(df)
    table.insert(0, "text", [clean_text(s, b) for s, b in zip(df["subject"], df["body"])])
    return table


def build_preprocessor():
    """TF-IDF on text + scaled numeric features. Fit it on TRAINING data only (Task 3 does this)."""
    tfidf = TfidfVectorizer(
        ngram_range=(1, 2), min_df=3, max_df=0.9, sublinear_tf=True,
        stop_words="english", strip_accents="unicode", max_features=50000,
    )
    return ColumnTransformer([
        ("tfidf", tfidf, "text"),
        ("numeric", MaxAbsScaler(), MODEL_NUMERIC_FEATURES),
    ])


# ------------------------------------------------------------------ check by class
def report(df, name):
    f = numeric_features(df)
    print(f"\n==================== {name}  ({len(df)} emails) ====================")
    print("Share of emails where the feature is > 0, by label (0 = legit, 1 = phishing):")
    print((f > 0).groupby(df["label"]).mean().round(3).T.to_string())
    print("\nAverage count, by label:")
    print(f[["urgency_count", "job_count"]].groupby(df["label"]).mean().round(2).T.to_string())

    # Show which sites triggered the form/free-host and shortener flags, so false hits are visible
    for lab in [0, 1]:
        part = df[df["label"] == lab]
        hits = [url_host(u) for s, b, h in zip(part["subject"], part["body"], part["body_html"])
                for u in extract_urls(s, b, h) if is_form_or_free_host(u)]
        print(f"\nForm/free-host sites found, label={lab}:",
              pd.Series(hits).value_counts().head(8).to_dict() if hits else "none")
    return f


if __name__ == "__main__":
    train = pd.read_csv("dataset.csv")
    ou = pd.read_csv("ou_holdout.csv")
    report(train, "TRAINING  dataset.csv")
    report(ou, "OU HOLDOUT  ou_holdout.csv")

    # TF-IDF check: fit on training only, then show the words that lean most to each class.
    # Look for words that reflect the dataset (old mailing lists, names) rather than phishing.
    pre = build_preprocessor()
    X = pre.fit_transform(make_feature_table(train))
    vocab = pre.named_transformers_["tfidf"].get_feature_names_out()
    n_text = len(vocab)
    print(f"\n==================== TF-IDF (fit on training only) ====================")
    print(f"Vocabulary size: {n_text}   |   Total features: {X.shape[1]} (TF-IDF + {len(MODEL_NUMERIC_FEATURES)} hand-made)")
    Xt = X[:, :n_text]
    y = train["label"].values
    diff = np.asarray(Xt[y == 1].mean(axis=0) - Xt[y == 0].mean(axis=0)).ravel()
    order = np.argsort(diff)
    print("\nTop 25 words leaning PHISHING:", ", ".join(vocab[order[::-1][:25]]))
    print("\nTop 25 words leaning LEGIT:   ", ", ".join(vocab[order[:25]]))

    ou_X = pre.transform(make_feature_table(ou))
    print(f"\nOU emails with zero known words: {int((ou_X[:, :n_text].getnnz(axis=1) == 0).sum())} of {len(ou)}")
