"""
train_embed.py  -   pretrained sentence embeddings + logistic regression

Instead of word counts (TF-IDF), each email is turned into 384 numbers that describe its MEANING,
using the small pretrained model all-MiniLM-L6-v2. Logistic regression then learns phishing vs legit
from those numbers + the same 5 hand-made link/attachment/urgency features.

Same honest setup as train_model.py:
  same text cleaning, grouped 5-fold cross-validation, OU holdout never used for training.

First time only:   pip install sentence-transformers
Run:               python train_embed.py                    (uses dataset_plus.csv)
                   python train_embed.py dataset.csv        (or any other training file)

The first run downloads the model (~90 MB) and converts every email (a few minutes on a laptop).
The converted emails are saved (embed_cache_*.npy), so later runs take seconds.
"""
import torch  # Windows: load PyTorch before pandas/scikit-learn, or its DLL can fail (WinError 1114)
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold, cross_val_predict
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MaxAbsScaler

from features import MODEL_NUMERIC_FEATURES, make_feature_table
from train_model import THRESHOLD, scores

EMBED_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
SEED = 42
_embedder = None


def get_embedder():
    global _embedder
    if _embedder is None:
        from sentence_transformers import SentenceTransformer
        _embedder = SentenceTransformer(EMBED_MODEL, device="cpu")
    return _embedder


def embed(texts, cache_file=None):
    """Texts -> array of shape (n, 384). Uses a saved copy if one exists for the same emails."""
    texts = [str(t) for t in texts]
    if cache_file and Path(cache_file).exists():
        cached = np.load(cache_file)
        if len(cached) == len(texts):
            print(f"  using saved embeddings from {cache_file}")
            return cached
    print(f"  converting {len(texts)} emails with {EMBED_MODEL} ...")
    vectors = get_embedder().encode(texts, batch_size=32, show_progress_bar=True,
                                    normalize_embeddings=True, convert_to_numpy=True)
    if cache_file:
        np.save(cache_file, vectors)
    return vectors


def to_matrix(table, vectors):
    """Embedding columns + the hand-made feature columns, as one table."""
    emb = pd.DataFrame(vectors, index=table.index, columns=[f"emb_{i}" for i in range(vectors.shape[1])])
    return pd.concat([emb, table[MODEL_NUMERIC_FEATURES]], axis=1)


def make_classifier(n_dims):
    emb_cols = [f"emb_{i}" for i in range(n_dims)]
    return Pipeline([
        ("cols", ColumnTransformer([
            ("emb", "passthrough", emb_cols),
            ("numeric", MaxAbsScaler(), MODEL_NUMERIC_FEATURES),
        ])),
        ("clf", LogisticRegression(C=1.0, max_iter=3000, random_state=SEED)),
    ])


def predict_proba_emails(df, saved):
    """For the backend: a DataFrame with subject, body, body_html, attachments -> phishing probability."""
    table = make_feature_table(df)
    return saved["classifier"].predict_proba(to_matrix(table, embed(table["text"])))[:, 1]


if __name__ == "__main__":
    data_file = sys.argv[1] if len(sys.argv) > 1 else "dataset_plus.csv"
    print(f"Training data: {data_file}   |   embedding model: {EMBED_MODEL}")
    train = pd.read_csv(data_file)
    ou = pd.read_csv("ou_holdout.csv")
    groups = train["group"].values if "group" in train.columns else np.arange(len(train))

    t_train, t_ou = make_feature_table(train), make_feature_table(ou)
    print("Embedding training emails:")
    v_train = embed(t_train["text"], f"embed_cache_{Path(data_file).stem}.npy")
    print("Embedding OU emails:")
    v_ou = embed(t_ou["text"], "embed_cache_ou_holdout.npy")
    X_train, X_ou = to_matrix(t_train, v_train), to_matrix(t_ou, v_ou)
    y_train, y_ou = train["label"].values, ou["label"].values

    # ---------------- 1. grouped cross-validation
    cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SEED)
    cv_prob = cross_val_predict(make_classifier(v_train.shape[1]), X_train, y_train, groups=groups,
                                cv=cv, method="predict_proba")[:, 1]
    scores(y_train, cv_prob, f"5-fold cross-validation on {data_file} (embeddings)")
    by_src = pd.DataFrame({"source": train["source"], "pred": (cv_prob >= THRESHOLD).astype(int)})
    print("\nShare flagged as phishing, by source (cross-validation):")
    print(by_src.groupby("source")["pred"].mean().round(3).to_string())

    # ---------------- 2. train on everything, test once on OU
    clf = make_classifier(v_train.shape[1]).fit(X_train, y_train)
    ou_prob = clf.predict_proba(X_ou)[:, 1]
    scores(y_ou, ou_prob, "OU HOLDOUT (never used for training) - embeddings")

    pred = ou_prob >= THRESHOLD
    fa, caught = int((pred & (y_ou == 0)).sum()), int((pred & (y_ou == 1)).sum())
    print("\n================ COMPARISON ON OU ================")
    print("                               false alarms   phishing caught   ROC AUC")
    print("  TF-IDF, dataset.csv           38 of 48        8 of 10          0.671")
    print("  TF-IDF, dataset_plus.csv      33 of 48        9 of 10          0.781")
    from sklearn.metrics import roc_auc_score
    print(f"  Embeddings, {data_file:17s} {fa:2d} of {int((y_ou == 0).sum())}        "
          f"{caught} of {int((y_ou == 1).sum())}          {roc_auc_score(y_ou, ou_prob):.3f}")

    print("\nEvery OU email (sorted by phishing probability):")
    show = pd.DataFrame({
        "label": y_ou, "prob": ou_prob.round(3),
        "result": np.where(pred == (y_ou == 1), "ok", "WRONG"),
        "source": ou["source"], "subject": ou["subject"].fillna("").str.slice(0, 60),
    }).sort_values("prob", ascending=False)
    with pd.option_context("display.width", 200, "display.max_colwidth", 60):
        print(show.to_string(index=False))

    coef = clf.named_steps["clf"].coef_.ravel()
    print("\nHand-made feature weights:")
    for i, f in enumerate(MODEL_NUMERIC_FEATURES):
        print(f"  {f:24s} {coef[v_train.shape[1] + i]:+.3f}")

    joblib.dump({"embedder": EMBED_MODEL, "classifier": clf}, "phishing_model_embed.pkl")
    print("\nSaved phishing_model_embed.pkl  (needs features.py + sentence-transformers to use)")
