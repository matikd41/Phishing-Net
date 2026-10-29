"""
train_model.py  -  Task 3: baseline model + evaluation
  1. 5-fold cross-validation on dataset.csv (TF-IDF is re-fitted inside every fold)
  2. Train on all of dataset.csv, test ONCE on ou_holdout.csv
  3. Save the trained pipeline to phishing_model.pkl

Run:   python train_model.py                     (uses dataset.csv, the baseline)
       python train_model.py dataset_plus.csv    (uses the file you name, e.g. with PhishFuzzer added)
Needs: features.py in the same folder, pandas, numpy, scikit-learn
"""

import sys

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import StratifiedGroupKFold, cross_val_predict
from sklearn.pipeline import Pipeline

from features import MODEL_NUMERIC_FEATURES, build_preprocessor, make_feature_table

SEED = 42
THRESHOLD = 0.5   # probability above this = phishing


def make_model():
    return Pipeline([
        ("features", build_preprocessor()),
        ("clf", LogisticRegression(C=1.0, max_iter=2000, solver="liblinear", random_state=SEED)),
    ])


def scores(y_true, prob, title):
    pred = (prob >= THRESHOLD).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    print(f"\n---------- {title} ----------")
    print(f"Accuracy : {accuracy_score(y_true, pred):.3f}")
    print(f"Precision: {precision_score(y_true, pred, zero_division=0):.3f}   (of emails flagged, share really phishing)")
    print(f"Recall   : {recall_score(y_true, pred, zero_division=0):.3f}   (of phishing emails, share caught)")
    print(f"F1       : {f1_score(y_true, pred, zero_division=0):.3f}")
    if len(set(y_true)) == 2:
        print(f"ROC AUC  : {roc_auc_score(y_true, prob):.3f}")
    print(f"Confusion matrix:  legit OK={tn}  legit FLAGGED (false alarm)={fp}")
    print(f"                   phishing MISSED={fn}  phishing CAUGHT={tp}")


if __name__ == "__main__":
    print(f"scikit-learn {sklearn.__version__}  (the backend must use the same version to load the .pkl)")

    data_file = sys.argv[1] if len(sys.argv) > 1 else "dataset.csv"
    print(f"Training data: {data_file}")
    train = pd.read_csv(data_file)
    # A real email and its AI variants share a group, so they always land in the same fold
    groups = train["group"].values if "group" in train.columns else np.arange(len(train))
    ou = pd.read_csv("ou_holdout.csv")
    X_train, y_train = make_feature_table(train), train["label"].values
    X_ou, y_ou = make_feature_table(ou), ou["label"].values

    # ---------------- 1. cross-validation on the public data
    cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SEED)
    cv_prob = cross_val_predict(make_model(), X_train, y_train, groups=groups, cv=cv,
                                method="predict_proba")[:, 1]
    scores(y_train, cv_prob, f"5-fold cross-validation on {data_file}")

    cv_pred = (cv_prob >= THRESHOLD).astype(int)
    print("\nRecall / false-alarm rate by source (cross-validation):")
    by_src = pd.DataFrame({"source": train["source"], "label": y_train, "pred": cv_pred})
    print(by_src.groupby("source").apply(lambda g: round((g["pred"] == 1).mean(), 3), include_groups=False)
          .rename("share flagged as phishing").to_string())

    # ---------------- 2. train on everything, test once on OU
    model = make_model().fit(X_train, y_train)
    ou_prob = model.predict_proba(X_ou)[:, 1]
    scores(y_ou, ou_prob, "OU HOLDOUT (never used for training)")

    print("\nEvery OU email (sorted by phishing probability):")
    show = pd.DataFrame({
        "label": y_ou, "prob": ou_prob.round(3),
        "result": np.where((ou_prob >= THRESHOLD) == (y_ou == 1), "ok", "WRONG"),
        "source": ou["source"], "subject": ou["subject"].fillna("").str.slice(0, 60),
    }).sort_values("prob", ascending=False)
    with pd.option_context("display.width", 200, "display.max_colwidth", 60):
        print(show.to_string(index=False))

    # ---------------- 3. what the model learned (for the report)
    pre = model.named_steps["features"]
    names = list(pre.named_transformers_["tfidf"].get_feature_names_out()) + MODEL_NUMERIC_FEATURES
    coef = model.named_steps["clf"].coef_.ravel()
    order = np.argsort(coef)
    print("\nTop 20 features pushing toward PHISHING:", ", ".join(names[i] for i in order[::-1][:20]))
    print("\nTop 20 features pushing toward LEGIT:   ", ", ".join(names[i] for i in order[:20]))
    print("\nHand-made feature weights:")
    for f in MODEL_NUMERIC_FEATURES:
        print(f"  {f:24s} {coef[names.index(f)]:+.3f}")

    out = "phishing_model.pkl" if data_file == "dataset.csv" else "phishing_model_plus.pkl"
    joblib.dump(model, out)
    print(f"\nSaved {out}")
