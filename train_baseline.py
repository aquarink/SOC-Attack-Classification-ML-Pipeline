#!/usr/bin/env python3
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder


SRC = Path("parsed/train_ready.csv")
OUT_DIR = Path("parsed/model")
OUT_DIR.mkdir(parents=True, exist_ok=True)


def main() -> None:
    df = pd.read_csv(SRC)

    y = df["label"].astype(str)
    X = df.drop(columns=["label"])

    # Keep engineered numerical features as-is, encode categoricals, and vectorize descriptions.
    numeric_cols = [
        "url_query_len",
        "url_len",
        "has_union_select",
        "has_script_tag",
        "has_dvwa_xss_path",
        "has_dvwa_sqli_path",
        "status_code",
        "rule_level",
        "is_sql_rule_group",
        "is_attack_group",
        "is_modsecurity_event",
        "log_len",
        "has_flood_ua",
        "has_query_id_param",
    ]
    cat_cols = [
        "agent_ip",
        "src_ip",
        "http_method",
        "url_path",
        "rule_id",
    ]
    text_col = "rule_description"

    pre = ColumnTransformer(
        transformers=[
            ("num", "passthrough", numeric_cols),
            ("cat", OneHotEncoder(handle_unknown="ignore"), cat_cols),
            ("txt", TfidfVectorizer(ngram_range=(1, 2), min_df=1), text_col),
        ]
    )

    model = RandomForestClassifier(
        n_estimators=300,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,
    )

    clf = Pipeline(
        steps=[
            ("preprocess", pre),
            ("model", model),
        ]
    )

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf.fit(X_train, y_train)
    preds = clf.predict(X_test)

    acc = accuracy_score(y_test, preds)
    report = classification_report(y_test, preds, output_dict=True)
    cm = confusion_matrix(y_test, preds, labels=sorted(y.unique()))

    joblib.dump(clf, OUT_DIR / "baseline_rf.joblib")

    metrics = {
        "accuracy": acc,
        "labels": sorted(y.unique()),
        "confusion_matrix": cm.tolist(),
        "classification_report": report,
        "train_size": int(len(X_train)),
        "test_size": int(len(X_test)),
    }
    (OUT_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print(f"Input        : {SRC}")
    print(f"Train/Test   : {len(X_train)}/{len(X_test)}")
    print(f"Accuracy     : {acc:.4f}")
    print(f"Model        : {OUT_DIR / 'baseline_rf.joblib'}")
    print(f"Metrics JSON : {OUT_DIR / 'metrics.json'}")
    print("Confusion Matrix labels:", sorted(y.unique()))
    print(cm)


if __name__ == "__main__":
    main()
