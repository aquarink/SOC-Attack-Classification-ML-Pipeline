#!/usr/bin/env python3
"""
Train baseline model from merged all-sources dataset.
Input default : parsed/train_ready_all_sources.csv
Output default: parsed/model_all_sources/
"""
import argparse
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


def build_pipeline():
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
        "source_file",
        "agent_ip",
        "agent_name",
        "src_ip",
        "src_port",
        "http_method",
        "url_path",
        "rule_id",
        "decoder_name",
        "location",
    ]
    text_col = "rule_description"

    preprocess = ColumnTransformer(
        transformers=[
            ("num", "passthrough", numeric_cols),
            ("cat", OneHotEncoder(handle_unknown="ignore"), cat_cols),
            ("txt", TfidfVectorizer(ngram_range=(1, 2), min_df=1), text_col),
        ]
    )

    model = RandomForestClassifier(
        n_estimators=500,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,
    )

    return Pipeline(steps=[("preprocess", preprocess), ("model", model)])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="parsed/train_ready_all_sources.csv")
    parser.add_argument("--output_dir", default="parsed/model_all_sources")
    parser.add_argument("--test_size", type=float, default=0.2)
    parser.add_argument("--random_state", type=int, default=42)
    args = parser.parse_args()

    src = Path(args.input)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not src.exists():
        raise FileNotFoundError(f"Input file not found: {src}")

    df = pd.read_csv(src)
    if "label" not in df.columns:
        raise ValueError("Input CSV must contain 'label' column")

    # minimal cleanup
    df = df.fillna("")
    y = df["label"].astype(str).str.lower()
    X = df.drop(columns=["label"])

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=args.test_size,
        random_state=args.random_state,
        stratify=y,
    )

    clf = build_pipeline()
    clf.fit(X_train, y_train)
    preds = clf.predict(X_test)

    labels = sorted(y.unique())
    metrics = {
        "input": str(src),
        "train_size": int(len(X_train)),
        "test_size": int(len(X_test)),
        "accuracy": float(accuracy_score(y_test, preds)),
        "labels": labels,
        "confusion_matrix": confusion_matrix(y_test, preds, labels=labels).tolist(),
        "classification_report": classification_report(y_test, preds, output_dict=True),
    }

    model_path = out_dir / "baseline_rf_all_sources.joblib"
    metrics_path = out_dir / "metrics_all_sources.json"

    joblib.dump(clf, model_path)
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print(f"Input        : {src}")
    print(f"Train/Test   : {len(X_train)}/{len(X_test)}")
    print(f"Accuracy     : {metrics['accuracy']:.4f}")
    print(f"Model        : {model_path}")
    print(f"Metrics JSON : {metrics_path}")
    print("Confusion Matrix labels:", labels)
    print(metrics["confusion_matrix"])


if __name__ == "__main__":
    main()
