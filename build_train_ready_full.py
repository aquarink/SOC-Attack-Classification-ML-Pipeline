#!/usr/bin/env python3
"""
Build full train-ready dataset from the original CSV (all rows),
filtered to labels: ddos, xss, sqli.
"""
import csv
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pandas as pd


SRC = Path("Datasets/Dataset-Simulasi-Labeled/wazuh_labeled_dataset.csv")
OUT = Path("parsed/train_ready_full.csv")
TARGET_LABELS = {"ddos", "xss", "sqli"}


def clean(s):
    return (s or "").strip()


def safe_int(s, default=0):
    try:
        return int(str(s).strip())
    except Exception:
        return default


def main():
    rows = []
    with SRC.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            label = clean(row.get("label", "")).lower()
            if label not in TARGET_LABELS:
                continue

            url = clean(row.get("_source.data.url", ""))
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            full_log = clean(row.get("_source.full_log", ""))
            rule_groups = clean(row.get("_source.rule.groups", ""))
            decoder_name = clean(row.get("_source.decoder.name", ""))

            rows.append(
                {
                    "label": label,
                    "timestamp": clean(row.get("_source.@timestamp", "")) or clean(row.get("_source.timestamp", "")),
                    "agent_ip": clean(row.get("_source.agent.ip", "")),
                    "agent_name": clean(row.get("_source.agent.name", "")),
                    "src_ip": clean(row.get("_source.data.srcip", "")),
                    "src_port": clean(row.get("_source.data.srcport", "")),
                    "http_method": clean(row.get("_source.data.protocol", "")),
                    "url_path": parsed.path,
                    "url_query_len": len(parsed.query or ""),
                    "url_len": len(url),
                    "has_union_select": int("union%20select" in url.lower() or "union select" in full_log.lower()),
                    "has_script_tag": int("<script" in url.lower() or "<script" in full_log.lower()),
                    "has_dvwa_xss_path": int("/dvwa/vulnerabilities/xss" in url.lower()),
                    "has_dvwa_sqli_path": int("/dvwa/vulnerabilities/sqli" in url.lower()),
                    "status_code": safe_int(clean(row.get("_source.data.id", "")), 0),
                    "rule_id": clean(row.get("_source.rule.id", "")),
                    "rule_level": safe_int(clean(row.get("_source.rule.level", "")), 0),
                    "rule_description": clean(row.get("_source.rule.description", "")),
                    "rule_groups": rule_groups,
                    "is_sql_rule_group": int("sql_injection" in rule_groups.lower()),
                    "is_attack_group": int("attack" in rule_groups.lower()),
                    "is_modsecurity_event": int("modsecurity" in rule_groups.lower() or "modsecurity" in decoder_name.lower()),
                    "log_len": len(full_log),
                    "has_flood_ua": int("mozilla/5.0 (flood)" in full_log.lower()),
                    "has_query_id_param": int("id" in query),
                    "decoder_name": decoder_name,
                    "location": clean(row.get("_source.location", "")),
                    "full_log": full_log,
                }
            )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    df = pd.DataFrame(rows)
    df.to_csv(OUT, index=False)

    print(f"Input : {SRC}")
    print(f"Output: {OUT}")
    print(f"Rows  : {len(df)}")
    if len(df):
        print("Label counts:")
        print(df["label"].value_counts().to_string())


if __name__ == "__main__":
    main()
