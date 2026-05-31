#!/usr/bin/env python3
"""
Build train-ready dataset by merging all sources in Datasets:
- JSONL alerts (alerts.json)
- JSONL labeled files (labeled-dataset/*.json)
- JSON array instruction format (kholil-lil-wazuh-alerts/wazuh_formatted_alerts.json)
- CSV flattened Wazuh alerts (Dataset-Simulasi-Labeled/wazuh_labeled_dataset.csv)

Output:
- parsed/train_ready_all_sources.csv
"""
import csv
import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pandas as pd


ROOT = Path("Datasets")
OUT = Path("parsed/train_ready_all_sources.csv")
TARGET_LABELS = {"ddos", "xss", "sqli"}


def clean(v):
    if v is None:
        return ""
    if isinstance(v, (list, dict)):
        return json.dumps(v, ensure_ascii=False)
    return str(v).strip()


def safe_int(s, default=0):
    try:
        return int(str(s).strip())
    except Exception:
        return default


def infer_attack_type(label_hint="", texts=None):
    texts = texts or []
    hint = clean(label_hint).lower()
    if hint == "dos":
        return "ddos"
    if hint in TARGET_LABELS:
        return hint

    blob = " ".join(clean(t).lower() for t in texts if t)
    if "ddos" in blob or " dos " in f" {blob} " or "flood" in blob:
        return "ddos"
    if "xss" in blob or "<script" in blob:
        return "xss"
    sqli_keys = ["sql injection", "sqli", "union select", "information_schema", "or 1=1"]
    if any(k in blob for k in sqli_keys):
        return "sqli"
    return ""


def to_features(
    *,
    source_file,
    label,
    timestamp="",
    agent_ip="",
    agent_name="",
    src_ip="",
    src_port="",
    http_method="",
    url="",
    status_code_raw="",
    rule_id="",
    rule_level="",
    rule_description="",
    rule_groups="",
    decoder_name="",
    location="",
    full_log="",
):
    url = clean(url)
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    full_log = clean(full_log)
    rule_groups = clean(rule_groups)
    decoder_name = clean(decoder_name)

    return {
        "source_file": clean(source_file),
        "label": clean(label).lower(),
        "timestamp": clean(timestamp),
        "agent_ip": clean(agent_ip),
        "agent_name": clean(agent_name),
        "src_ip": clean(src_ip),
        "src_port": clean(src_port),
        "http_method": clean(http_method),
        "url_path": clean(parsed.path),
        "url_query_len": len(parsed.query or ""),
        "url_len": len(url),
        "has_union_select": int("union%20select" in url.lower() or "union select" in full_log.lower()),
        "has_script_tag": int("<script" in url.lower() or "<script" in full_log.lower()),
        "has_dvwa_xss_path": int("/dvwa/vulnerabilities/xss" in url.lower()),
        "has_dvwa_sqli_path": int("/dvwa/vulnerabilities/sqli" in url.lower()),
        "status_code": safe_int(clean(status_code_raw), 0),
        "rule_id": clean(rule_id),
        "rule_level": safe_int(clean(rule_level), 0),
        "rule_description": clean(rule_description),
        "rule_groups": rule_groups,
        "is_sql_rule_group": int("sql_injection" in rule_groups.lower()),
        "is_attack_group": int("attack" in rule_groups.lower()),
        "is_modsecurity_event": int("modsecurity" in rule_groups.lower() or "modsecurity" in decoder_name.lower()),
        "log_len": len(full_log),
        "has_flood_ua": int("mozilla/5.0 (flood)" in full_log.lower()),
        "has_query_id_param": int("id" in query),
        "decoder_name": decoder_name,
        "location": clean(location),
        "full_log": full_log,
    }


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def from_labeled_json(path: Path):
    for row in iter_jsonl(path):
        rule = row.get("rule", {}) or {}
        data = row.get("data", {}) or {}
        agent = row.get("agent", {}) or {}
        pre = row.get("predecoder", {}) or {}
        label = infer_attack_type(
            label_hint=row.get("attack_label", ""),
            texts=[
                rule.get("description"),
                rule.get("groups"),
                data.get("url"),
                row.get("full_log"),
            ],
        )
        if label not in TARGET_LABELS:
            continue
        yield to_features(
            source_file=path.name,
            label=label,
            timestamp=row.get("@timestamp") or row.get("timestamp", ""),
            agent_ip=agent.get("ip", ""),
            agent_name=agent.get("name", ""),
            src_ip=data.get("srcip") or data.get("src_ip", ""),
            src_port=data.get("srcport") or data.get("src_port", ""),
            http_method=data.get("protocol", ""),
            url=data.get("url", ""),
            status_code_raw=data.get("id", ""),
            rule_id=rule.get("id", ""),
            rule_level=rule.get("level", ""),
            rule_description=rule.get("description", ""),
            rule_groups=rule.get("groups", ""),
            decoder_name=(row.get("decoder", {}) or {}).get("name", ""),
            location=row.get("location", ""),
            full_log=row.get("full_log", ""),
        )


def from_alerts_json(path: Path):
    for row in iter_jsonl(path):
        rule = row.get("rule", {}) or {}
        data = row.get("data", {}) or {}
        agent = row.get("agent", {}) or {}
        label = infer_attack_type(
            texts=[
                rule.get("description"),
                rule.get("groups"),
                data.get("url"),
                row.get("full_log"),
            ]
        )
        if label not in TARGET_LABELS:
            continue
        yield to_features(
            source_file=path.name,
            label=label,
            timestamp=row.get("@timestamp") or row.get("timestamp", ""),
            agent_ip=agent.get("ip", ""),
            agent_name=agent.get("name", ""),
            src_ip=data.get("srcip") or data.get("src_ip", ""),
            src_port=data.get("srcport") or data.get("src_port", ""),
            http_method=data.get("protocol", ""),
            url=data.get("url", ""),
            status_code_raw=data.get("id", ""),
            rule_id=rule.get("id", ""),
            rule_level=rule.get("level", ""),
            rule_description=rule.get("description", ""),
            rule_groups=rule.get("groups", ""),
            decoder_name=(row.get("decoder", {}) or {}).get("name", ""),
            location=row.get("location", ""),
            full_log=row.get("full_log", ""),
        )


def from_formatted_json(path: Path):
    arr = json.loads(path.read_text(encoding="utf-8"))
    for item in arr:
        raw_input = item.get("input", "")
        try:
            row = json.loads(raw_input)
        except Exception:
            continue
        rule = row.get("rule", {}) or {}
        data = row.get("data", {}) or {}
        agent = row.get("agent", {}) or {}
        label = infer_attack_type(
            label_hint=item.get("output", ""),
            texts=[
                rule.get("description"),
                rule.get("groups"),
                data.get("url"),
                row.get("full_log"),
            ],
        )
        if label not in TARGET_LABELS:
            continue
        yield to_features(
            source_file=path.name,
            label=label,
            timestamp=row.get("@timestamp") or row.get("timestamp", ""),
            agent_ip=agent.get("ip", ""),
            agent_name=agent.get("name", ""),
            src_ip=data.get("srcip") or data.get("src_ip", ""),
            src_port=data.get("srcport") or data.get("src_port", ""),
            http_method=data.get("protocol", ""),
            url=data.get("url", ""),
            status_code_raw=data.get("id", ""),
            rule_id=rule.get("id", ""),
            rule_level=rule.get("level", ""),
            rule_description=rule.get("description", ""),
            rule_groups=rule.get("groups", ""),
            decoder_name=(row.get("decoder", {}) or {}).get("name", ""),
            location=row.get("location", ""),
            full_log=row.get("full_log", ""),
        )


def from_csv(path: Path):
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            label = infer_attack_type(
                label_hint=row.get("label", ""),
                texts=[
                    row.get("_source.rule.description", ""),
                    row.get("_source.rule.groups", ""),
                    row.get("_source.data.url", ""),
                    row.get("_source.full_log", ""),
                ],
            )
            if label not in TARGET_LABELS:
                continue
            yield to_features(
                source_file=path.name,
                label=label,
                timestamp=row.get("_source.@timestamp", "") or row.get("_source.timestamp", ""),
                agent_ip=row.get("_source.agent.ip", ""),
                agent_name=row.get("_source.agent.name", ""),
                src_ip=row.get("_source.data.srcip", ""),
                src_port=row.get("_source.data.srcport", ""),
                http_method=row.get("_source.data.protocol", ""),
                url=row.get("_source.data.url", ""),
                status_code_raw=row.get("_source.data.id", ""),
                rule_id=row.get("_source.rule.id", ""),
                rule_level=row.get("_source.rule.level", ""),
                rule_description=row.get("_source.rule.description", ""),
                rule_groups=row.get("_source.rule.groups", ""),
                decoder_name=row.get("_source.decoder.name", ""),
                location=row.get("_source.location", ""),
                full_log=row.get("_source.full_log", ""),
            )


def main():
    rows = []

    alerts = ROOT / "alerts.json"
    if alerts.exists():
        rows.extend(from_alerts_json(alerts))

    labeled_dir = ROOT / "labeled-dataset"
    if labeled_dir.exists():
        for p in sorted(labeled_dir.glob("*.json")):
            rows.extend(from_labeled_json(p))

    formatted = ROOT / "kholil-lil-wazuh-alerts" / "wazuh_formatted_alerts.json"
    if formatted.exists():
        rows.extend(from_formatted_json(formatted))

    csv_src = ROOT / "Dataset-Simulasi-Labeled" / "wazuh_labeled_dataset.csv"
    if csv_src.exists():
        rows.extend(from_csv(csv_src))

    OUT.parent.mkdir(parents=True, exist_ok=True)
    df = pd.DataFrame(rows)
    df.to_csv(OUT, index=False)

    print(f"Output: {OUT}")
    print(f"Rows  : {len(df)}")
    if len(df):
        print("By source_file:")
        print(df["source_file"].value_counts().to_string())
        print("\nBy label:")
        print(df["label"].value_counts().to_string())


if __name__ == "__main__":
    main()
