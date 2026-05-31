#!/usr/bin/env python3
import csv
import json
from pathlib import Path
from urllib.parse import urlparse, parse_qs


SRC = Path("parsed/focus_attacks_csv_100each.jsonl")
OUT = Path("parsed/train_ready.csv")


def clean(s: str) -> str:
    return (s or "").strip()


def safe_int(s: str, default: int = 0) -> int:
    try:
        return int(str(s).strip())
    except Exception:
        return default


def main() -> None:
    rows = []
    with SRC.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            r = json.loads(line)
            url = clean(r.get("url", ""))
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            full_log = clean(r.get("full_log", ""))
            rule_groups = clean(r.get("rule_groups", ""))
            label = clean(r.get("attack_type", "")).lower()

            features = {
                "label": label,
                "timestamp": clean(r.get("timestamp", "")),
                "agent_ip": clean(r.get("agent_ip", "")),
                "src_ip": clean(r.get("src_ip", "")),
                "http_method": clean(r.get("http_method", "")),
                "url_path": parsed.path,
                "url_query_len": len(parsed.query or ""),
                "url_len": len(url),
                "has_union_select": int("union%20select" in url.lower() or "union select" in full_log.lower()),
                "has_script_tag": int("<script" in url.lower() or "<script" in full_log.lower()),
                "has_dvwa_xss_path": int("/dvwa/vulnerabilities/xss" in url.lower()),
                "has_dvwa_sqli_path": int("/dvwa/vulnerabilities/sqli" in url.lower()),
                "status_code": safe_int(clean(r.get("status_or_data_id", "")), 0),
                "rule_id": clean(r.get("rule_id", "")),
                "rule_level": safe_int(clean(r.get("rule_level", "")), 0),
                "rule_description": clean(r.get("rule_description", "")),
                "rule_groups": rule_groups,
                "is_sql_rule_group": int("sql_injection" in rule_groups.lower()),
                "is_attack_group": int("attack" in rule_groups.lower()),
                "is_modsecurity_event": int("modsecurity" in rule_groups.lower() or "modsecurity" in clean(r.get("decoder_name", "")).lower()),
                "log_len": len(full_log),
                "has_flood_ua": int("mozilla/5.0 (flood)" in full_log.lower()),
                "has_query_id_param": int("id" in query),
            }
            rows.append(features)

    fieldnames = list(rows[0].keys()) if rows else []
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    print(f"Input : {SRC}")
    print(f"Output: {OUT}")
    print(f"Rows  : {len(rows)}")


if __name__ == "__main__":
    main()
