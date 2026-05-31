#!/usr/bin/env python3
import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


ROOT = Path("Datasets")
OUT_DIR = Path("parsed")
OUT_DIR.mkdir(exist_ok=True)


FOCUS_MAP = {
    "ddos": "ddos",
    "dos": "ddos",
    "xss": "xss",
    "sqli": "sqli",
    "sql_injection": "sqli",
}


def _str(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (list, dict)):
        return json.dumps(v, ensure_ascii=False)
    return str(v)


def _pick_attack(texts: Iterable[str], label_hint: str = "") -> Optional[str]:
    hint = label_hint.strip().lower()
    if hint in FOCUS_MAP:
        return FOCUS_MAP[hint]

    blob = " ".join(t.lower() for t in texts if t)
    if "ddos" in blob or "dos" in blob or "flood" in blob:
        return "ddos"
    if "xss" in blob or "<script" in blob:
        return "xss"
    sqli_tokens = ["sql injection", "sqli", "union select", "or 1=1", "information_schema"]
    if any(t in blob for t in sqli_tokens):
        return "sqli"
    return None


def normalize_record(source_file: str, row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    rule = row.get("rule", {})
    data = row.get("data", {})
    agent = row.get("agent", {})
    pre = row.get("predecoder", {})

    attack = _pick_attack(
        texts=[
            _str(rule.get("description")),
            _str(rule.get("groups")),
            _str(data.get("url")),
            _str(row.get("full_log")),
        ],
        label_hint=_str(row.get("attack_label")),
    )
    if attack is None:
        return None

    return {
        "source_file": source_file,
        "attack_type": attack,
        "timestamp": row.get("@timestamp") or row.get("timestamp") or "",
        "event_id": row.get("id", ""),
        "agent_id": _str(agent.get("id")),
        "agent_name": _str(agent.get("name")),
        "agent_ip": _str(agent.get("ip")),
        "src_ip": _str(data.get("srcip") or data.get("src_ip")),
        "src_port": _str(data.get("srcport") or data.get("src_port")),
        "http_method": _str(data.get("protocol")),
        "url": _str(data.get("url")),
        "status_or_data_id": _str(data.get("id")),
        "rule_id": _str(rule.get("id")),
        "rule_level": _str(rule.get("level")),
        "rule_description": _str(rule.get("description")),
        "rule_groups": _str(rule.get("groups")),
        "location": _str(row.get("location")),
        "decoder_name": _str(row.get("decoder", {}).get("name")),
        "program_name": _str(pre.get("program_name")),
        "raw_label": _str(row.get("attack_label")),
        "full_log": _str(row.get("full_log")),
    }


def parse_jsonl(path: Path, max_rows: Optional[int] = None) -> Iterable[Dict[str, Any]]:
    seen = 0
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            seen += 1
            if max_rows is not None and seen > max_rows:
                break
            row = json.loads(line)
            rec = normalize_record(path.name, row)
            if rec:
                yield rec


def parse_formatted_json(path: Path, max_rows: Optional[int] = None) -> Iterable[Dict[str, Any]]:
    arr = json.loads(path.read_text(encoding="utf-8"))
    for i, item in enumerate(arr, start=1):
        if max_rows is not None and i > max_rows:
            break
        payload = item.get("input", "")
        try:
            row = json.loads(payload)
        except Exception:
            continue
        rec = normalize_record(path.name, row)
        if rec:
            rec["raw_label"] = item.get("output", "")
            yield rec


def parse_csv(path: Path, max_rows: Optional[int] = None) -> Iterable[Dict[str, Any]]:
    with path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader, start=1):
            if max_rows is not None and i > max_rows:
                break
            label = (row.get("label") or "").strip().lower()
            attack = _pick_attack(
                texts=[
                    row.get("_source.rule.description", ""),
                    row.get("_source.rule.groups", ""),
                    row.get("_source.data.url", ""),
                    row.get("_source.full_log", ""),
                ],
                label_hint=label,
            )
            if attack is None:
                continue
            yield {
                "source_file": path.name,
                "attack_type": attack,
                "timestamp": row.get("_source.@timestamp", "") or row.get("_source.timestamp", ""),
                "event_id": row.get("_source.id", "") or row.get("_id", ""),
                "agent_id": row.get("_source.agent.id", ""),
                "agent_name": row.get("_source.agent.name", ""),
                "agent_ip": row.get("_source.agent.ip", ""),
                "src_ip": row.get("_source.data.srcip", ""),
                "src_port": row.get("_source.data.srcport", ""),
                "http_method": row.get("_source.data.protocol", ""),
                "url": row.get("_source.data.url", ""),
                "status_or_data_id": row.get("_source.data.id", ""),
                "rule_id": row.get("_source.rule.id", ""),
                "rule_level": row.get("_source.rule.level", ""),
                "rule_description": row.get("_source.rule.description", ""),
                "rule_groups": row.get("_source.rule.groups", ""),
                "location": row.get("_source.location", ""),
                "decoder_name": row.get("_source.decoder.name", ""),
                "program_name": row.get("_source.predecoder.program_name", ""),
                "raw_label": row.get("label", ""),
                "full_log": row.get("_source.full_log", ""),
            }


def main() -> None:
    sample_size = 100
    summary: Dict[str, int] = {}

    out_file = OUT_DIR / "focus_attacks_normalized.jsonl"
    with out_file.open("w", encoding="utf-8") as f:
        for p in (ROOT / "labeled-dataset").glob("*.json"):
            for r in parse_jsonl(p, max_rows=sample_size):
                summary[r["attack_type"]] = summary.get(r["attack_type"], 0) + 1
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

        for r in parse_jsonl(ROOT / "alerts.json", max_rows=sample_size):
            summary[r["attack_type"]] = summary.get(r["attack_type"], 0) + 1
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

        for r in parse_formatted_json(
            ROOT / "kholil-lil-wazuh-alerts" / "wazuh_formatted_alerts.json", max_rows=sample_size
        ):
            summary[r["attack_type"]] = summary.get(r["attack_type"], 0) + 1
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

        for r in parse_csv(ROOT / "Dataset-Simulasi-Labeled" / "wazuh_labeled_dataset.csv", max_rows=sample_size):
            summary[r["attack_type"]] = summary.get(r["attack_type"], 0) + 1
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"Output: {out_file}")
    print(f"Sample per dataset: {sample_size}")
    print("Counts:", summary)


if __name__ == "__main__":
    main()
