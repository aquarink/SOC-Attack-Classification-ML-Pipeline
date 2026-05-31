import os
import json
import sys
from collections import Counter

sys.stdout = open('/Volumes/SSD 850/PROJECTS/soc/detailed_results.txt', 'w', encoding='utf-8')

def analyze_labeled_dataset_labels():
    print("=== Analyzing Labeled Dataset Folder ===")
    labeled_dir = "/Volumes/SSD 850/PROJECTS/soc/Datasets/labeled-dataset"
    if not os.path.exists(labeled_dir):
        print("labeled-dataset folder not found")
        return
        
    files = sorted([f for f in os.listdir(labeled_dir) if f.endswith('.json')])
    for file in files:
        file_path = os.path.join(labeled_dir, file)
        label_counter = Counter()
        row_count = 0
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip():
                    continue
                row_count += 1
                try:
                    data = json.loads(line)
                    lbl = data.get('attack_label', 'unknown')
                    label_counter[lbl] += 1
                except Exception as e:
                    pass
        print(f"File: {file} | Total rows: {row_count} | Labels: {dict(label_counter)}")
    print("\n")

def analyze_formatted_json():
    print("=== Analyzing Formatted JSON ===")
    formatted_path = "/Volumes/SSD 850/PROJECTS/soc/Datasets/kholil-lil-wazuh-alerts/wazuh_formatted_alerts.json"
    if not os.path.exists(formatted_path):
        print("wazuh_formatted_alerts.json not found")
        return
        
    with open(formatted_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
        
    rule_ids = Counter()
    descriptions = Counter()
    groups_counter = Counter()
    total_elements = len(data)
    
    # We will look for keywords in the description or groups
    keyword_matches = Counter()
    
    for idx, item in enumerate(data):
        input_str = item.get('input', '{}')
        try:
            inner = json.loads(input_str)
            rule = inner.get('rule', {})
            rule_id = rule.get('id', 'unknown')
            desc = rule.get('description', 'unknown')
            groups = rule.get('groups', [])
            output = item.get('output', 'unknown')
            
            rule_ids[rule_id] += 1
            descriptions[desc] += 1
            for g in groups:
                groups_counter[g] += 1
                
            # Classify based on rule description or groups
            matched = False
            desc_lower = desc.lower()
            groups_lower = [g.lower() for g in groups]
            
            if 'sql' in desc_lower or 'sqli' in groups_lower or 'sql_injection' in groups_lower:
                keyword_matches[f"sqli ({output})"] += 1
                matched = True
            if 'xss' in desc_lower or 'xss' in groups_lower or 'cross site scripting' in desc_lower:
                keyword_matches[f"xss ({output})"] += 1
                matched = True
            if any(k in desc_lower for k in ['dos', 'ddos', 'flood', 'slowloris']) or any(k in groups_lower for k in ['dos', 'ddos']):
                keyword_matches[f"dos_ddos ({output})"] += 1
                matched = True
                
            if not matched:
                keyword_matches[f"other ({output})"] += 1
                
        except Exception as e:
            keyword_matches[f"error_parsing"] += 1
            
    print(f"Total elements: {total_elements}")
    print(f"Rule ID distribution: {dict(rule_ids)}")
    print(f"Rule description distribution (top 15): {dict(descriptions.most_common(15))}")
    print(f"Groups distribution: {dict(groups_counter)}")
    print(f"Keyword-based classification (with true/false positive output): {dict(keyword_matches)}")
    print("\n")

def analyze_large_alerts_json():
    print("=== Analyzing Large alerts.json (Sampling first 100,000 rows for rule distribution) ===")
    alerts_path = "/Volumes/SSD 850/PROJECTS/soc/Datasets/alerts.json"
    if not os.path.exists(alerts_path):
        print("alerts.json not found")
        return
        
    rule_ids = Counter()
    descriptions = Counter()
    groups_counter = Counter()
    keyword_matches = Counter()
    row_count = 0
    
    with open(alerts_path, 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip():
                continue
            row_count += 1
            try:
                data = json.loads(line)
                rule = data.get('rule', {})
                rule_id = rule.get('id', 'unknown')
                desc = rule.get('description', 'unknown')
                groups = rule.get('groups', [])
                
                rule_ids[rule_id] += 1
                descriptions[desc] += 1
                for g in groups:
                    groups_counter[g] += 1
                    
                # Classify based on rule description or groups
                matched = False
                desc_lower = desc.lower()
                groups_lower = [g.lower() for g in groups]
                
                if 'sql' in desc_lower or 'sqli' in groups_lower or 'sql_injection' in groups_lower:
                    keyword_matches["sqli"] += 1
                    matched = True
                if 'xss' in desc_lower or 'xss' in groups_lower or 'cross site scripting' in desc_lower:
                    keyword_matches["xss"] += 1
                    matched = True
                if any(k in desc_lower for k in ['dos', 'ddos', 'flood', 'slowloris']) or any(k in groups_lower for k in ['dos', 'ddos']):
                    keyword_matches["dos_ddos"] += 1
                    matched = True
                    
                if not matched:
                    keyword_matches["other"] += 1
                    
            except Exception as e:
                pass
                
            if row_count >= 100000:
                break
                
    print(f"Scanned {row_count} rows in alerts.json")
    print(f"Rule ID distribution: {dict(rule_ids.most_common(15))}")
    print(f"Rule description distribution (top 15): {dict(descriptions.most_common(15))}")
    print(f"Groups distribution (top 15): {dict(groups_counter.most_common(15))}")
    print(f"Keyword-based classification: {dict(keyword_matches)}")
    print("\n")

def main():
    analyze_labeled_dataset_labels()
    analyze_formatted_json()
    analyze_large_alerts_json()

if __name__ == '__main__':
    main()
