import os
import json
import csv
import sys
from collections import Counter

# Redirect standard output to a file so we can view it easily
sys.stdout = open('/Volumes/SSD 850/PROJECTS/soc/explore_results.txt', 'w', encoding='utf-8')

def inspect_csv(file_path):
    print(f"=== Inspecting CSV: {file_path} ===")
    headers = []
    labels = Counter()
    samples = []
    
    with open(file_path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        try:
            headers = next(reader)
        except StopIteration:
            print("Empty file")
            return
        
        # Let's find index of 'label' or last column
        label_idx = -1
        for idx, h in enumerate(headers):
            if h.lower() == 'label':
                label_idx = idx
                break
        
        row_count = 0
        for row in reader:
            if not row:
                continue
            row_count += 1
            if label_idx != -1 and label_idx < len(row):
                labels[row[label_idx]] += 1
            else:
                labels[row[-1]] += 1
                
            if row_count <= 5:
                samples.append(row)
                
    print(f"Total Rows: {row_count}")
    print(f"Headers ({len(headers)}): {headers[:15]} ... and {len(headers)-15} more")
    print(f"Label distribution: {dict(labels)}")
    print(f"Sample row 1:")
    if samples:
        for k, v in zip(headers, samples[0]):
            print(f"  {k}: {v}")
    print("\n")

def inspect_json_lines(file_path, label_key='attack_label', max_rows=10000):
    print(f"=== Inspecting JSON Lines: {file_path} ===")
    labels = Counter()
    headers = set()
    samples = []
    
    row_count = 0
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip():
                continue
            row_count += 1
            try:
                data = json.loads(line)
            except Exception as e:
                print(f"Error decoding JSON at line {row_count}: {e}")
                continue
                
            if row_count == 1:
                headers.update(data.keys())
                
            # track label
            lbl = data.get(label_key, 'unknown')
            if isinstance(lbl, dict) or isinstance(lbl, list):
                lbl = str(lbl)
            labels[lbl] += 1
            
            if len(samples) < 3:
                samples.append(data)
                
            # Stop early if file is huge to avoid slow execution
            if row_count >= max_rows:
                break
                
    print(f"Read {row_count} rows (limited check for stats)")
    print(f"Keys: {list(headers)}")
    print(f"Label distribution (up to {row_count} rows): {dict(labels)}")
    print(f"Sample row 1:\n{json.dumps(samples[0], indent=2) if samples else 'None'}")
    print("\n")

def inspect_formatted_json(file_path):
    print(f"=== Inspecting Formatted JSON: {file_path} ===")
    with open(file_path, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
        except Exception as e:
            print(f"Error loading JSON: {e}")
            return
            
    print(f"Type: {type(data)}")
    if isinstance(data, list):
        print(f"Total elements: {len(data)}")
        if len(data) > 0:
            sample = data[0]
            print(f"Keys of elements: {list(sample.keys())}")
            print(f"Sample element:\n{json.dumps(sample, indent=2)}")
            # Let's count outputs
            outputs = Counter(item.get('output') for item in data)
            print(f"Output distribution: {dict(outputs)}")
            
            # Let's see if we can parse the input JSON inside to see its attributes
            try:
                inner = json.loads(sample.get('input', '{}'))
                print(f"Inner JSON keys: {list(inner.keys())}")
            except Exception as e:
                print(f"Failed to parse inner input JSON: {e}")
    print("\n")

def main():
    base_dir = "/Volumes/SSD 850/PROJECTS/soc/Datasets"
    
    # 1. CSV dataset
    csv_path = os.path.join(base_dir, "Dataset-Simulasi-Labeled/wazuh_labeled_dataset.csv")
    if os.path.exists(csv_path):
        inspect_csv(csv_path)
        
    # 2. Formatted alerts JSON
    formatted_path = os.path.join(base_dir, "kholil-lil-wazuh-alerts/wazuh_formatted_alerts.json")
    if os.path.exists(formatted_path):
        inspect_formatted_json(formatted_path)
        
    # 3. Labeled dataset (pick one file for sampling)
    labeled_dir = os.path.join(base_dir, "labeled-dataset")
    if os.path.exists(labeled_dir):
        files = sorted([f for f in os.listdir(labeled_dir) if f.endswith('.json')])
        print(f"Labeled dataset files: {files}")
        for file in files:
            sample_file = os.path.join(labeled_dir, file)
            # Let's check attack_label
            inspect_json_lines(sample_file, label_key='attack_label', max_rows=5000)
            
    # 4. Large alerts.json (just read first 1000 lines to see schema and label if any)
    alerts_path = os.path.join(base_dir, "alerts.json")
    if os.path.exists(alerts_path):
        # alerts.json usually doesn't have an attack_label unless we look at rule.groups or mitre
        inspect_json_lines(alerts_path, label_key='attack_label', max_rows=1000)

if __name__ == '__main__':
    main()
