#!/usr/bin/env python3
"""
Convert JSON dataset to CSV format for evaluation
"""

import json
import csv
import sys

def convert_json_to_csv(json_file, csv_file):
    """Convert JSON dataset to CSV with prompt,label columns"""
    try:
        # Load JSON data
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Write CSV
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['prompt', 'label'])  # CSV header
            
            for item in data:
                prompt = item.get('prompt', '')
                label = item.get('label', '')
                if prompt and label:
                    writer.writerow([prompt, label])
        
        print(f"✅ Successfully converted {json_file} to {csv_file}")
        print(f"📊 Total records: {len(data)}")
        
        # Show sample of converted data
        print(f"\n📋 Sample records:")
        for i, item in enumerate(data[:3]):
            print(f"  {i+1}. Prompt: '{item['prompt'][:50]}...' | Label: {item['label']}")
            
    except Exception as e:
        print(f"❌ Error converting file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 convert_to_csv.py <input_json> <output_csv>")
        print("Example: python3 convert_to_csv.py data/4kdata.json data/4kdata.csv")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    convert_json_to_csv(input_file, output_file)