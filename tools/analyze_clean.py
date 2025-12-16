import json
from collections import Counter

# Load the scan result
with open('sample/result/Malware2025_2_1_20251212_085308.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

clean_samples = [x for x in data['details'] if x['status'] == 'clean']

print(f"Total clean (undetected) samples: {len(clean_samples)}")
print("\n" + "="*80)
print("First 20 undetected samples:")
print("="*80)

for i, sample in enumerate(clean_samples[:20], 1):
    print(f"\n{i}. {sample['file_name']}")
    print(f"   Score: {sample['score']}")
    print(f"   Matches: {sample['matches'][:10]}")

# Analyze score distribution
scores = [x['score'] for x in clean_samples]
print("\n" + "="*80)
print("Score Distribution:")
print("="*80)
score_ranges = {
    "0": 0,
    "1-10": 0,
    "11-20": 0,
    "21-30": 0,
    "31-40": 0,
    "41-49": 0
}

for score in scores:
    if score == 0:
        score_ranges["0"] += 1
    elif score <= 10:
        score_ranges["1-10"] += 1
    elif score <= 20:
        score_ranges["11-20"] += 1
    elif score <= 30:
        score_ranges["21-30"] += 1
    elif score <= 40:
        score_ranges["31-40"] += 1
    else:
        score_ranges["41-49"] += 1

for range_name, count in score_ranges.items():
    print(f"Score {range_name:>6}: {count:>3} samples")

# Count common rules in undetected samples
all_rules = []
for sample in clean_samples:
    all_rules.extend(sample['matches'])

rule_counter = Counter(all_rules)
print("\n" + "="*80)
print("Top 20 rules in undetected samples:")
print("="*80)
for rule, count in rule_counter.most_common(20):
    print(f"{rule:50} : {count:3} times")
