"""Summarise e4_incidents.csv into e4_summary.json (read-only with respect to the CSV)."""
import csv, collections, json
rows = list(csv.DictReader(open('e4_incidents.csv', encoding='utf-8')))
itw = [r for r in rows if r['exploited'] == 'ITW']
summ = {
    'records': len(rows),
    'by_capability': dict(collections.Counter(r['capability_A'] for r in rows)),
    'exploited_in_wild': len(itw),
    'policy_origination': sum(r['policy_write_A'] == 'Y' for r in rows),
    'confidentiality_only': sum(r['capability_A'] == 'C3' for r in rows),
    'vendors': sorted({r['vendor'] for r in rows}),
    'years': [min(int(r['year']) for r in rows), max(int(r['year']) for r in rows)],
    'itw_all_policy_origination': all(r['policy_write_A'] == 'Y' for r in itw),
}
json.dump(summ, open('e4_summary.json', 'w'), indent=1)
print(json.dumps(summ, indent=1))
