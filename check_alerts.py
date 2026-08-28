import json
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/data/alerts.json', 'r', encoding='utf-8') as f:
    alerts = json.load(f)
    for a in reversed(alerts):
        if a.get('event') == 'Mimikatz Credential Dumping Detected' or 'c2' in str(a.get('event', '')).lower():
            print(f"Event: {a.get('event')}, VT: '{a.get('vt_score')}', Abuse: '{a.get('abuse_score')}', type: {type(a.get('vt_score'))}")
