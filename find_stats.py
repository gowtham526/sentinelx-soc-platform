import re
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'r', encoding='utf-8') as f:
    text = f.read()

match = re.search(r'def get_alert_stats\([\s\S]*?(?=def )', text)
if match:
    print(match.group(0).encode('ascii', 'ignore').decode())
else:
    match2 = re.search(r'def get_metrics\([\s\S]*?(?=def )', text)
    if match2:
        print(match2.group(0).encode('ascii', 'ignore').decode())
