import re
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'r', encoding='utf-8') as f:
    text = f.read()
routes = re.findall(r'@app\.route\("(/api/[^"]+)"', text)
for r in routes:
    if 'user' in r or 'pass' in r or 'auth' in r:
        print(r)
