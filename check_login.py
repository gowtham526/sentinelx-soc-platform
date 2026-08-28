import re
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'r', encoding='utf-8') as f:
    text = f.read()
match = re.search(r'@app\.route\("/api/auth/login"[\s\S]*?(?=@app\.route)', text)
if match:
    print(match.group(0))
