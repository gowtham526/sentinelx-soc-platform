import re
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'r', encoding='utf-8') as f:
    text = f.read()
match = re.search(r'@app\.route\("/api/users/<username>/reset_password"[\s\S]*?(?=@app\.route)', text)
if match: print(match.group(0))

match2 = re.search(r'@app\.route\("/api/users/<username>/role"[\s\S]*?(?=@app\.route)', text)
if match2: print(match2.group(0))

match3 = re.search(r'@app\.route\("/api/admin/delete_user"[\s\S]*?(?=@app\.route)', text)
if match3: print(match3.group(0))

