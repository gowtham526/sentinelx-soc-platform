import re
f=open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', encoding='utf-8')
text = f.read()

for ep in ['/api/rules/custom', '/api/audit_log', '/api/admin/users']:
    m = re.search(f'@app\\.route\\("{ep}"(?:, methods=\\[.*?\\])?\\)\n(?:@require_auth\n)*def [a-zA-Z0-9_]+\\(.*?\\):', text)
    if m:
        start = m.end()
        print('---', ep)
        print(text[start:start+400])
