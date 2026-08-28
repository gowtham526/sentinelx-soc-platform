import re
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx-web/public/spa.html', 'r', encoding='utf-8') as f:
    text = f.read()
m = re.search(r'QUICK DEMO EVALUATOR LOGIN[\s\S]{0,1000}', text)
if m:
    with open('C:/SOC_AUTOMATION_PROJECT_FINAL/dump_login.txt', 'w', encoding='utf-8') as out:
        out.write(m.group(0))
