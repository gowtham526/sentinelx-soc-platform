import re
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'r', encoding='utf-8') as f:
    text = f.read()

m = re.search(r'User Management.{0,300}', text, re.IGNORECASE | re.DOTALL)
if m:
    with open('C:/SOC_AUTOMATION_PROJECT_FINAL/dump_user.txt', 'w', encoding='utf-8') as out:
        out.write(m.group(0))
