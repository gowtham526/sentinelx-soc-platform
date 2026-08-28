import re
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx-web/public/spa.html', 'r', encoding='utf-8') as f:
    text = f.read()

m1 = re.search(r'function promptAdminLogin\([\s\S]*?\}', text)
if m1:
    with open('C:/SOC_AUTOMATION_PROJECT_FINAL/dump_prompt_logic.txt', 'w', encoding='utf-8') as out:
        out.write(m1.group(0) + "\n\n")

m2 = re.search(r'function promptAnalystLogin\([\s\S]*?\}', text)
if m2:
    with open('C:/SOC_AUTOMATION_PROJECT_FINAL/dump_prompt_logic.txt', 'a', encoding='utf-8') as out:
        out.write(m2.group(0))
