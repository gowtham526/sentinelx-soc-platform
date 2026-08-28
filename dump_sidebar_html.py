import re
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'r', encoding='utf-8') as f:
    text = f.read()
m = re.search(r'M8[\s\S]*?M9', text, re.IGNORECASE)
if m:
    with open('C:/SOC_AUTOMATION_PROJECT_FINAL/dump_sidebar.txt', 'w', encoding='utf-8') as out:
        out.write(m.group(0))
