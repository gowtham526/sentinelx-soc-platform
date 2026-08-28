import re
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'r', encoding='utf-8') as f:
    text = f.read()

m = re.search(r'function renderSidebar[\s\S]{0,1000}', text)
if m:
    with open('C:/SOC_AUTOMATION_PROJECT_FINAL/dump_sidebar.txt', 'w', encoding='utf-8') as out:
        out.write(m.group(0))

m2 = re.search(r'function initSidebar[\s\S]{0,1000}', text)
if m2:
    with open('C:/SOC_AUTOMATION_PROJECT_FINAL/dump_sidebar2.txt', 'w', encoding='utf-8') as out:
        out.write(m2.group(0))
