import re
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'r', encoding='utf-8') as f:
    text = f.read()

m = re.search(r'function \w+\(.*?\).*?sidebar-item.*?;', text, re.DOTALL | re.IGNORECASE)
if m:
    with open('C:/SOC_AUTOMATION_PROJECT_FINAL/dump_render.txt', 'w', encoding='utf-8') as out:
        out.write(m.group(0)[:2000])

m2 = re.search(r'sidebar.innerHTML.*?=', text, re.IGNORECASE)
if m2:
    start = max(0, m2.start() - 200)
    end = min(len(text), m2.end() + 1000)
    with open('C:/SOC_AUTOMATION_PROJECT_FINAL/dump_render2.txt', 'w', encoding='utf-8') as out:
        out.write(text[start:end])
