import re
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'r', encoding='utf-8') as f:
    text = f.read()

m = re.search(r'var slides = \[[\s\S]*?\];', text)
if m:
    with open('C:/SOC_AUTOMATION_PROJECT_FINAL/dump_slides.txt', 'w', encoding='utf-8') as out:
        out.write(m.group(0))
    print("Found slides array")
else:
    print("Not found")

m3 = re.search(r'function updateUIRoleVisibility[\s\S]{0,1000}', text)
if m3:
    print("Found updateUIRoleVisibility")
