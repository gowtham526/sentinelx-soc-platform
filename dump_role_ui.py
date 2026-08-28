import re
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'r', encoding='utf-8') as f:
    text = f.read()

m1 = re.search(r'data-slide="38"[\s\S]{0,300}', text)
if m1: print("Slide 38 HTML:", m1.group(0).encode('utf-8'))

m2 = re.search(r'function updateUIRoleVisibility[\s\S]{0,1000}', text)
if m2: print("Update UI Role:\n", m2.group(0))

m3 = re.search(r'data-slide="39"[\s\S]{0,300}', text)
if m3: print("Slide 39 HTML:", m3.group(0).encode('utf-8'))

m4 = re.search(r'role.*?visibility[\s\S]{0,500}', text, re.IGNORECASE)
if m4: print("Role Visibility:", m4.group(0))
