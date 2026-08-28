import re
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'r', encoding='utf-8') as f:
    text = f.read()

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/login_pages.txt', 'w', encoding='utf-8') as out:
    m1 = re.search(r'id="login-view"[\s\S]{0,1000}', text)
    if m1: out.write("Login View:\n" + m1.group(0) + "\n\n")

    m2 = re.search(r'create(?:\s|-)account[\s\S]{0,1000}', text, re.IGNORECASE)
    if m2: out.write("Create Account:\n" + m2.group(0) + "\n\n")

    m3 = re.search(r'auditor[\s\S]{0,500}', text, re.IGNORECASE)
    if m3: out.write("Auditor:\n" + m3.group(0) + "\n\n")
