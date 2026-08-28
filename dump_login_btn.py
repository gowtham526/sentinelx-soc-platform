import re
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/login_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()
m = re.search(r'// Login Button[\s\S]*?(?=// Server settings button)', text)
if m:
    with open('C:/SOC_AUTOMATION_PROJECT_FINAL/login_btn_dump.txt', 'w', encoding='utf-8') as out:
        out.write(m.group(0))
