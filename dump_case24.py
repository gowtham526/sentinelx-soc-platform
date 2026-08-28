import re
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

old_24 = re.search(r"case '24':.*?(?=          _buildBox\('Active Classification Rules Matrix')", text, re.DOTALL)
if old_24:
    print(old_24.group(0).encode('utf-8'))
