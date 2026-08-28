with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()
import re
match = re.search(r'User Management[\s\S]{0,1000}', text, re.IGNORECASE)
if match:
    with open('C:/SOC_AUTOMATION_PROJECT_FINAL/user_mgmt.txt', 'w', encoding='utf-8') as out:
        out.write(match.group(0))
    print('Found')
else:
    print('Not found')
