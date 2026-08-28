import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

# Fix DataRow fileN split overflow issue
text = text.replace(
    r"String fileN = (a['detail'] ?? '').toString().split(r'\n')[0];",
    r"String fileN = (a['detail'] ?? '').toString().split('\\n')[0];"
)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)
print('Dashboard UI check.')
