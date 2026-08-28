with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace("_buildSidebarItem('26', 'Attack Chain Visualization'), ", '')
text = text.replace("_buildSidebarItem('30', 'Endpoint Summary'), ", '')

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)
