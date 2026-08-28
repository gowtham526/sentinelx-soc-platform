import re
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/settings_screens.dart', 'r', encoding='utf-8') as f:
    text = f.read()

start = text.find('class _UserManagementScreenState')
end = text.find('class _AppLogsScreenState')
if end == -1: end = len(text)
print(text[start:end])
