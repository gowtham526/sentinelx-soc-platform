import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace(
    "_askCopilot('Analyze chrome.exe network connection to 104.21.43.1');",
    "_showCopilotSheet();"
)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)
print("Fixed _askCopilot to _showCopilotSheet().")
