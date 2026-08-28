import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

# Replace missing positional arguments
text = text.replace("_pinpointIp('IN India')", "_pinpointIp('IN India', 'Location:')")
text = text.replace("_pinpointIp('RU Russia')", "_pinpointIp('RU Russia', 'Location:')")
text = text.replace("_pinpointIp('US USA')", "_pinpointIp('US USA', 'Location:')")
text = text.replace("_pinpointIp('DE Germany')", "_pinpointIp('DE Germany', 'Location:')")

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)

print("Patched preset buttons in dashboard_screen.dart")
