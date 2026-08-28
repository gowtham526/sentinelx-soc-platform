with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/alert_detail_screen.dart', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace("alert['details'] ?? alert['description']", "alert['detail'] ?? alert['details'] ?? alert['description']")
content = content.replace("alert['title'] ?? alert['event']", "alert['event'] ?? alert['title']")
content = content.replace("alert['mitre_id']", "alert['mitre'] ?? alert['mitre_id']")

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/alert_detail_screen.dart', 'w', encoding='utf-8') as f:
    f.write(content)
