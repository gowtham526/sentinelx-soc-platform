with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/services/api_service.dart', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace("http://127.0.0.1:5000", "http://10.0.2.2:5000")

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/services/api_service.dart', 'w', encoding='utf-8') as f:
    f.write(content)
