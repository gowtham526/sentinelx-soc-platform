with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/services/api_service.dart', 'r', encoding='utf-8') as f:
    text = f.read()

# Change default URL to the actual PC IP
text = text.replace(
    "static String _baseUrl = 'http://10.0.2.2:5000';",
    "static String _baseUrl = 'http://10.124.241.52:5000';"
)
text = text.replace(
    "_baseUrl = prefs.getString('server_url') ?? 'http://10.0.2.2:5000';",
    "_baseUrl = prefs.getString('server_url') ?? 'http://10.124.241.52:5000';"
)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/services/api_service.dart', 'w', encoding='utf-8') as f:
    f.write(text)
print('Default URL updated to 10.124.241.52:5000')
