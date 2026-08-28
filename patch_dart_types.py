import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix string concatenation and casts for dynamic types
content = content.replace(
    "_buildAlertWarningBox('MATCH: ' + _intelResult!['match']!, _intelResult!['color']!),",
    "_buildAlertWarningBox('MATCH: ${_intelResult!['match']}', _intelResult!['color'] as Color),"
)

content = content.replace(
    "_buildDetailRow('Query', _intelResult!['md5']!),",
    "_buildDetailRow('Query', _intelResult!['md5'].toString()),"
)

content = content.replace(
    "_buildDetailRow('Threat Name', _intelResult!['name']!),",
    "_buildDetailRow('Threat Name', _intelResult!['name'].toString()),"
)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(content)
