import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/services/api_service.dart', 'r', encoding='utf-8') as f:
    text = f.read()

new_fetch_alerts = """static Future<List<dynamic>> fetchAlerts() async {
    final url = Uri.parse('$_baseUrl/api/alerts');
    try {
      final res = await http.get(url, headers: _headers).timeout(const Duration(seconds: 8));
      if (res.statusCode == 200) {
        return jsonDecode(res.body) as List<dynamic>;
      } else {
        return [{'event': 'API Error ${res.statusCode}', 'host': 'res: ${res.body}', 'severity': 'CRITICAL', 'timestamp': 'now', 'id': 'DEBUG-1', 'mitre': 'Error'}];
      }
    } catch (e) {
        return [{'event': 'Network Exception', 'host': 'error: $e', 'severity': 'CRITICAL', 'timestamp': 'now', 'id': 'DEBUG-2', 'mitre': 'Error'}];
    }
  }"""

text = re.sub(r'static Future<List<dynamic>> fetchAlerts\(\) async \{[\s\S]*?return \[\];\n  \}', new_fetch_alerts, text)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/services/api_service.dart', 'w', encoding='utf-8') as f:
    f.write(text)
print("api_service.dart patched.")
