import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/services/api_service.dart', 'r', encoding='utf-8') as f:
    content = f.read()

kill_process_code = """
  static Future<String?> killProcess(String target) async {
    try {
      final response = await http.post(
        Uri.parse('$_baseUrl/api/kill_process'),
        headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer $_token'},
        body: jsonEncode({'pid': target, 'name': target}),
      );
      if (response.statusCode == 200) {
         return null; // success
      }
      return 'HTTP ${response.statusCode}: ${response.body}';
    } catch (e) {
      return e.toString();
    }
  }
"""

content = content.replace("class ApiService {", "class ApiService {\n" + kill_process_code)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/services/api_service.dart', 'w', encoding='utf-8') as f:
    f.write(content)
