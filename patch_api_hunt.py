import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/services/api_service.dart', 'r', encoding='utf-8') as f:
    content = f.read()

hunt_ip_code = """
  static Future<Map<String, dynamic>?> huntIp(String target) async {
    try {
      final response = await http.get(
        Uri.parse('$_baseUrl/api/hunt/ip?ip=$target'),
        headers: {'Authorization': 'Bearer $_authToken'},
      );
      if (response.statusCode == 200) {
         return jsonDecode(response.body);
      }
      return null;
    } catch (e) {
      return null;
    }
  }
"""

if 'huntIp(' not in content:
    content = content.replace("static Future<String?> killProcess", hunt_ip_code + "\n  static Future<String?> killProcess")

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/services/api_service.dart', 'w', encoding='utf-8') as f:
    f.write(content)
