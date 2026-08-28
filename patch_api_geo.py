import re
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/services/api_service.dart', 'r', encoding='utf-8') as f:
    text = f.read()

new_method = '''
  static Future<Map<String, dynamic>?> fetchGeo(String ip) async {
    final url = Uri.parse('$_baseUrl/api/geo?ip=$ip');
    try {
      final res = await http.get(url, headers: _headers).timeout(const Duration(seconds: 4));
      if (res.statusCode == 200) {
        return jsonDecode(res.body);
      }
    } catch (_) {}
    return null;
  }
}'''

if 'fetchGeo(' not in text:
    text = re.sub(r'\}\s*$', new_method, text)
    with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/services/api_service.dart', 'w', encoding='utf-8') as f:
        f.write(text)
    print("Added fetchGeo")
else:
    print("Already exists")
