import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/services/api_service.dart', 'r', encoding='utf-8') as f:
    text = f.read()

new_methods = '''
  static Future<bool> sendOtp(String email) async {
    try {
      final res = await http.post(
        Uri.parse('$_baseUrl/api/auth/send_otp'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'email': email})
      );
      if (res.statusCode == 200) {
        return jsonDecode(res.body)['success'] ?? false;
      }
    } catch (e) {
      debugPrint('Error sending OTP: $e');
    }
    return false;
  }

  static Future<bool> verifyOtp(String email, String otp) async {
    try {
      final res = await http.post(
        Uri.parse('$_baseUrl/api/auth/verify_otp'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'email': email, 'otp': otp})
      );
      if (res.statusCode == 200) {
        return jsonDecode(res.body)['success'] ?? false;
      }
    } catch (e) {
      debugPrint('Error verifying OTP: $e');
    }
    return false;
  }
'''

# insert right before the last closing brace
text = text.rstrip()
if text.endswith('}'):
    text = text[:-1] + new_methods + '}\n'
    with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/services/api_service.dart', 'w', encoding='utf-8') as f:
        f.write(text)
    print("Added sendOtp and verifyOtp")
