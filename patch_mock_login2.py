import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/services/api_service.dart', 'r', encoding='utf-8') as f:
    text = f.read()

login_injection = '''
  static Future<Map<String, dynamic>> login(String username, String password) async {
    // Check mock credentials first
    if (mockRegisteredUser != null && mockRegisteredPass != null) {
      if (username == mockRegisteredUser && password == mockRegisteredPass) {
        _currentUser = username;
        _userRole = 'analyst';
        final token = 'mock-token-for-$username';
        _authToken = token;
        
        final prefs = await SharedPreferences.getInstance();
        await prefs.setString('auth_token', token);
        await prefs.setString('current_user', username);
        await prefs.setString('user_role', 'analyst');
        return {'success': true};
      }
    }
'''

text = text.replace('  static Future<Map<String, dynamic>> login(String username, String password) async {', login_injection)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/services/api_service.dart', 'w', encoding='utf-8') as f:
    f.write(text)

print("Properly mocked login!")
