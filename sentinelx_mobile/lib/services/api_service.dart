import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

class ApiService {
  
  


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

  static Future<String?> killProcess(String target) async {
    try {
      final response = await http.post(
        Uri.parse('$_baseUrl/api/kill_process'),
        headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer $_authToken'},
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

  static String _baseUrl = 'http://10.124.241.52:5000'; // Default Android emulator host localhost
  static String? _authToken;
  static String? _currentUser;
  static String? _userRole;

  static String get baseUrl => _baseUrl;
  static String? get authToken => _authToken;
  static String? get currentUser => _currentUser;
  static String? get userRole => _userRole;

  static Future<void> init() async {
    final prefs = await SharedPreferences.getInstance();
    _baseUrl = prefs.getString('server_url') ?? 'http://10.124.241.52:5000';
    _authToken = prefs.getString('auth_token');
    _currentUser = prefs.getString('current_user');
    _userRole = prefs.getString('user_role');
  }

  static Future<void> setServerUrl(String url) async {
    String formatted = url.trim();
    if (!formatted.startsWith('http://') && !formatted.startsWith('https://')) {
      formatted = 'http://$formatted';
    }
    if (formatted.endsWith('/')) {
      formatted = formatted.substring(0, formatted.length - 1);
    }
    _baseUrl = formatted;
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('server_url', _baseUrl);
  }


  

  static Future<bool> register(String username, String password) async {
    final url = Uri.parse('$_baseUrl/api/auth/register');
    try {
      final response = await http.post(
        url,
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'username': username, 'password': password}),
      ).timeout(const Duration(seconds: 8));
      
      final data = jsonDecode(response.body);
      return response.statusCode == 200 && data['success'] == true;
    } catch (e) {
      print('Registration error: $e');
      return false;
    }
  }

  static Future<Map<String, dynamic>> login(String username, String password) async {
    final url = Uri.parse('$_baseUrl/api/auth/login');
    try {
      final response = await http.post(
        url,
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'username': username, 'password': password}),
      ).timeout(const Duration(seconds: 8));

      final data = jsonDecode(response.body);
      if (response.statusCode == 200 && data['success'] == true) {
        _authToken = data['token'];
        _currentUser = data['user'];
        _userRole = data['role'];

        final prefs = await SharedPreferences.getInstance();
        await prefs.setString('auth_token', _authToken!);
        await prefs.setString('current_user', _currentUser!);
        await prefs.setString('user_role', _userRole!);
        return {'success': true, 'role': _userRole};
      }
      return {'success': false, 'error': data['error'] ?? 'Invalid credentials'};
    } catch (e) {
      return {'success': false, 'error': 'Connection error: $e'};
    }
  }

  static Future<void> logout() async {
    _authToken = null;
    _currentUser = null;
    _userRole = null;
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('auth_token');
    await prefs.remove('current_user');
    await prefs.remove('user_role');
  }

  static Map<String, String> get _headers => {
    'Content-Type': 'application/json',
    if (_authToken != null) 'Authorization': 'Bearer $_authToken',
  };


  static Future<List<dynamic>> fetchEventsStream() async {
    final url = Uri.parse('$_baseUrl/api/events/stream');
    try {
      final res = await http.get(url, headers: _headers).timeout(const Duration(seconds: 8));
      if (res.statusCode == 200) {
        final data = jsonDecode(res.body);
        if (data['success'] == true) {
            return data['events'] as List<dynamic>;
        }
      }
    } catch (_) {}
    return [];
  }

  static Future<List<dynamic>> fetchAlerts() async {
    final url = Uri.parse('$_baseUrl/api/alerts');
    try {
      final res = await http.get(url, headers: _headers).timeout(const Duration(seconds: 8));
      if (res.statusCode == 200) {
        return jsonDecode(res.body) as List<dynamic>;
      } else {
        return [];
      }
    } catch (e) {
        return [];
    }
  }

  static Future<Map<String, dynamic>> fetchFrameworksStatus() async {
    final url = Uri.parse('$_baseUrl/api/frameworks/status');
    try {
      final res = await http.get(url, headers: _headers).timeout(const Duration(seconds: 8));
      if (res.statusCode == 200) {
        return jsonDecode(res.body) as Map<String, dynamic>;
      }
    } catch (_) {}
    return {};
  }

  static Future<String?> updateAlertStatus(String alertId, String newStatus) async {
    final url = Uri.parse('$_baseUrl/api/alerts/status');
    try {
      final res = await http.post(
        url,
        headers: _headers,
        body: jsonEncode({'alert_id': alertId, 'status': newStatus}),
      );
      if (res.statusCode == 200) return null;
      return 'HTTP ${res.statusCode}: ${res.body}';
    } catch (e) {
      return 'Exception: $e';
    }
  }

  static Future<bool> simulateAttack(String scenario) async {
    final url = Uri.parse('$_baseUrl/api/simulate_attack');
    try {
      final res = await http.post(
        url,
        headers: _headers,
        body: jsonEncode({'scenario': scenario, 'host': 'SOC-ENDPOINT-01', 'user': 'analyst_demo'})
      );
      return res.statusCode == 200;
    } catch (_) {
      return false;
    }
  }

  static Future<String> askCopilot(String query) async {
    final url = Uri.parse('$_baseUrl/api/ai_copilot');
    try {
      final res = await http.post(
        url,
        headers: _headers,
        body: jsonEncode({'query': query})
      );
      if (res.statusCode == 200) {
        final data = jsonDecode(res.body);
        if (data['success'] == true) {
            return data['reply'] ?? 'Empty response from AI.';
        }
      }
      return 'Error: AI Copilot returned HTTP ${res.statusCode}';
    } catch (e) {
      return 'Error connecting to AI Copilot: $e';
    }
  }

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
      print('Error sending OTP: $e');
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
      print('Error verifying OTP: $e');
    }
    return false;
  }
}
