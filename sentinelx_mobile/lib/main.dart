import 'package:flutter/material.dart';
import 'services/api_service.dart';
import 'screens/login_screen.dart';
import 'screens/dashboard_screen.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  try {
    await ApiService.init();
  } catch (e) {
    debugPrint('Init Error: $e');
  }
  runApp(const SentinelXApp());
}

class SentinelXApp extends StatelessWidget {
  const SentinelXApp({super.key});

  @override
  Widget build(BuildContext context) {
    final isLoggedIn = ApiService.authToken != null;

    return MaterialApp(
      title: 'SentinelX SOC Platform',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        brightness: Brightness.dark,
        scaffoldBackgroundColor: const Color(0xFF030712),
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFF00F0FF),
          secondary: Color(0xFF00FF9D),
          surface: Color(0xFF0A1424),
          tertiary: Color(0xFFA855F7),
        ),
        cardColor: const Color(0xFF0A1424),
      ),
      home: const LoginScreen(),
    );
  }
}
