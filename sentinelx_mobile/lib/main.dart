import 'package:flutter/material.dart';
import 'services/api_service.dart';
import 'screens/login_screen.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const SentinelXApp());
}

class SentinelXApp extends StatefulWidget {
  const SentinelXApp({super.key});

  @override
  State<SentinelXApp> createState() => _SentinelXAppState();
}

class _SentinelXAppState extends State<SentinelXApp> {
  @override
  void initState() {
    super.initState();
    // Non-blocking initialization of SharedPreferences
    ApiService.init().catchError((e) {
      debugPrint('ApiService init error: $e');
    });
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'SentinelX SOC Platform',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        brightness: Brightness.dark,
        scaffoldBackgroundColor: const Color(0xFF0b0f19),
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFF00F0FF),
          secondary: Color(0xFF00FF9D),
          surface: Color(0xFF161b22),
          tertiary: Color(0xFFA855F7),
        ),
        cardColor: const Color(0xFF161b22),
      ),
      home: const LoginScreen(),
    );
  }
}
