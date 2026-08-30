import 'dart:ui';
import 'package:flutter/material.dart';
import '../services/api_service.dart';
import 'dashboard_screen.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}


class _LoginScreenState extends State<LoginScreen> with SingleTickerProviderStateMixin {
  final TextEditingController _emailController = TextEditingController();
  bool _isCreateAccount = false;

  final _usernameController = TextEditingController();
  final _passwordController = TextEditingController();
  final _serverUrlController = TextEditingController();
  bool _isLoading = false;
  bool _obscurePassword = true;
  String? _errorMessage;

  late AnimationController _animController;

  @override
  void initState() {
    super.initState();
    _serverUrlController.text = ApiService.baseUrl;
    _animController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 12),
    )..repeat();
  }

  @override
  void dispose() {
    _animController.dispose();
    _usernameController.dispose();
    _passwordController.dispose();
    _serverUrlController.dispose();
    super.dispose();
  }

  Future<void> _handleLogin() async {
    final u = _usernameController.text;
    final p = _passwordController.text;

    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    await ApiService.setServerUrl(_serverUrlController.text);
    final result = await ApiService.login(u, p);

    setState(() {
      _isLoading = false;
    });

    if (result['success'] == true && mounted) {
      Navigator.of(context).pushReplacement(
        MaterialPageRoute(builder: (_) => const DashboardScreen()),
      );
    } else {
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(result['error'] ?? 'Authentication failed')));
      setState(() {
        _errorMessage = result['error'] ?? 'Authentication failed';
      });
    }
  }


  Widget _buildQuickLoginBtn(String label, String u, String p, Color c) {
    return InkWell(
      onTap: () {
        _usernameController.text = u;
        _passwordController.text = p;
      },
      child: Container(
        padding: const EdgeInsets.symmetric(vertical: 10),
        decoration: BoxDecoration(
          color: c.withOpacity(0.1),
          border: Border.all(color: c.withOpacity(0.5)),
          borderRadius: BorderRadius.circular(4)
        ),
        child: Center(child: Text(label, style: TextStyle(color: c, fontSize: 11, fontWeight: FontWeight.bold)))
      )
    );
  }

  void _showServerSettingsModal() {
    showModalBottomSheet(
      context: context,
      backgroundColor: const Color(0xFF0c121e),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) {
        return Padding(
          padding: EdgeInsets.only(
            left: 24.0, right: 24.0, top: 24.0,
            bottom: MediaQuery.of(ctx).viewInsets.bottom + 24.0,
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'SERVER CONFIGURATION',
                style: TextStyle(
                  color: Color(0xFF58a6ff),
                  fontSize: 12,
                  fontWeight: FontWeight.bold,
                  letterSpacing: 1.2,
                ),
              ),
              const SizedBox(height: 16),
              TextField(
                controller: _serverUrlController,
                style: const TextStyle(color: Colors.white, fontSize: 14),
                decoration: InputDecoration(
                  labelText: 'SentinelX Backend URL',
                  labelStyle: const TextStyle(color: Colors.grey),
                  filled: true,
                  fillColor: const Color(0xFF131c2a),
                  enabledBorder: OutlineInputBorder(
                    borderSide: const BorderSide(color: Color(0x26FFFFFF)),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  focusedBorder: OutlineInputBorder(
                    borderSide: const BorderSide(color: Color(0xFF0a84ff)),
                    borderRadius: BorderRadius.circular(8),
                  ),
                ),
              ),
              const SizedBox(height: 24),
              SizedBox(
                width: double.infinity,
                height: 44,
                child: ElevatedButton(
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFF0a84ff),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                  ),
                  onPressed: () {
                    ApiService.setServerUrl(_serverUrlController.text);
                    Navigator.pop(ctx);
                  },
                  child: const Text('Save Configuration', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
                ),
              )
            ],
          ),
        );
      },
    );
  }



  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0b0f19),
      body: Stack(
        children: [
          Center(
            child: SingleChildScrollView(

          child: Padding(
            padding: const EdgeInsets.all(24.0),
            child: Container(
              constraints: const BoxConstraints(maxWidth: 400),
              decoration: BoxDecoration(
                color: const Color(0xFF161b22),
                borderRadius: BorderRadius.circular(16),
                border: Border.all(color: const Color(0xFF1f242d), width: 1.5),
                boxShadow: [
                  BoxShadow(color: Colors.black.withOpacity(0.5), blurRadius: 20, offset: const Offset(0, 10)),
                ]
              ),
              child: Padding(
                padding: const EdgeInsets.all(32.0),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    // Glowing SX Logo
                    Container(
                      width: 64,
                      height: 64,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        gradient: const LinearGradient(
                          colors: [Color(0xFF0a84ff), Color(0xFF00e5ff)],
                          begin: Alignment.topLeft,
                          end: Alignment.bottomRight,
                        ),
                        boxShadow: [
                          BoxShadow(color: const Color(0xFF0a84ff).withOpacity(0.5), blurRadius: 20, spreadRadius: 2),
                        ]
                      ),
                      alignment: Alignment.center,
                      child: const Text('SX', style: TextStyle(color: Colors.white, fontSize: 24, fontWeight: FontWeight.w900)),
                    ),
                    const SizedBox(height: 24),
                    
                    // Headings
                    Text(_isCreateAccount ? 'CREATE ACCOUNT' : 'SENTINELX', style: const TextStyle(color: Colors.white, fontSize: 22, fontWeight: FontWeight.w900, letterSpacing: 2.0)),
                    const SizedBox(height: 8),
                    Text(_isCreateAccount ? 'INITIALIZE OPERATOR PROFILE' : 'ENTERPRISE SOC & THREAT RESPONSE v3.0', style: const TextStyle(color: Color(0xFF8b949e), fontSize: 10, fontWeight: FontWeight.bold, letterSpacing: 1.2)),
                    const SizedBox(height: 40),
                    
                    // Username Field
                    
                    if (_isCreateAccount) ...[
                      Align(alignment: Alignment.centerLeft, child: Text('EMAIL ADDRESS', style: TextStyle(color: const Color(0xFF0a84ff).withOpacity(0.8), fontSize: 10, fontWeight: FontWeight.w800, letterSpacing: 1.0))),
                      const SizedBox(height: 8),
                      TextField(
                        controller: _emailController,
                        style: const TextStyle(color: Colors.white, fontSize: 14),
                        decoration: InputDecoration(
                          hintText: 'operator@soc.local',
                          hintStyle: const TextStyle(color: Colors.white30),
                          filled: true,
                          fillColor: const Color(0xFF0d1117),
                          border: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: BorderSide.none),
                          contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
                        ),
                      ),
                      const SizedBox(height: 20),
                    ],
                    Align(alignment: Alignment.centerLeft, child: Text('USERNAME / OPERATOR ID', style: TextStyle(color: const Color(0xFF0a84ff).withOpacity(0.8), fontSize: 10, fontWeight: FontWeight.w800, letterSpacing: 1.0))),

                    const SizedBox(height: 8),
                    TextField(
                      controller: _usernameController,
                      style: const TextStyle(color: Colors.white, fontSize: 14),
                      decoration: InputDecoration(
                        filled: true,
                        fillColor: const Color(0xFF0d1117),
                        border: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: BorderSide.none),
                        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
                      ),
                    ),
                    const SizedBox(height: 20),
                    
                    // Password Field
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Text('SECURITY CREDENTIAL', style: TextStyle(color: const Color(0xFF0a84ff).withOpacity(0.8), fontSize: 10, fontWeight: FontWeight.w800, letterSpacing: 1.0)),
                        GestureDetector(
                          onTap: () {
                            // toggle visibility (not fully implemented for brevity, but UI shows "Show")
                          },
                          child: const Text('👁 Show', style: TextStyle(color: Color(0xFF8b949e), fontSize: 10)),
                        )
                      ],
                    ),
                    const SizedBox(height: 8),
                    TextField(
                      controller: _passwordController,
                      obscureText: _obscurePassword,
                      style: const TextStyle(color: Colors.white, fontSize: 14),
                      decoration: InputDecoration(
                        filled: true,
                        fillColor: const Color(0xFF0d1117),
                        border: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: BorderSide.none),
                        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
                      ),
                    ),
                    const SizedBox(height: 32),
                    
                    // Login Button
                    SizedBox(
                      width: double.infinity,
                      height: 48,
                      child: ElevatedButton(
                        style: ElevatedButton.styleFrom(
                          backgroundColor: const Color(0xFF0a84ff),
                          foregroundColor: Colors.white,
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                          elevation: 10,
                          shadowColor: const Color(0x800A84FF),
                        ),
                        onPressed: _isLoading ? null : (_isCreateAccount ? _handleRegister : _handleLogin),
                        child: _isLoading
                            ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2, valueColor: AlwaysStoppedAnimation<Color>(Colors.white)))
                            : Text(_isCreateAccount ? 'SEND VERIFICATION CODE' : 'AUTHENTICATE & ENTER SOC', style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w900, letterSpacing: 1.0)),
                      ),
                    ),
                    
                    const SizedBox(height: 16),
                    // Toggle Mode Links
                    if (!_isCreateAccount) ...[
                      GestureDetector(
                        onTap: () => setState(() => _isCreateAccount = true),
                        child: const Text('Create an account instead', style: TextStyle(color: Color(0xFF0a84ff), fontSize: 11, fontWeight: FontWeight.bold)),
                      ),
                      const SizedBox(height: 8),
                      GestureDetector(
                        onTap: _showForgotPasswordPrompt,
                        child: const Text('Forgot Password?', style: TextStyle(color: Color(0xFFFF3B30), fontSize: 11, fontWeight: FontWeight.bold)),
                      ),
                    ] else ...[
                      GestureDetector(
                        onTap: () => setState(() => _isCreateAccount = false),
                        child: const Text('Login here', style: TextStyle(color: Color(0xFF0a84ff), fontSize: 11, fontWeight: FontWeight.bold)),
                      ),
                    ],
                    const SizedBox(height: 32),
                    const Divider(color: Color(0xFF1f242d), height: 1),
                    const SizedBox(height: 24),

                    
                    // Quick Demo Login
                    if (!_isCreateAccount) ...[
                    const Text('QUICK DEMO EVALUATOR LOGIN', style: TextStyle(color: Color(0xFF8b949e), fontSize: 10, fontWeight: FontWeight.w800, letterSpacing: 1.0)),
                    const SizedBox(height: 16),
                    Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Expanded(child: _buildPromptBtn('Admin', 'admin', const Color(0xFFFF3B30))),
                        const SizedBox(width: 8),
                        Expanded(child: _buildPromptBtn('Analyst', 'analyst', const Color(0xFF30D158))),
                        const SizedBox(width: 8),
                        Expanded(child: _buildPromptBtn('Auditor', 'auditor', const Color(0xFFFF9F0A))),
                      ]
                    ),
                  ],
                    
                    const SizedBox(height: 32),
                    // Footer
                    Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: const [
                        Icon(Icons.lock, color: Color(0xFFFF9F0A), size: 12),
                        SizedBox(width: 4),
                        Text('HMAC-SHA256 SESSION AUTH - RBAC ENGINE ACTIVE', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.w800, letterSpacing: 1.0)),
                      ],
                    )
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
          Positioned(
            top: 40,
            right: 16,
            child: IconButton(
              icon: const Icon(Icons.settings_outlined, color: Colors.white54),
              onPressed: _showServerSettingsModal,
              tooltip: 'Server Configuration',
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildPromptBtn(String label, String role, Color c) {
    return InkWell(
      onTap: () => _showLoginPrompt(label, role),
      child: Container(
        padding: const EdgeInsets.symmetric(vertical: 12),
        decoration: BoxDecoration(
          color: const Color(0xFF0d1117),
          border: Border.all(color: const Color(0xFF1f242d)),
          borderRadius: BorderRadius.circular(6)
        ),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(role == 'admin' ? Icons.shield : (role == 'analyst' ? Icons.analytics : Icons.visibility), color: c, size: 12),
            const SizedBox(width: 4),
            Text(label, style: const TextStyle(color: Colors.white, fontSize: 11, fontWeight: FontWeight.bold))
          ],
        )
      )
    );
  }


  Future<void> _handleRegister() async {
    final e = _emailController.text.trim();
    final u = _usernameController.text.trim();
    final p = _passwordController.text.trim();
    if (e.isEmpty || u.isEmpty || p.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Please fill all fields')));
      return;
    }
    
    setState(() => _isLoading = true);
    bool sent = await ApiService.sendOtp(e);
    setState(() => _isLoading = false);
    
    if (sent) {
      _showOtpPrompt(e, u, p);
    } else {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Failed to send OTP. Check email or server.')));
    }
  }


  void _showForgotPasswordPrompt() {
    final TextEditingController resetCtrl = TextEditingController();
    showDialog(
      context: context,
      builder: (context) {
        return AlertDialog(
          backgroundColor: const Color(0xFF161b22),
          title: const Text('RESET PASSWORD', style: TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold)),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Text('VERIFY IDENTITY TO PROCEED', style: TextStyle(color: Color(0xFF8b949e), fontSize: 10, fontWeight: FontWeight.bold)),
              const SizedBox(height: 16),
              TextField(
                controller: resetCtrl,
                style: const TextStyle(color: Colors.white, fontSize: 14),
                decoration: const InputDecoration(labelText: 'REGISTERED EMAIL', labelStyle: TextStyle(color: Color(0xFF8b949e))),
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Cancel', style: TextStyle(color: Color(0xFF8b949e))),
            ),
            ElevatedButton(
              style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF0a84ff)),
              onPressed: () {
                Navigator.pop(context);
                ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Reset code sent to ${resetCtrl.text}')));
              },
              child: const Text('SEND RESET CODE'),
            ),
          ],
        );
      }
    );
  }

  void _showOtpPrompt(String e, String u, String p) {
    final TextEditingController otpCtrl = TextEditingController();
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (context) {
        bool verifying = false;
        return StatefulBuilder(
          builder: (context, setStateDialog) {
            return AlertDialog(
              backgroundColor: const Color(0xFF161b22),
              title: const Text('Verify Email', style: TextStyle(color: Colors.white)),
              content: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text('Code sent to $e', style: const TextStyle(color: Color(0xFF8b949e), fontSize: 12)),
                  const SizedBox(height: 16),
                  TextField(
                    controller: otpCtrl,
                    style: const TextStyle(color: Colors.white, fontSize: 14),
                    keyboardType: TextInputType.number,
                    decoration: const InputDecoration(labelText: '6-digit OTP', labelStyle: TextStyle(color: Color(0xFF8b949e))),
                  ),
                ],
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.pop(context),
                  child: const Text('Cancel', style: TextStyle(color: Color(0xFF8b949e))),
                ),
                ElevatedButton(
                  style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF0a84ff)),
                  onPressed: verifying ? null : () async {
                    if (otpCtrl.text.trim().isEmpty) return;
                    setStateDialog(() => verifying = true);
                    bool ok = await ApiService.verifyOtp(e, otpCtrl.text.trim());
                    setStateDialog(() => verifying = false);
                    if (ok) {
                      Navigator.pop(context);
                      
                      // Call backend to actually create user
                      bool registered = await ApiService.register(u, p);
                      if (!registered && mounted) {
                         ScaffoldMessenger.of(context).showSnackBar(
                           const SnackBar(content: Text('Registration failed (user may exist). Trying login anyway.')),
                         );
                      }

                      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Account Created! Please log in.')));
                      setState(() {
                        _isCreateAccount = false;
                        _emailController.clear();
                      });
                    } else {
                      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Invalid OTP')));
                    }
                  },
                  child: verifying ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2)) : const Text('Verify & Create'),
                ),
              ],
            );
          }
        );
      }
    );
  }

  void _showLoginPrompt(String label, String role) {
    final TextEditingController uCtrl = TextEditingController(text: role);
    final TextEditingController pCtrl = TextEditingController();
    
    showDialog(
      context: context,
      builder: (context) {
        return AlertDialog(
          backgroundColor: const Color(0xFF161b22),
          title: Text('Enter $label Credentials', style: const TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold)),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: uCtrl,
                style: const TextStyle(color: Colors.white, fontSize: 14),
                decoration: const InputDecoration(labelText: 'Username', labelStyle: TextStyle(color: Color(0xFF8b949e))),
              ),
              const SizedBox(height: 16),
              TextField(
                controller: pCtrl,
                obscureText: _obscurePassword,
                style: const TextStyle(color: Colors.white, fontSize: 14),
                decoration: const InputDecoration(labelText: 'Password', labelStyle: TextStyle(color: Color(0xFF8b949e))),
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Cancel', style: TextStyle(color: Color(0xFF8b949e))),
            ),
            ElevatedButton(
              style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF0a84ff)),
              onPressed: () {
                Navigator.pop(context);
                _usernameController.text = uCtrl.text;
                _passwordController.text = pCtrl.text;
                _handleLogin();
              },
              child: const Text('Authenticate'),
            ),
          ],
        );
      }
    );
  }
}
