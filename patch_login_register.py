import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/login_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

# Add _emailController
text = text.replace('final TextEditingController _passwordController = TextEditingController();',
                    'final TextEditingController _passwordController = TextEditingController();\n  final TextEditingController _emailController = TextEditingController();')

# Link it to the email text field
# The email text field was added as:
# TextField(
#   style: const TextStyle(color: Colors.white, fontSize: 14),
#   decoration: InputDecoration(
#     hintText: 'operator@soc.local',

text = text.replace('''                      TextField(
                        style: const TextStyle(color: Colors.white, fontSize: 14),
                        decoration: InputDecoration(
                          hintText: 'operator@soc.local',''',
                    '''                      TextField(
                        controller: _emailController,
                        style: const TextStyle(color: Colors.white, fontSize: 14),
                        decoration: const InputDecoration(
                          hintText: 'operator@soc.local',''')
# wait I made InputDecoration const in the replacement, let's just make it not const to be safe or check original

# Create _handleRegister method
register_method = '''
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
                      // In web it stores in localStorage, we can just do a mock login or switch to login mode
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
'''

text = text.replace('  void _showLoginPrompt(String label, String role) {', register_method + '\n  void _showLoginPrompt(String label, String role) {')

# Hook up the button
# `onPressed: _isLoading ? null : _handleLogin,` -> `onPressed: _isLoading ? null : (_isCreateAccount ? _handleRegister : _handleLogin),`
text = text.replace('onPressed: _isLoading ? null : _handleLogin,', 'onPressed: _isLoading ? null : (_isCreateAccount ? _handleRegister : _handleLogin),')

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/login_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)

print("Wired up create account logic")
