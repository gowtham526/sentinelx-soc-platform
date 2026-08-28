import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/login_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

# Let's add a proper forgot password dialog instead of just a snackbar.
forgot_pw_method = '''
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
'''

text = text.replace('  void _showOtpPrompt(String e, String u, String p) {', forgot_pw_method + '\n  void _showOtpPrompt(String e, String u, String p) {')

text = text.replace('''GestureDetector(
                        onTap: () {
                          ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Password reset link sent to registered email!')));
                        },''',
'''GestureDetector(
                        onTap: _showForgotPasswordPrompt,''')

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/login_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)

print("Added Forgot Password popup")
