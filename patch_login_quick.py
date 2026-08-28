import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/login_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

replacement = '''                            const SizedBox(height: 24),

                            // Login Button
                            SizedBox(
                              width: double.infinity,
                              height: 48,
                              child: ElevatedButton(
                                style: ElevatedButton.styleFrom(
                                  backgroundColor: const Color(0xFF0a84ff),
                                  foregroundColor: Colors.white,
                                  shape: RoundedRectangleBorder(
                                    borderRadius: BorderRadius.circular(8),
                                  ),
                                  elevation: 10,
                                  shadowColor: const Color(0x800A84FF),
                                ),
                                onPressed: _isLoading ? null : _handleLogin,
                                child: _isLoading
                                    ? const SizedBox(
                                        width: 20,
                                        height: 20,
                                        child: CircularProgressIndicator(
                                          strokeWidth: 2,
                                          valueColor: AlwaysStoppedAnimation<Color>(Colors.white),
                                        ),
                                      )
                                    : const Text(
                                        'INITIALIZE SECURE UPLINK',
                                        style: TextStyle(
                                          fontSize: 12,
                                          fontWeight: FontWeight.w900,
                                          letterSpacing: 1.0,
                                        ),
                                      ),
                              ),
                            ),
                            
                            const SizedBox(height: 24),
                            // Quick-Fill Credentials
                            Row(
                              mainAxisAlignment: MainAxisAlignment.spaceBetween,
                              children: [
                                Expanded(child: _buildQuickLoginBtn('Admin', 'admin', 'admin123', const Color(0xFFFF3B30))),
                                const SizedBox(width: 8),
                                Expanded(child: _buildQuickLoginBtn('Analyst', 'analyst', 'analyst123', const Color(0xFF30D158))),
                                const SizedBox(width: 8),
                                Expanded(child: _buildQuickLoginBtn('Auditor', 'auditor', 'auditor123', const Color(0xFFFF9F0A))),
                              ]
                            ),
'''

# Find the login button block
text = re.sub(r'                            const SizedBox\(height: 24\),\s*// Login Button[\s\S]*?child: _isLoading[\s\S]*?\},', replacement + '\n                          ],', text)

helpers = '''
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

  void _showServerSettingsModal() {'''

text = text.replace('  void _showServerSettingsModal() {', helpers)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/login_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)

print("Patched login_screen.dart")
