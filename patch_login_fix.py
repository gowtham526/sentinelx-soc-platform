import re
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/login_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

# We need to insert after the ElevatedButton inside the Login Button section.
# We can search for the end of the ElevatedButton which is followed by:
#                              ),
#                            ),
#                          ],

pattern = r"(                                      \),\r?\n                              \),\r?\n                            \),)"

replacement = r'''\1
                            
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
                            ),'''

text = re.sub(pattern, replacement, text)

# Now add the helper function if it doesn't exist
if '_buildQuickLoginBtn' not in text:
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

print("Patched login screen")
