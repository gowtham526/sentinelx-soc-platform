import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/login_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

# Add a boolean state variable
state_injection = '''
class _LoginScreenState extends State<LoginScreen> with SingleTickerProviderStateMixin {
  bool _isCreateAccount = false;
'''
text = text.replace('class _LoginScreenState extends State<LoginScreen> with SingleTickerProviderStateMixin {', state_injection)

# Replace the specific UI elements dynamically based on _isCreateAccount

# 1. Update the Heading
text = text.replace("const Text('SENTINELX', style: TextStyle(color: Colors.white, fontSize: 22, fontWeight: FontWeight.w900, letterSpacing: 2.0)),", 
                    "Text(_isCreateAccount ? 'CREATE ACCOUNT' : 'SENTINELX', style: const TextStyle(color: Colors.white, fontSize: 22, fontWeight: FontWeight.w900, letterSpacing: 2.0)),")

text = text.replace("const Text('ENTERPRISE SOC & THREAT RESPONSE v3.0', style: TextStyle(color: Color(0xFF8b949e), fontSize: 10, fontWeight: FontWeight.bold, letterSpacing: 1.2)),",
                    "Text(_isCreateAccount ? 'INITIALIZE OPERATOR PROFILE' : 'ENTERPRISE SOC & THREAT RESPONSE v3.0', style: const TextStyle(color: Color(0xFF8b949e), fontSize: 10, fontWeight: FontWeight.bold, letterSpacing: 1.2)),")

# 2. Add Email Field if Create Account
# We find the 'USERNAME / OPERATOR ID' label and prepend the Email field if _isCreateAccount is true
email_field = '''
                    if (_isCreateAccount) ...[
                      Align(alignment: Alignment.centerLeft, child: Text('EMAIL ADDRESS', style: TextStyle(color: const Color(0xFF0a84ff).withOpacity(0.8), fontSize: 10, fontWeight: FontWeight.w800, letterSpacing: 1.0))),
                      const SizedBox(height: 8),
                      TextField(
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
'''
text = text.replace("Align(alignment: Alignment.centerLeft, child: Text('USERNAME / OPERATOR ID', style: TextStyle(color: const Color(0xFF0a84ff).withOpacity(0.8), fontSize: 10, fontWeight: FontWeight.w800, letterSpacing: 1.0))),", email_field)

# 3. Update the Button text
text = text.replace("const Text('AUTHENTICATE & ENTER SOC', style: TextStyle(fontSize: 12, fontWeight: FontWeight.w900, letterSpacing: 1.0)),",
                    "Text(_isCreateAccount ? 'SEND VERIFICATION CODE' : 'AUTHENTICATE & ENTER SOC', style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w900, letterSpacing: 1.0)),")

# 4. Add the toggle links below the button
links_replacement = '''
                    const SizedBox(height: 16),
                    // Toggle Mode Links
                    if (!_isCreateAccount) ...[
                      GestureDetector(
                        onTap: () => setState(() => _isCreateAccount = true),
                        child: const Text('Create an account instead', style: TextStyle(color: Color(0xFF0a84ff), fontSize: 11, fontWeight: FontWeight.bold)),
                      ),
                      const SizedBox(height: 8),
                      const Text('Forgot Password?', style: TextStyle(color: Color(0xFFFF3B30), fontSize: 11, fontWeight: FontWeight.bold)),
                    ] else ...[
                      GestureDetector(
                        onTap: () => setState(() => _isCreateAccount = false),
                        child: const Text('Login here', style: TextStyle(color: Color(0xFF0a84ff), fontSize: 11, fontWeight: FontWeight.bold)),
                      ),
                    ],
                    const SizedBox(height: 32),
                    const Divider(color: Color(0xFF1f242d), height: 1),
                    const SizedBox(height: 24),
'''
text = text.replace('''
                    const SizedBox(height: 32),
                    const Divider(color: Color(0xFF1f242d), height: 1),
                    const SizedBox(height: 24),''', links_replacement)


# 5. Hide the quick login section if in create account mode
quick_login_regex = r"const Text\('QUICK DEMO EVALUATOR LOGIN'[\s\S]*?Row\([\s\S]*?\]\r?\n\s*\),"
m = re.search(quick_login_regex, text)
if m:
    wrapped = f"if (!_isCreateAccount) ...[\n                    {m.group(0)}\n                  ],"
    text = text.replace(m.group(0), wrapped)


with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/login_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)

print("Added Create Account flow")
