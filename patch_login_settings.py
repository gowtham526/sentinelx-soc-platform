import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/login_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

replacement = '''
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0b0f19),
      body: Stack(
        children: [
          Center(
            child: SingleChildScrollView(
'''

text = text.replace('''  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0b0f19),
      body: Center(
        child: SingleChildScrollView(''', replacement)


replacement2 = '''                  ],
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
  }'''

text = text.replace('''                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }''', replacement2)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/login_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)

print("Added settings button back")
