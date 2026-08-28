import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/login_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

replacement = '''
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
'''

text = text.replace('''
    if (result['success'] == true && mounted) {
      Navigator.of(context).pushReplacement(
        MaterialPageRoute(builder: (_) => const DashboardScreen()),
      );
    } else {
      setState(() {
        _errorMessage = result['error'] ?? 'Authentication failed';
      });
    }
''', replacement)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/login_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)

print("Fixed handleLogin error reporting")
