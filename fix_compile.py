import re

# Fix api_service.dart
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/services/api_service.dart', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace("debugPrint('Error sending OTP:", "print('Error sending OTP:")
text = text.replace("debugPrint('Error verifying OTP:", "print('Error verifying OTP:")

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/services/api_service.dart', 'w', encoding='utf-8') as f:
    f.write(text)

# Fix login_screen.dart
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/login_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

# Fix const InputDecoration
text = text.replace('const InputDecoration(\n                          hintText: \'operator@soc.local\',',
                    'InputDecoration(\n                          hintText: \'operator@soc.local\',')

# Fix _emailController
if '_emailController' not in text.split('Widget build')[0]:
    # Inject it right after _passwordController
    m = re.search(r'TextEditingController _passwordController[^;]*;', text)
    if m:
        text = text[:m.end()] + '\n  final TextEditingController _emailController = TextEditingController();' + text[m.end():]
    else:
        # Just inject at the top of the class
        m2 = re.search(r'class _LoginScreenState extends State<LoginScreen>.*?\{', text, re.DOTALL)
        if m2:
            text = text[:m2.end()] + '\n  final TextEditingController _emailController = TextEditingController();' + text[m2.end():]

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/login_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)

print("Fixed compile errors")
