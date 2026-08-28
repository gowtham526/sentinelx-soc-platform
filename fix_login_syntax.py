import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/login_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

# I will find the Positioned block and insert the missing closures right before it.
replacement = '''                  ],
                ),
              ),
            ),
          ),
        ),
      ),
          Positioned('''

text = text.replace('''                  ],
                ),
              ),
            ),
          ),
          Positioned(''', replacement)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/login_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)

print("Fixed syntax")
