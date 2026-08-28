import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

# 1. Remove the extra } that closes the class prematurely
text = text.replace("    );\n  }\n}\n  bool _isExeAlert", "    );\n  }\n\n  bool _isExeAlert")

# 2. Add the missing } to close the class at the end before CustomPainters
text = text.replace("\nclass GridPainter", "\n}\n\nclass GridPainter")

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)

print("Fixed the structural braces in dashboard_screen.dart!")
