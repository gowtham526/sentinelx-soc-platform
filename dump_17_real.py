import sys
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    lines = f.readlines()
in_17 = False
for i, line in enumerate(lines):
    if "case '17':" in line:
        in_17 = True
    if in_17:
        print(f'{i+1}: {line.strip()}')
    if in_17 and ("case '18':" in line or "case '19':" in line or "case '20':" in line):
        break
