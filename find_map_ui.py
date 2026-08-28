with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    lines = f.readlines()
for i, line in enumerate(lines):
    if "case '8': return Padding(" in line:
        start = i + 48
        end = i + 90
        print(''.join(lines[start:end]))
        break
