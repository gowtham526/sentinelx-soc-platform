with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    lines = f.readlines()
for i, line in enumerate(lines):
    if "case '9':" in line:
        for j in range(i, min(len(lines), i+10)):
            print(f'{j+1}: {lines[j].rstrip()}')
        break
