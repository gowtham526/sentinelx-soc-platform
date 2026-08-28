with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    lines = f.readlines()

in_17 = False
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/dump_17.txt', 'w', encoding='utf-8') as f2:
    for i, line in enumerate(lines):
        if "case '17':" in line:
            in_17 = True
        if in_17:
            f2.write(f'{i+1}: {line}')
            if "case '18':" in line or "case '19':" in line:
                break
