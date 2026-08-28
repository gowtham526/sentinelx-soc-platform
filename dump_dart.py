with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    lines = f.readlines()
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/out_dart.txt', 'w', encoding='utf-8') as out:
    for i in range(1500, min(1570, len(lines))):
        out.write(f'{i+1}: {lines[i]}')
