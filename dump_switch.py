with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    lines = f.readlines()
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/out_switch.txt', 'w', encoding='utf-8') as out:
    for i, line in enumerate(lines):
        if 'default: return const Center(child: Text(\'Data Loading...\'));' in line:
            start = max(0, i-10)
            for j in range(start, i+5):
                out.write(f'{j+1}: {lines[j]}')
            break
