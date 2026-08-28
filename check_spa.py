with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'r', encoding='utf-8') as f:
    lines = f.readlines()
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/out_spa.txt', 'w', encoding='utf-8') as out:
    for i, line in enumerate(lines):
        if '14/72' in line or 'Check Score' in line:
            start = max(0, i-5)
            for j in range(start, i+5):
                out.write(f'{j}: {lines[j]}')
            out.write('=====================================\n')
