with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'r', encoding='utf-8') as f:
    lines = f.readlines()
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/out_simulate.txt', 'w', encoding='utf-8') as out:
    for i, line in enumerate(lines):
        if 'Simulate C2' in line or 'simulateC2' in line or 'function simulate' in line:
            start = max(0, i-5)
            for j in range(start, i+15):
                out.write(f'{j+1}: {lines[j]}')
            break
