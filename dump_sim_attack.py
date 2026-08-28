with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/out_simulate_attack.txt', 'w', encoding='utf-8') as out:
    for i, line in enumerate(lines):
        if 'def api_simulate_attack():' in line:
            for j in range(max(0, i-5), min(len(lines), i+80)):
                out.write(f'{j+1}: {lines[j]}')
            break
