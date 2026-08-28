with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()
for i, line in enumerate(lines):
    if '"mimikatz": {' in line:
        for j in range(i, i+15):
            print(f'{j+1}: {lines[j].strip()}')
        break
