with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/dump_app.txt', 'w', encoding='utf-8') as f2:
    for i, line in enumerate(lines):
        if '/api/alerts/status' in line:
            for j in range(i, min(len(lines), i+20)):
                f2.write(f'{j+1}: {lines[j]}')
            break
