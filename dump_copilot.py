with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/out_copilot.txt', 'w', encoding='utf-8') as out:
    for i, line in enumerate(lines):
        if 'def api_ai_copilot():' in line:
            for j in range(i, min(len(lines), i+60)):
                out.write(f'{j+1}: {lines[j]}')
            break
