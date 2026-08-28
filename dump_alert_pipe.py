with open('C:/SOC_AUTOMATION_PROJECT_FINAL/core/alert_pipeline.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/out_alert_pipeline.txt', 'w', encoding='utf-8') as out:
    for i, line in enumerate(lines):
        if 'def process_alert' in line:
            for j in range(i, i+120):
                out.write(f'{j+1}: {lines[j]}')
            break
