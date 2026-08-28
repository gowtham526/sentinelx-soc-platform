with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()
for j in range(1645, 1660):
    print(f'{j+1}: {lines[j].strip()}')
