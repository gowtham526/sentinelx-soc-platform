with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'r', encoding='utf-8') as f:
    lines = f.readlines()
for i, line in enumerate(lines):
    if 'id="login-view"' in line or 'login-box' in line:
        for j in range(i, min(i+60, len(lines))):
            print(lines[j], end='')
        break
