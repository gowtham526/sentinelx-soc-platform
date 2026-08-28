import re
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'r', encoding='utf-8') as f:
    text = f.read()

m = re.findall(r'<script.*?>([\s\S]*?)</script>', text)
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/all_js.txt', 'w', encoding='utf-8') as out:
    for i, script in enumerate(m):
        out.write(f"\n\n--- SCRIPT {i} ---\n\n")
        out.write(script)
