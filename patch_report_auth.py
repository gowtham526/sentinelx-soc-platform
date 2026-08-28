import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'r', encoding='utf-8') as f:
    text = f.read()

# Remove @require_auth from all /api/report/ routes to allow mobile browser downloads
text = re.sub(r'(@app\.route\("/api/report/(?:markdown|csv|json|compliance)"\))\n@require_auth', r'\1', text)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'w', encoding='utf-8') as f:
    f.write(text)
print("Removed @require_auth from export routes.")
