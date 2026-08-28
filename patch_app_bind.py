import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace(
    '_bind_host = _os.environ.get("BIND_HOST", "127.0.0.1")',
    '_bind_host = _os.environ.get("BIND_HOST", "0.0.0.0")'
)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'w', encoding='utf-8') as f:
    f.write(text)
print('Patched app.py to bind to 0.0.0.0')
