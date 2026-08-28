import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

fix = """import sys
try:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
except:
    pass
"""

if "sys.stdout.reconfigure" not in content:
    # insert at the top after imports
    content = fix + "\n" + content
    
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'w', encoding='utf-8') as f:
    f.write(content)
