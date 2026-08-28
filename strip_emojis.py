import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace any print statement with an ascii-only version
# But we can just use regex to strip all unicode characters from print arguments.
def remove_unicode_from_print(match):
    full_print = match.group(0)
    # keep only ascii chars
    ascii_only = "".join(c for c in full_print if ord(c) < 128)
    return ascii_only

content = re.sub(r'print\(f?[\'\"].*?[\'\"]\)', remove_unicode_from_print, content, flags=re.DOTALL)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'w', encoding='utf-8') as f:
    f.write(content)
