import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace the failing print statement with a safe ascii print
old_print = 'print(f"\\n\\u270f\\ufe0f  ALERT {target_id} status \\u2192 {new_status}")'
new_print = 'print(f"\\n[*] ALERT {target_id} status -> {new_status}")'

if old_print in content:
    content = content.replace(old_print, new_print)
else:
    # Use regex if exact match fails
    content = re.sub(r'print\(f"\\n.*?ALERT \{target_id\} status.*?\{new_status\}"\)', new_print, content)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'w', encoding='utf-8') as f:
    f.write(content)
