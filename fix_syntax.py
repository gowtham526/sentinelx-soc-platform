with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

bad_str = 'print(f"\n[*] ALERT {target_id} status -> {new_status}")'
good_str = 'print(f"\\n[*] ALERT {target_id} status -> {new_status}")'

content = content.replace(bad_str, good_str)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'w', encoding='utf-8') as f:
    f.write(content)
