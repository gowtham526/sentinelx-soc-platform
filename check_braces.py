with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/settings_screens.dart', 'r', encoding='utf-8') as f:
    text = f.read()

count = 0
for c in text:
    if c == '{': count += 1
    elif c == '}': count -= 1
print('Net braces in settings_screens:', count)
