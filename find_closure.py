with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

count = 0
in_str = False
str_char = ''
escape = False
for i, c in enumerate(text):
    if in_str:
        if escape:
            escape = False
        elif c == '\\':
            escape = True
        elif c == str_char:
            in_str = False
    else:
        if c in '"\'':
            in_str = True
            str_char = c
        elif c == '{':
            count += 1
        elif c == '}':
            count -= 1
            if count == 0 and i > 1000:
                print("Count hit 0 at index", i)
                print("Context around closure:")
                print(text[max(0, i-500):min(len(text), i+500)])
                break
