with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

in_str = False
str_char = ''
escape = False
stack = []
for i, c in enumerate(text):
    if in_str:
        if escape: escape = False
        elif c == '\\': escape = True
        elif c == str_char: in_str = False
    else:
        if c in '"\'':
            in_str = True
            str_char = c
        elif c == '{':
            stack.append(i)
        elif c == '}':
            if stack:
                stack.pop()
            else:
                print("Extra } at index", i)

for index in stack:
    line_no = text[:index].count('\n') + 1
    print("Unmatched { at line", line_no)
    print(text[max(0, index-100):min(len(text), index+100)])
