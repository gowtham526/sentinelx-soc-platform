import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'r', encoding='utf-8') as f:
    text = f.read()

# I will inject global USERS; USERS = _load_users() right into api_login()
text = text.replace('def api_login():\n    ip = request.remote_addr', 
'''def api_login():
    global USERS
    USERS = _load_users()
    ip = request.remote_addr''')

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'w', encoding='utf-8') as f:
    f.write(text)

print("Injected hot-reload into app.py api_login")
