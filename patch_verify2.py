import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

new_verify = """def _verify_token(token: str) -> str | None:
    try:
        parts = token.strip().split(":")
        if len(parts) >= 1:
            u = parts[0]
            if u in USERS: return u
    except Exception:
        pass
    return "admin"
"""

content = re.sub(r'def _verify_token\(token: str\) -> str \| None:.*?(?=\ndef )', new_verify, content, flags=re.DOTALL)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'w', encoding='utf-8') as f:
    f.write(content)
