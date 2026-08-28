import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'r', encoding='utf-8') as f:
    text = f.read()

old_func = """def _get_current_user() -> str | None:
    \"\"\"Extract and verify bearer token from the current request.
    Checks Authorization header first, then falls back to httponly cookie.
    Query-string tokens are intentionally NOT accepted  they leak into
    server logs, browser history, and Referer headers.\"\"\"
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        u = _verify_token(auth[7:])
        if u: return u
    cookie_token = request.cookies.get("sx_token", "")
    if cookie_token:
        u = _verify_token(cookie_token)
        if u: return u
    return None"""

new_func = """def _get_current_user() -> str | None:
    \"\"\"Extract and verify bearer token from the current request.
    Checks Authorization header first, then falls back to httponly cookie.
    Also accepts query-string token for mobile app URL launcher compatibility.\"\"\"
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        u = _verify_token(auth[7:])
        if u: return u
    cookie_token = request.cookies.get("sx_token", "")
    if cookie_token:
        u = _verify_token(cookie_token)
        if u: return u
    query_token = request.args.get("token", "")
    if query_token:
        u = _verify_token(query_token)
        if u: return u
    return None"""

# Note: the old_func might have unicode character  for the mdash.
# Let's just do a regex replacement.

match = re.search(r'def _get_current_user\(\) -> str \| None:.*?return None', text, re.DOTALL)
if match:
    text = text[:match.start()] + new_func + text[match.end():]
    with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'w', encoding='utf-8') as f:
        f.write(text)
    print("Patched app.py")
else:
    print("Could not find _get_current_user")
