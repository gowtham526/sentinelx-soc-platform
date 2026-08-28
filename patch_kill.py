import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

protection_code = """
import os
import psutil
try:
    current_proc = psutil.Process(os.getpid())
    protected_pids = {os.getpid()}
    # Protect parents up to 2 levels
    parent = current_proc.parent()
    if parent:
        protected_pids.add(parent.pid)
        if parent.parent():
            protected_pids.add(parent.parent().pid)
except:
    protected_pids = set()

if pid_int in protected_pids:
    return jsonify({"success": False, "error": "Cannot kill SentinelX host process or its terminal!"}), 400
"""

# Insert protection code right after `pid_int = int(pid)`
content = re.sub(r'pid_int = int\(pid\)', f'pid_int = int(pid)\n{protection_code}', content, 1)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'w', encoding='utf-8') as f:
    f.write(content)
