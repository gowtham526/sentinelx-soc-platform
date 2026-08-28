import re
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'r', encoding='utf-8') as f:
    text = f.read()

# The UI uses classes for roles in some places? Or we just need to add a class `admin-only`?
# Let's see how `data-slide="39"` (Admin Command Center) is hidden, if at all.
m = re.search(r'<div class="sidebar-item"[^>]*data-slide="39"[^>]*>[\s\S]*?</div>', text)
if m: print("Slide 39:", m.group(0))

m2 = re.search(r'<div class="sidebar-item"[^>]*data-slide="38"[^>]*>[\s\S]*?</div>', text)
if m2: print("Slide 38:", m2.group(0))
