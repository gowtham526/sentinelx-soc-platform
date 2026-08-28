import re
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'r', encoding='utf-8') as f:
    text = f.read()

m = re.search(r'<div[^>]*data-slide="39"[^>]*>[\s\S]*?</div>', text)
if m: print("Slide 39:", m.group(0).encode('utf-8'))

m2 = re.search(r'<div[^>]*data-slide="38"[^>]*>[\s\S]*?</div>', text)
if m2: print("Slide 38:", m2.group(0).encode('utf-8'))
