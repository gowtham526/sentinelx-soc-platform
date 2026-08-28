import re
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'r', encoding='utf-8') as f:
    text = f.read()

match = re.search(r'id="slide-7"[\s\S]*?(?=id="slide-8")', text)
if match:
    print(match.group(0)[:1500].encode('ascii', 'ignore').decode())
else:
    print("Slide 7 not found")
