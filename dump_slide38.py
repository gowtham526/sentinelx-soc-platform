import re
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'r', encoding='utf-8') as f:
    text = f.read()

m = re.search(r'<div[^>]*data-slide="38"[^>]*>[\s\S]*?</div>', text)
if m:
    print(m.group(0).encode('ascii', 'ignore').decode())
else:
    print('Not found')
    
    # Just in case, try searching for the word "User Management"
    m2 = re.search(r'<[^>]*>[^<]*User Management[^<]*</[^>]*>', text)
    if m2:
        print("Found via text:", m2.group(0).encode('ascii', 'ignore').decode())

