with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'r', encoding='utf-8') as f:
    text = f.read()
start = text.find('Incident Reports')
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/dump2.txt', 'w', encoding='utf-8') as f:
    f.write(text[start:start+2000])
