with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'r', encoding='utf-8') as f:
    text = f.read()

start = text.find('Current Incident')
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/dump4.txt', 'w', encoding='utf-8') as f:
    f.write(text[start+3000:start+4000])
