with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'r', encoding='utf-8') as f:
    text = f.read()

start = text.find('function _generateAiReport')
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/dump5.txt', 'w', encoding='utf-8') as f:
    f.write(text[start:start+1000])
