with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'r', encoding='utf-8') as f:
    text = f.read()

start = text.find('INCIDENT_REPORTS')
end = text.find('AUDIT_LOG')
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/dump_between.txt', 'w', encoding='utf-8') as f:
    f.write(text[start:end])
