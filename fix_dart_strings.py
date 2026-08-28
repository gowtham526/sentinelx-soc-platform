import re
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/reporting_screens.dart', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace(r'\$index', '${index}')
text = text.replace(r'\$ev', '${ev}')
text = text.replace(r'\$host', '${host}')
text = text.replace(r'\$sev', '${sev}')
text = text.replace(r'\$idx', '${idx}')
text = text.replace(r'\$_selectedIncidentIndex', '${_selectedIncidentIndex}')
text = text.replace(r'\$latestEv', '${latestEv}')
text = text.replace(r'\$incCount', '${incCount}')
text = text.replace(r'\$total', '${total}')
text = text.replace(r'\$critical', '${critical}')
text = text.replace(r'\$high', '${high}')
text = text.replace(r'\$btnLabel', '${btnLabel}')

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/reporting_screens.dart', 'w', encoding='utf-8') as f:
    f.write(text)
