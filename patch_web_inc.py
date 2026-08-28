with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'r', encoding='utf-8') as f:
    text = f.read()

# Replace the incident selection logic in INCIDENT_REPORTS
old_inc_sel = "const inc = (_I && _I.length) ? _I[0] : {};"
new_inc_sel = "const inc = (_I && _I.length) ? (_I.find(i=>i.id===window._selectedIncidentId || i.incident_id===window._selectedIncidentId) || _I[0]) : {};"
text = text.replace(old_inc_sel, new_inc_sel)

# Also need to update the generator function
old_gen_ai = """function _generateAiReport(incidentId){
  const btn = document.getElementById('AIR_BTN');"""

new_gen_ai = """function _generateAiReport(incidentId){
  if (window._selectedIncidentId !== incidentId) {
    window._selectedIncidentId = incidentId;
    go('INCIDENT_REPORTS');
    setTimeout(() => _generateAiReport(incidentId), 100);
    return;
  }
  const btn = document.getElementById('AIR_BTN');"""

text = text.replace(old_gen_ai, new_gen_ai)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'w', encoding='utf-8') as f:
    f.write(text)
