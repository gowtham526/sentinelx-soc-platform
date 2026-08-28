import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'r', encoding='utf-8') as f:
    text = f.read()

# Find the end of the EXPORT slide and the start of the RULE_ENGINE slide
match_export = re.search(r'id:\'EXPORT\'.*?\}\},', text, re.DOTALL)
match_rule = re.search(r'\{id:\'RULE_ENGINE\'', text)

if match_export and match_rule:
    end_of_export = match_export.end()
    start_of_rule = match_rule.start()
    
    # Replace the dangling compliance code with just a newline
    new_text = text[:end_of_export] + '\n' + text[start_of_rule:]
    
    # Also fix the INCIDENT_REPORTS typo I introduced
    new_text = new_text.replace("go('INCIDENT_REPORTS');", "go('INCIDENT_REPORT');")
    
    with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'w', encoding='utf-8') as f:
        f.write(new_text)
    print("SUCCESS")
else:
    print("COULD NOT FIND BOUNDARIES")
