import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'r', encoding='utf-8') as f:
    text = f.read()

# The exact ending of the EXPORT slide is:
#  )}`,
# },

# And the start of RULE_ENGINE is:
# {id:'RULE_ENGINE'

# Let's find exactly those boundaries
export_match = re.search(r'id:\'EXPORT\'.*?\n\},\n', text, re.DOTALL)
rule_match = re.search(r'\{id:\'RULE_ENGINE\'', text)

if export_match and rule_match:
    end_of_export = export_match.end()
    start_of_rule = rule_match.start()
    
    # Replace the dangling compliance code with just a newline
    new_text = text[:end_of_export] + '\n' + text[start_of_rule:]
    
    with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'w', encoding='utf-8') as f:
        f.write(new_text)
    print("SUCCESS")
else:
    print("COULD NOT FIND BOUNDARIES")
