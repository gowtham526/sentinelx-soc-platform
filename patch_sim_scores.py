import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace(
    '"mitre_tactic": "Credential Access"\n        },',
    '"mitre_tactic": "Credential Access",\n            "vt_score": 12,\n            "abuse_score": 90\n        },'
)

content = content.replace(
    '"mitre_tactic": "Command and Control"\n        },',
    '"mitre_tactic": "Command and Control",\n            "vt_score": 14,\n            "abuse_score": 85\n        },'
)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/app.py', 'w', encoding='utf-8') as f:
    f.write(content)
