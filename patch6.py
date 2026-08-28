import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace(
    "Expanded(child: ListView.builder(",
    "ListView.builder(shrinkWrap: true, physics: const NeverScrollableScrollPhysics(),"
)
content = content.replace(
    "}\n          ))\n        ]));",
    "}\n          )\n        ]));"
)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(content)
