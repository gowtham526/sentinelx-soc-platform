import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix Case 14
# Replace `Expanded(child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [`
# with `Container(height: 600, child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [`
content = content.replace(
    "Expanded(child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [\n            Expanded(flex: 1, child: Container(",
    "Container(height: 600, child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [\n            Expanded(flex: 1, child: Container("
)

# Fix Case 15
# Replace `Expanded(child: _buildBox('Anomalous Chains Detected'`
content = content.replace(
    "Expanded(child: _buildBox('Anomalous Chains Detected', 'EID 1 — click View to open full alert detail', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(",
    "_buildBox('Anomalous Chains Detected', 'EID 1 — click View to open full alert detail', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable("
)
# Case 15 closing parentheses: change `))))` to `)))`
# But be careful, we need to locate it exactly.
# Let's just use regex or exact string replacement for the end of case 15.
# The end of case 15 looks like: `])))),\n              ]);\n            }).toList(),\n          ))))\n        ]));`
# Actually, the DataTable ends with `).toList(),\n          ))))\n        ]));`
content = content.replace(
    ").toList(),\n          ))))\n        ]));",
    ").toList(),\n          )))\n        ]));"
)

# Fix Case 16
# Replace `Expanded(child: _buildBox('All Network Alerts'`
content = content.replace(
    "Expanded(child: _buildBox('All Network Alerts', 'Live from _alerts', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(",
    "_buildBox('All Network Alerts', 'Live from _alerts', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable("
)
# Case 16 closing parentheses: change `))))` to `)))`
# The end of case 16 looks like: `).toList(),\n          ))))\n        ]));`
# Same replacement! So the previous replace might have done both if we use replace without count, but let's be sure.

# Fix Case 17
# Replace `Expanded(child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [\n            Expanded(child: _buildBox('Live File IoCs & Hashes'`
content = content.replace(
    "Expanded(child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [\n            Expanded(child: _buildBox('Live File IoCs & Hashes'",
    "Row(crossAxisAlignment: CrossAxisAlignment.start, children: [\n            Expanded(child: _buildBox('Live File IoCs & Hashes'"
)
# Case 17 closing parentheses
content = content.replace(
    "_buildDetailRow('Threat Name', 'Trojan.Meterpreter.Agent'),\n            ])))\n          ]))\n        ]));",
    "_buildDetailRow('Threat Name', 'Trojan.Meterpreter.Agent'),\n            ])))\n          ])\n        ]));"
)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(content)
