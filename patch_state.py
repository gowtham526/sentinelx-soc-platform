import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    content = f.read()

state_vars = """String _currentViewTitle = 'Live Alerts';
  
  // Threat Intel State
  String _intelSearchQuery = '';
  Map<String, dynamic>? _intelResult;
"""

content = content.replace("String _currentViewTitle = 'Live Alerts';", state_vars)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(content)
