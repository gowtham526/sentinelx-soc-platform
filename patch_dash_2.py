import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace("import 'reporting_screens.dart';", "import 'reporting_screens.dart';\nimport 'settings_screens.dart';")

new_cases = '''
      case '37': return const RuleEngineScreen();
      case '38': return const CustomDetectionRulesScreen();
      case '39': return const AuditLogScreen();
      case '40': return const UserManagementScreen();
'''

text = text.replace("case '35': return ExportLogsScreen(alerts: _alerts);", "case '35': return ExportLogsScreen(alerts: _alerts);\n" + new_cases)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)
print("Patched successfully!")
