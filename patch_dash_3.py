import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

# Add import for admin_screens.dart
if "import 'admin_screens.dart';" not in text:
    text = text.replace("import 'settings_screens.dart';", "import 'settings_screens.dart';\nimport 'admin_screens.dart';")

# Re-write the switch cases
cases_to_replace = r"(case '35':.*?)(?=default:|case '[0-9]':|$)"
new_cases = '''case '35': return const RuleEngineScreen();
      case '36': return const CustomDetectionRulesScreen();
      case '37': return const AuditLogScreen();
      case '38': return const UserManagementScreen();
      case '39': return const AdminCommandCenterScreen();
      '''

# But wait, what if '35' is still ExportLogsScreen? Let's fix the sidebar first.
sidebar_replacements = [
    ("case '30': return const SocAutomationPlaybookScreen();", "case '30': return SocAutomationPlaybookScreen(alerts: _alerts);"),
    ("case '31': return SoarPlaybookScreen(alerts: _alerts);", "case '31': return const PlaybookBuilderScreen();"),
    ("case '32': return const PlaybookBuilderScreen();", "case '32': return IncidentReportsScreen(alerts: _alerts);"),
    ("case '33': return IncidentReportsScreen(alerts: _alerts);", "case '33': return ReportGeneratorScreen(alerts: _alerts);"),
    ("case '34': return ReportGeneratorScreen(alerts: _alerts);", "case '34': return ExportLogsScreen(alerts: _alerts);"),
    ("case '35': return ExportLogsScreen(alerts: _alerts);", "case '35': return const RuleEngineScreen();\n      case '36': return const CustomDetectionRulesScreen();\n      case '37': return const AuditLogScreen();\n      case '38': return const UserManagementScreen();\n      case '39': return const AdminCommandCenterScreen();"),
]

for old, new in sidebar_replacements:
    text = text.replace(old, new)

# And remove the duplicate cases I injected earlier (37, 38, 39, 40)
text = re.sub(r'case \'37\': return const RuleEngineScreen\(\);\s*case \'38\': return const CustomDetectionRulesScreen\(\);\s*case \'39\': return const AuditLogScreen\(\);\s*case \'40\': return const UserManagementScreen\(\);\s*', '', text)

# Now fix the sidebar menu items list!
text = re.sub(r'_buildSidebarItem\(\'31\', \'SOC Automation Playbook\'\)', r"_buildSidebarItem('30', 'SOC Automation Playbook')\n              _buildSidebarItem('31', 'Playbook Builder')", text)
text = text.replace("_buildSidebarItem('32', 'Playbook Builder')", "_buildSidebarItem('32', 'Incident Reports')")
text = text.replace("_buildSidebarItem('33', 'Incident Reports')", "_buildSidebarItem('33', 'Report Generator')")
text = text.replace("_buildSidebarItem('34', 'Report Generator')", "_buildSidebarItem('34', 'Export Logs')")
text = text.replace("_buildSidebarItem('35', 'Export Logs')", "_buildSidebarItem('35', 'Rule Engine')")
text = text.replace("_buildSidebarItem('37', 'Rule Engine')", "_buildSidebarItem('36', 'Custom Detection Rules')")
text = text.replace("_buildSidebarItem('38', 'Custom Detection Rules')", "_buildSidebarItem('37', 'Audit Log')")
text = text.replace("_buildSidebarItem('39', 'Audit Log')", "_buildSidebarItem('38', 'User Management')\n              _buildSidebarItem('39', 'Admin Command Center')")
text = text.replace("_buildSidebarItem('40', 'User Management')", "")

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)
print("Dashboard updated")
