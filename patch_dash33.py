with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace("import 'advanced_soc_playbook_screens.dart';", "import 'advanced_soc_playbook_screens.dart';\nimport 'reporting_screens.dart';")

cases = """
      case '33': return IncidentReportsScreen(alerts: _alerts);
      case '34': return ReportGeneratorScreen(alerts: _alerts);
      case '35': return ExportLogsScreen(alerts: _alerts);
"""
text = text.replace("      default: return const Center(child: Text('Data Loading...'));", cases + "      default: return const Center(child: Text('Data Loading...'));")

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)
