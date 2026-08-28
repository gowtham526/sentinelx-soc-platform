with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

imports = """import 'advanced_soc_screens.dart';
import 'advanced_soc_playbook_screens.dart';
"""
text = text.replace("import 'alert_detail_screen.dart';", "import 'alert_detail_screen.dart';\n" + imports)

cases = """
      case '27': return AlertCorrelationScreen(alerts: _alerts, incidents: _incidents);
      case '28': return ThreatHuntingScreen(alerts: _alerts);
      case '29': return IocDashboardScreen(alerts: _alerts);
      case '31': return const SoarPlaybookScreen();
      case '32': return const PlaybookBuilderScreen();
"""
text = text.replace("default: return const Center(child: Text('Data Loading...'));", cases + "      default: return const Center(child: Text('Data Loading...'));")

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)
