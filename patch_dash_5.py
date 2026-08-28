import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

# 1. Fix the Sidebar
sidebar_start = text.find("_buildSectionHeader('M4")
sidebar_end = text.find("],\n              ),\n            ),", sidebar_start)

if sidebar_start != -1 and sidebar_end != -1:
    correct_sidebar = """_buildSectionHeader('M4 — INVESTIGATION'),
                  _buildSidebarItem('14', 'Alert Detail'),
                  _buildSidebarItem('15', 'Parent-Child Process Analysis'),
                  _buildSidebarItem('16', 'Network Connection Analysis'),
                  _buildSidebarItem('17', 'Threat Intelligence'),
                  _buildSidebarItem('18', 'Registry Persistence Investigation'),
                  _buildSidebarItem('19', 'Command Line Analysis'),
                  _buildSidebarItem('20', 'User Behavior Analysis'),
                  _buildSidebarItem('21', 'Containment & Neutralization'),
                  _buildSidebarItem('22', 'Response Action History'),
                  _buildSectionHeader('M5 — AI ENGINE'),
                  _buildSidebarItem('23', 'AI Threat Analysis'),
                  _buildSidebarItem('24', 'Threat Classification'),
                  _buildSidebarItem('25', 'Threat Intelligence Framework'),
                  _buildSectionHeader('M6 — ADVANCED SOC'),
                  _buildSidebarItem('26', 'Alert Correlation'),
                  _buildSidebarItem('27', 'Threat Hunting'),
                  _buildSidebarItem('28', 'IOC Dashboard'),
                  _buildSidebarItem('29', 'Endpoint Summary'),
                  _buildSidebarItem('30', 'SOC Automation Playbook'),
                  _buildSidebarItem('31', 'Playbook Builder'),
                  _buildSectionHeader('M7 — REPORTING'),
                  _buildSidebarItem('32', 'Incident Reports'),
                  _buildSidebarItem('33', 'Report Generator'),
                  _buildSidebarItem('34', 'Export Logs'),
                  _buildSectionHeader('M8 — SETTINGS'),
                  _buildSidebarItem('35', 'Rule Engine'),
                  _buildSidebarItem('36', 'Custom Detection Rules'),
                  _buildSidebarItem('37', 'Audit Log'),
                  _buildSidebarItem('38', 'User Management'),
                  _buildSectionHeader('M9 — ADMIN COMMAND'),
                  _buildSidebarItem('39', '⚡ Admin Command Center'),
"""
    text = text[:sidebar_start] + correct_sidebar + text[sidebar_end:]

# 2. Fix the Switch cases
text = text.replace("case '27': return AlertCorrelationScreen", "case '26': return AlertCorrelationScreen")
text = text.replace("case '28': return ThreatHuntingScreen", "case '27': return ThreatHuntingScreen")
text = text.replace("case '29': return IocDashboardScreen", "case '28': return IocDashboardScreen")

# Add case 30
if "case '30':" not in text:
    text = text.replace("case '31': return const PlaybookBuilderScreen();", "case '30': return SoarPlaybookScreen(alerts: _alerts);\n      case '31': return const PlaybookBuilderScreen();")

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)
print("Applied perfect 1-39 numbering and cleaned up duplicates!")
