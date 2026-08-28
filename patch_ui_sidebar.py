import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace the M4 sidebar items line
old_m4_line = "_buildSidebarItem('14', 'Alert Detail'), _buildSidebarItem('15', 'Parent-Child Analysis'), _buildSidebarItem('16', 'Network Connection Detail'), _buildSidebarItem('17', 'Threat Intelligence & Hash Lookup'), _buildSidebarItem('19', 'Command Line Analysis'), _buildSidebarItem('20', 'User Activity Analysis'), _buildSidebarItem('21', 'Active Containment & Process Killer'), _buildSidebarItem('22', 'Response History'),"
new_m4_line = "_buildSidebarItem('14', 'Alert Detail'), _buildSidebarItem('15', 'Parent-Child Analysis'), _buildSidebarItem('16', 'Network Connection Detail'), _buildSidebarItem('17', 'Threat Intelligence & Hash Lookup'), _buildSidebarItem('20', 'User Activity Analysis'), _buildSidebarItem('21', 'Active Containment & Process Killer'),"

content = content.replace(old_m4_line, new_m4_line)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(content)
