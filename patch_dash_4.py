import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

# Fix line 460 missing comma
text = text.replace(
    "_buildSidebarItem('30', 'SOC Automation Playbook')\n              _buildSidebarItem('31', 'Playbook Builder')",
    "_buildSidebarItem('30', 'SOC Automation Playbook'),\n              _buildSidebarItem('31', 'Playbook Builder')"
)

# Fix line 465 missing comma and 466 double comma
text = text.replace(
    "_buildSidebarItem('38', 'User Management')\n              _buildSidebarItem('39', 'Admin Command Center'), ,",
    "_buildSidebarItem('38', 'User Management'),\n              _buildSidebarItem('39', 'Admin Command Center'),"
)
# Just in case the trailing comma is something else
text = text.replace(
    "_buildSidebarItem('38', 'User Management')\n              _buildSidebarItem('39', 'Admin Command Center'),",
    "_buildSidebarItem('38', 'User Management'),\n              _buildSidebarItem('39', 'Admin Command Center'),"
)

# Wait, let's just do a targeted regex replace for the section since it's a bit messed up.
# Looking at the original:
# _buildSidebarItem('30', 'SOC Automation Playbook')
# _buildSidebarItem('31', 'Playbook Builder')
text = re.sub(
    r"_buildSidebarItem\('30', 'SOC Automation Playbook'\)\s*_buildSidebarItem\('31', 'Playbook Builder'\)",
    r"_buildSidebarItem('30', 'SOC Automation Playbook'), _buildSidebarItem('31', 'Playbook Builder')",
    text
)

text = re.sub(
    r"_buildSidebarItem\('38', 'User Management'\)\s*_buildSidebarItem\('39', 'Admin Command Center'\)(, ,|,)",
    r"_buildSidebarItem('38', 'User Management'), _buildSidebarItem('39', 'Admin Command Center'),",
    text
)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)
print("Syntax fixed")
