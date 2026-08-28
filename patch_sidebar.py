import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

replacement = '''
                  _buildSectionHeader('M8 ?" SETTINGS'),
                  _buildSidebarItem('35', 'Rule Engine'),
                  _buildSidebarItem('36', 'Custom Detection Rules'),
                  _buildSidebarItem('37', 'Audit Log'),
                  if (ApiService.userRole == 'admin') _buildSidebarItem('38', 'User Management'),
                  if (ApiService.userRole == 'admin') _buildSectionHeader('M9 ?" ADMIN COMMAND'),
                  if (ApiService.userRole == 'admin') _buildSidebarItem('39', 's Admin Command Center'),
'''

# We need to be careful with the unicode strings, let's just use replace on exact strings, but python might choke.
# It's better to use regex to find the end of the sidebar items.
