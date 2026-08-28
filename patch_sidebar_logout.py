import re
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

# Add a logout item to the bottom of the sidebar
replacement = '''
                  if (ApiService.userRole == 'admin') _buildSidebarItem('39', 's Admin Command Center'),
                  const Divider(color: Color(0xFF1f242d), height: 32),
                  ListTile(
                    leading: const Icon(Icons.logout, color: Colors.redAccent, size: 20),
                    title: const Text('Log Out', style: TextStyle(color: Colors.redAccent, fontSize: 13, fontWeight: FontWeight.bold)),
                    onTap: () => _handleLogout(),
                  ),
'''

text = re.sub(r"if \(ApiService.userRole == 'admin'\) _buildSidebarItem\('39', '.*?'\),", replacement, text)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)

print("Added logout to sidebar")
