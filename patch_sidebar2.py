import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

# Replace the block for 38 and 39 with a conditionally rendered block
old_pattern = r"_buildSidebarItem\('38', 'User Management'\),\s*_buildSectionHeader\('M9 .*?'\),\s*_buildSidebarItem\('39', '.*?'\),"

def replacer(match):
    s = match.group(0)
    # Wrap '38' in an if block
    s = s.replace("_buildSidebarItem('38', 'User Management'),", "if (ApiService.userRole == 'admin') _buildSidebarItem('38', 'User Management'),")
    # Wrap 'M9' in an if block
    s = re.sub(r"_buildSectionHeader\('M9 .*?'\),", lambda m: f"if (ApiService.userRole == 'admin') {m.group(0)}", s)
    # Wrap '39' in an if block
    s = re.sub(r"_buildSidebarItem\('39', '.*?'\),", lambda m: f"if (ApiService.userRole == 'admin') {m.group(0)}", s)
    return s

text = re.sub(old_pattern, replacer, text)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)

print("Sidebar patched successfully.")
