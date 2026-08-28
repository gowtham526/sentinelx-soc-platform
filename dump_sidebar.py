with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()
start = text.find('Widget _buildMobileDrawer')
end = text.find('Widget _buildSectionHeader')
if start != -1:
    with open('C:/SOC_AUTOMATION_PROJECT_FINAL/out_sidebar.txt', 'w', encoding='utf-8') as out:
        out.write(text[start:end])
