with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    content = f.read()

helper = """
  Widget _buildDetailRow(String label, String value, {Color valColor = Colors.white}) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Expanded(flex: 1, child: Text(label, style: const TextStyle(color: Color(0xFF8b949e), fontSize: 10))),
        Expanded(flex: 2, child: Text(value, style: TextStyle(color: valColor, fontSize: 10, fontFamily: 'monospace'))),
      ]),
    );
  }
"""
if "_buildDetailRow(String label" not in content[:content.find("case '14'")]:
    content = content.replace("Widget _buildBox(String title, String subtitle, Widget child) {", helper.strip() + "\n\n  Widget _buildBox(String title, String subtitle, Widget child) {")

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(content)
