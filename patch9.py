with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    content = f.read()

helper = """
  Future<void> _updateAlert(String id, String status, String label) async {
    bool success = await ApiService.updateAlertStatus(id, status);
    if (success) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Marked as $label'), backgroundColor: const Color(0xFF10B981)));
      _loadDashboardData();
    } else {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Failed to update alert'), backgroundColor: Color(0xFFF43F5E)));
    }
  }
"""

if '_updateAlert(String id' not in content:
    content = content.replace('Widget _buildDetailRow', helper.strip() + '\n\n  Widget _buildDetailRow')


import re
# Use regex to replace the old buttons to prevent whitespace mismatch
old_actions_regex = re.compile(
    r"_buildBox\('Response Actions', 'SOAR Playbooks', Wrap\(spacing: 8, runSpacing: 8, children: \[.*?\]\)\)",
    re.DOTALL
)

new_actions = """_buildBox('Response Actions', 'SOAR Playbooks', Wrap(spacing: 8, runSpacing: 8, children: [
                ElevatedButton(onPressed: () => _updateAlert((sel['id'] ?? sel['alert_id'] ?? '').toString(), 'INVESTIGATING', 'Investigating'), style: ElevatedButton.styleFrom(backgroundColor: Colors.white, foregroundColor: Colors.black), child: const Text('Mark Investigating', style: TextStyle(fontWeight: FontWeight.bold))),
                ElevatedButton(onPressed: () => _updateAlert((sel['id'] ?? sel['alert_id'] ?? '').toString(), 'RESOLVED', 'Resolved'), style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), side: const BorderSide(color: Color(0xFF30d158)), foregroundColor: const Color(0xFF30d158)), child: const Text('Mark Resolved')),
                ElevatedButton(onPressed: () => _updateAlert((sel['id'] ?? sel['alert_id'] ?? '').toString(), 'FALSE_POSITIVE', 'False Positive'), style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), side: const BorderSide(color: Color(0xFF8b949e)), foregroundColor: const Color(0xFF8b949e)), child: const Text('False Positive')),
              ]))"""

content = old_actions_regex.sub(new_actions, content)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(content)
