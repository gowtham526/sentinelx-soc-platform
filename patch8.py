import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Fix _buildBox Title overflow
old_title_row = """Text(title, style: const TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.bold)),"""
new_title_row = """Expanded(child: Text(title, style: const TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.bold), maxLines: 2, overflow: TextOverflow.ellipsis)),"""
content = content.replace(old_title_row, new_title_row)

# 2. Fix Titles in Case 14
content = content.replace("'Alert Information (Tap to expand)'", "'Alert Information'")
content = content.replace("'Threat Intelligence (Tap to expand)'", "'Threat Intelligence'")

# 3. Fix Response Actions Row -> Wrap in Case 14
old_actions = """_buildBox('Response Actions', 'SOAR Playbooks', Row(children: ["""
new_actions = """_buildBox('Response Actions', 'SOAR Playbooks', Wrap(spacing: 8, runSpacing: 8, children: ["""
content = content.replace(old_actions, new_actions)

# 4. Fix Threat Intel static data in Case 14
old_intel = """_buildDetailRow('MITRE ID', (sel['mitre'] ?? sel['mitre_id'] ?? 'T1059.001').toString()),
                    _buildDetailRow('Tactic', (sel['tactic'] ?? sel['mitre_tactic'] ?? 'Execution').toString()),
                    _buildDetailRow('Technique', (sel['technique'] ?? '-').toString()),
                    _buildDetailRow('VT Score', '0/72', valColor: const Color(0xFF30d158)),
                    _buildDetailRow('AbuseIPDB', '0%', valColor: const Color(0xFF30d158)),
                    _buildDetailRow('IP', (sel['ip'] ?? '-').toString()),"""
new_intel = """_buildDetailRow('MITRE ID', (sel['mitre'] ?? sel['mitre_id'] ?? '-').toString()),
                    _buildDetailRow('Tactic', (sel['tactic'] ?? sel['mitre_tactic'] ?? '-').toString()),
                    _buildDetailRow('Technique', (sel['technique'] ?? '-').toString()),
                    _buildDetailRow('VT Score', (sel['vt_score'] ?? '0/72').toString(), valColor: const Color(0xFF30d158)),
                    _buildDetailRow('AbuseIPDB', (sel['abuse_ipdb'] ?? '0%').toString(), valColor: const Color(0xFF30d158)),
                    _buildDetailRow('IP', (sel['ip'] ?? '-').toString()),"""
content = content.replace(old_intel, new_intel)

# 5. Fix Threat Intel button in Case 16
old_threat_btn = """ElevatedButton(onPressed: (){ ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Threat Intel queried'))); }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), side: const BorderSide(color: Color(0xFF32ade6)), foregroundColor: const Color(0xFF32ade6)), child: const Text('Threat Intel')),"""
new_threat_btn = """ElevatedButton(onPressed: (){ setState(() => _currentViewId = '17'); }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), side: const BorderSide(color: Color(0xFF32ade6)), foregroundColor: const Color(0xFF32ade6)), child: const Text('Threat Intel')),"""
content = content.replace(old_threat_btn, new_threat_btn)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(content)
