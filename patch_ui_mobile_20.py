import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    content = f.read()

new_row_20 = """          Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            _buildBox('USERS TRACKED', 'From active alerts', Text(userStats.keys.length.toString(), style: const TextStyle(color: Color(0xFF32ade6), fontSize: 24, fontWeight: FontWeight.bold))),
            const SizedBox(height: 12),
            _buildBox('HIGH RISK', 'CRITICAL activity', Text(highRiskUsers.toString(), style: const TextStyle(color: Color(0xFFFF3B30), fontSize: 24, fontWeight: FontWeight.bold))),
            const SizedBox(height: 12),
            _buildBox('TOTAL ALERTS', 'All users', Text(_alerts.length.toString(), style: const TextStyle(color: Color(0xFF32ade6), fontSize: 24, fontWeight: FontWeight.bold))),
          ]),"""

content = re.sub(r'Row\(children: \[\s*Flexible\(child: _buildBox\(\'USERS TRACKED\'.*?\]\),', new_row_20, content, flags=re.DOTALL)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(content)
