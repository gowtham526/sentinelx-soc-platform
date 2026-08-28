import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Import AlertDetailScreen
if "import 'alert_detail_screen.dart';" not in content:
    content = "import 'alert_detail_screen.dart';\n" + content

# 2. Fix _buildDetailRow pixel overflow
old_detail_row = """Expanded(flex: 2, child: Text(value, style: TextStyle(color: valColor, fontSize: 10, fontFamily: 'monospace'))),"""
new_detail_row = """Expanded(flex: 2, child: Text(value, style: TextStyle(color: valColor, fontSize: 10, fontFamily: 'monospace'), maxLines: 4, overflow: TextOverflow.ellipsis)),"""
content = content.replace(old_detail_row, new_detail_row)

# 3. Rewrite case 14
# We need to extract the entire case '14' block and replace it.
# The block starts at `case '14':` and ends before `case '15':`
case14_regex = re.compile(r"case '14':.*?case '15':", re.DOTALL)

new_case14 = """case '14':
        if (_alerts.isEmpty) return const Center(child: Text('No alerts active.', style: TextStyle(color: Colors.white)));
        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          _buildAlertWarningBox('SELECT AN ALERT TO VIEW FULL DETAILS AND THREAT INTELLIGENCE', const Color(0xFF32ade6)),
          const SizedBox(height: 12),
          Expanded(child: ListView.builder(
            itemCount: _alerts.length,
            itemBuilder: (ctx, i) {
              final a = _alerts[i];
              String s = (a['severity'] ?? 'LOW').toString().toUpperCase();
              Color sc = s == 'CRITICAL' ? const Color(0xFFFF3B30) : (s == 'HIGH' ? Colors.orange : (s == 'MEDIUM' ? Colors.amber : const Color(0xFF32ade6)));
              return Card(
                color: const Color(0xFF161b22),
                margin: const EdgeInsets.only(bottom: 8),
                shape: RoundedRectangleBorder(side: BorderSide(color: sc.withOpacity(0.5)), borderRadius: BorderRadius.circular(4)),
                child: ListTile(
                  title: Text((a['event'] ?? 'Alert').toString(), style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 12)),
                  subtitle: Text('${a['host'] ?? '-'}  |  ${(a['timestamp'] ?? '').toString()}', style: const TextStyle(color: Color(0xFF8b949e), fontSize: 10)),
                  trailing: Container(padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4), decoration: BoxDecoration(color: sc.withOpacity(0.15), borderRadius: BorderRadius.circular(4)), child: Text(s, style: TextStyle(color: sc, fontSize: 10, fontWeight: FontWeight.bold))),
                  onTap: () {
                    Navigator.push(context, MaterialPageRoute(builder: (_) => AlertDetailScreen(alert: a)));
                  },
                )
              );
            }
          ))
        ]));

      case '15':"""

content = case14_regex.sub(new_case14, content)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(content)
