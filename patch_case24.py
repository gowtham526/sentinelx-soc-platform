import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

old_24 = re.search(r"case '24':.*?(?=          _buildBox\('Active Classification Rules Matrix')", text, re.DOTALL)
if not old_24:
    print("Could not find case 24!")
    exit(1)

new_24 = '''case '24': {
        final malware = _alerts.where((a) => a['severity'] == 'CRITICAL').toList();
        final suspicious = _alerts.where((a) => a['severity'] == 'HIGH').toList();
        final normal = _alerts.where((a) => a['severity'] == 'LOW' || a['severity'] == 'MEDIUM').toList();

        String getLabel(Map<String, dynamic> a) {
          String d = (a['detail']?.toString() ?? '') + (a['event']?.toString() ?? '');
          d = d.toLowerCase();
          if (d.contains('mimikatz') || d.contains('lsass') || d.contains('sekurlsa')) return 'Credential Dumper (Mimikatz)';
          if (d.contains('ransom') || d.contains('vssadmin') || d.contains('shadows')) return 'Ransomware / Shadow Delete';
          if (d.contains('backdoor') || d.contains('rat') || d.contains('meterpreter')) return 'C2 Backdoor / Meterpreter';
          if (d.contains('powershell') || d.contains('-enc') || d.contains('bypass') || d.contains('downloadstring')) return 'Encoded PowerShell Cradle';
          if (d.contains('registry') || d.contains('run key') || d.contains('currentversion\\\\run')) return 'Registry Persistence';
          if (d.contains('network') || d.contains(':44') || d.contains('c2') || d.contains('port')) return 'C2 Network Beacon';
          if (d.contains('macro') || d.contains('office') || d.contains('winword') || d.contains('excel')) return 'Malicious Office Macro';
          if (d.contains('canary') || d.contains('decoy') || d.contains('trap')) return 'Deception / Canary File Trip';
          if (d.contains('injection') || d.contains('createremotethread') || d.contains('eid 8')) return 'Process Injection (EID 8)';
          if (d.contains('.exe') || d.contains('temp') || d.contains('appdata')) return 'Suspicious Dropped Executable';
          return a['mitre_tactic']?.toString() ?? 'General Threat Detection';
        }

        Widget buildBadge(Map<String, dynamic> a, Color color) {
          return GestureDetector(
            onTap: () {
              Navigator.push(context, MaterialPageRoute(builder: (_) => AlertDetailScreen(alert: a)));
            },
            child: Container(
              margin: const EdgeInsets.symmetric(horizontal: 4, vertical: 4),
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              decoration: BoxDecoration(color: color.withOpacity(0.2), borderRadius: BorderRadius.circular(4)),
              child: Text(getLabel(a), style: TextStyle(color: color, fontSize: 9)),
            ),
          );
        }

        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          _buildAlertWarningBox('⚡ AI Classification Engine: ${_alerts.length} active alert(s) categorized into ${malware.length} Malware Confirmed, ${suspicious.length} Suspicious Activity, and ${normal.length} Benign.', const Color(0xFFFF3B30)),
          _buildBox('Malware Confirmed', '${malware.length} events', Column(children: [
             Text('${malware.length}', style: const TextStyle(color: Color(0xFFFF3B30), fontSize: 32, fontWeight: FontWeight.bold)),
             const SizedBox(height: 8),
             if (malware.isEmpty)
               const Text('No active critical malware', style: TextStyle(color: Color(0xFF8b949e), fontSize: 10))
             else ...[
               Wrap(
                 alignment: WrapAlignment.center,
                 children: malware.map((a) => buildBadge(a, const Color(0xFFFF3B30))).toList(),
               ),
               const SizedBox(height: 8),
               const Text('Click any badge to inspect alert', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9))
             ]
          ])),
          const SizedBox(height: 12),
          _buildBox('Suspicious Activity', '${suspicious.length} events', Column(children: [
             Text('${suspicious.length}', style: const TextStyle(color: Colors.orange, fontSize: 32, fontWeight: FontWeight.bold)),
             const SizedBox(height: 8),
             if (suspicious.isEmpty)
               const Text('No elevated suspicious events', style: TextStyle(color: Color(0xFF8b949e), fontSize: 10))
             else ...[
               Wrap(
                 alignment: WrapAlignment.center,
                 children: suspicious.map((a) => buildBadge(a, Colors.orange)).toList(),
               ),
               const SizedBox(height: 8),
               const Text('Click any badge to inspect alert', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9))
             ]
          ])),
          const SizedBox(height: 12),
          _buildBox('Normal / Benign', '${normal.length} events', Column(children: [
             Text('${normal.length}', style: const TextStyle(color: Color(0xFF30d158), fontSize: 32, fontWeight: FontWeight.bold)),
             const SizedBox(height: 8),
             if (normal.isEmpty)
               const Text('No benign events', style: TextStyle(color: Color(0xFF8b949e), fontSize: 10))
             else ...[
               Wrap(
                 alignment: WrapAlignment.center,
                 children: normal.map((a) => buildBadge(a, const Color(0xFF30d158))).toList(),
               ),
               const SizedBox(height: 8),
               const Text('Click any badge to inspect alert', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9))
             ]
          ])),
          const SizedBox(height: 12),
'''

text = text.replace(old_24.group(0), new_24)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)

print("Patched!")
