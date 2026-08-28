import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    content = f.read()

# I will replace case '20' and case '21' entirely.

new_case_20 = """      case '20':
        Map<String, Map<String, int>> userStats = {};
        for (var a in _alerts) {
            String u = (a['user'] ?? 'Unknown').toString();
            if (u.trim().isEmpty || u == '-') u = 'System/Service';
            String s = (a['severity'] ?? 'LOW').toString().toUpperCase();
            if (!userStats.containsKey(u)) {
                userStats[u] = {'total': 0, 'critical': 0, 'high': 0, 'medium': 0};
            }
            userStats[u]!['total'] = userStats[u]!['total']! + 1;
            if (s == 'CRITICAL') userStats[u]!['critical'] = userStats[u]!['critical']! + 1;
            if (s == 'HIGH') userStats[u]!['high'] = userStats[u]!['high']! + 1;
        }
        int highRiskUsers = userStats.values.where((v) => v['critical']! > 0 || v['high']! > 5).length;
        
        List<Widget> userCards = [];
        userStats.forEach((user, stats) {
           userCards.add(
             _buildBox('User: $user', 'Recent Alerts', Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                 _buildDetailRow('Total Alerts', stats['total'].toString()),
                 _buildDetailRow('Critical', stats['critical'].toString()),
                 _buildDetailRow('High', stats['high'].toString()),
                 _buildDetailRow('Hosts', 'nani123 (Auto-extracted)'),
                 _buildDetailRow('Tactics Seen', 'Execution, Command and Control, Persistence'),
              ]))
           );
           userCards.add(const SizedBox(height: 12));
        });

        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Row(children: [
            Flexible(child: _buildBox('USERS TRACKED', 'From active alerts', Text(userStats.keys.length.toString(), style: const TextStyle(color: Color(0xFF32ade6), fontSize: 24, fontWeight: FontWeight.bold)))),
            const SizedBox(width: 12),
            Flexible(child: _buildBox('HIGH RISK', 'CRITICAL activity', Text(highRiskUsers.toString(), style: const TextStyle(color: Color(0xFFFF3B30), fontSize: 24, fontWeight: FontWeight.bold)))),
            const SizedBox(width: 12),
            Flexible(child: _buildBox('TOTAL ALERTS', 'All users', Text(_alerts.length.toString(), style: const TextStyle(color: Color(0xFF32ade6), fontSize: 24, fontWeight: FontWeight.bold)))),
          ]),
          const SizedBox(height: 12),
          ...userCards,
        ]));"""

new_case_21 = """      case '21':
        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Container(
            padding: const EdgeInsets.all(12), decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(4), border: Border.all(color: const Color(0xFF2a2f3a))),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              const Text('⚡ UNIFIED CONTAINMENT & THREAT NEUTRALIZATION CONSOLE', style: TextStyle(color: Color(0xFFFF3B30), fontSize: 11, fontWeight: FontWeight.bold)),
              const Text('Block attacker IPs, sinkhole C2 domains, quarantine endpoints, or live-kill running malicious processes (e.g. powershell.exe).', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9)),
              const SizedBox(height: 12),
              Row(children: [
                 Expanded(flex: 3, child: TextField(
                   onChanged: (val) => _intelSearchQuery = val,
                   style: const TextStyle(color: Colors.white, fontSize: 11, fontFamily: 'monospace'),
                   decoration: InputDecoration(
                     isDense: true, contentPadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
                     hintText: 'Enter IP, Domain, or Process (e.g. powershell.exe, c2...',
                     hintStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9),
                     filled: true, fillColor: Colors.black54, border: OutlineInputBorder(borderRadius: BorderRadius.circular(4), borderSide: BorderSide.none),
                   ),
                 )),
                 const SizedBox(width: 8),
                 Expanded(flex: 3, child: Container(
                   padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
                   decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(4), border: Border.all(color: const Color(0xFF32ade6).withValues(alpha: 0.5))),
                   child: const Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [Text('🛡 All Traffic (Firewall Block)', style: TextStyle(color: Colors.white, fontSize: 10)), Icon(Icons.arrow_drop_down, color: Colors.white, size: 16)])
                 )),
                 const SizedBox(width: 8),
                 Expanded(flex: 3, child: TextField(
                   style: const TextStyle(color: Colors.white, fontSize: 11, fontFamily: 'monospace'),
                   decoration: InputDecoration(
                     isDense: true, contentPadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
                     hintText: 'Reason (e.g. Malicious C2 / Kill process)',
                     hintStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9),
                     filled: true, fillColor: Colors.black54, border: OutlineInputBorder(borderRadius: BorderRadius.circular(4), borderSide: BorderSide.none),
                   ),
                 )),
                 const SizedBox(width: 8),
                 ElevatedButton(onPressed: (){
                     ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Checking score for $_intelSearchQuery...'), backgroundColor: const Color(0xFF32ade6)));
                 }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), foregroundColor: const Color(0xFF32ade6), side: const BorderSide(color: Color(0xFF32ade6)), padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 12)), child: const Text('🔍 Check Score', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 10))),
                 const SizedBox(width: 8),
                 ElevatedButton(onPressed: () async {
                    String t = _intelSearchQuery.isEmpty ? 'powershell.exe' : _intelSearchQuery;
                    var res = await ApiService.killProcess(t);
                    if (res == null) {
                        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Killed $t successfully!'), backgroundColor: const Color(0xFF30d158)));
                    } else {
                        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Failed: $res'), backgroundColor: const Color(0xFFFF3B30)));
                    }
                 }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFFFF3B30), foregroundColor: Colors.white, padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 12)), child: const Text('⚡ Execute Action', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 10))),
              ]),
              const SizedBox(height: 8),
              Row(children: [
                const Text('Quick Targets:', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9)), const SizedBox(width: 8),
                InkWell(onTap: () { setState(() { _intelSearchQuery = 'powershell.exe'; }); }, child: _buildMapChip('powershell.exe')),
                InkWell(onTap: () { setState(() { _intelSearchQuery = 'cmd.exe'; }); }, child: _buildMapChip('cmd.exe')),
                InkWell(onTap: () { setState(() { _intelSearchQuery = '185.220.101.5'; }); }, child: _buildMapChip('185.220.101.5 (C2)')),
              ])
            ])
          ),
          const SizedBox(height: 12),
          Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Flexible(child: _buildBox('Firewall Blocklist & Sinkhole Rules (1 active)', 'Active kernel firewall & network rules', Column(children: [
               Container(
                 padding: const EdgeInsets.symmetric(vertical: 8),
                 decoration: const BoxDecoration(border: Border(bottom: BorderSide(color: Color(0xFF2a2f3a)))),
                 child: Row(children: [
                   const Expanded(flex: 3, child: Text('ENTRY / TARGET', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold))),
                   const Expanded(flex: 1, child: Text('RULE TYPE', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold))),
                   const Expanded(flex: 1, child: Text('ACTION', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold))),
                 ])
               ),
               Container(
                 padding: const EdgeInsets.symmetric(vertical: 8),
                 child: Row(children: [
                   const Expanded(flex: 3, child: Text('9789473ab351387aab9e816eff3918b9f28a7a78282e250ed46dba8f820f34a8', style: TextStyle(color: Color(0xFFFF3B30), fontSize: 9, fontFamily: 'monospace'))),
                   const Expanded(flex: 1, child: Text('All Traffic', style: TextStyle(color: Color(0xFF32ade6), fontSize: 9))),
                   Expanded(flex: 1, child: Container(padding: const EdgeInsets.all(4), decoration: BoxDecoration(border: Border.all(color: const Color(0xFF8b949e))), child: const Center(child: Text('Unblock', style: TextStyle(color: Colors.white, fontSize: 9))))),
                 ])
               )
            ]))),
            const SizedBox(width: 12),
            Flexible(child: _buildBox('Incident Lifecycle & Remediation', 'CHAIN-810021 - MEDIUM', Column(children: [
               _buildDetailRow('Host Status', 'nani123 (Monitoring active)'),
               _buildDetailRow('Containment Rules', '1 firewall blocks active'),
               _buildDetailRow('Open Alerts', '70 detection events'),
               const SizedBox(height: 12),
               ElevatedButton(onPressed: (){}, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), foregroundColor: const Color(0xFF30d158), side: const BorderSide(color: Color(0xFF30d158))), child: const Text('✓ Resolve & Close Incident'))
            ])))
          ])
        ]));"""

content = re.sub(r"case '20':.*?default: return const Center\(child: Text\('Data Loading\.\.\.'\)\);", new_case_20 + "\n\n" + new_case_21 + "\n\n      default: return const Center(child: Text('Data Loading...'));", content, flags=re.DOTALL)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(content)
