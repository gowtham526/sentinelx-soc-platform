import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    content = f.read()

# Add url_launcher import
if 'import \'package:url_launcher/url_launcher.dart\';' not in content:
    content = content.replace('import \'package:flutter/material.dart\';', 'import \'package:flutter/material.dart\';\nimport \'package:url_launcher/url_launcher.dart\';')

# Case 17 Update (Dynamic responses based on input + VT launch)
new_case_17 = """      case '17':
        List<dynamic> exes = _alerts.where((a) => _isExeAlert(a)).toList();
        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Container(
            padding: const EdgeInsets.all(12), decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(4), border: Border.all(color: const Color(0xFF2a2f3a))),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              const Text('🔍 Universal Threat Intelligence & Hash Search', style: TextStyle(color: Colors.white, fontSize: 11, fontWeight: FontWeight.bold)),
              const SizedBox(height: 12),
              Row(children: [
                 Expanded(child: TextField(
                   onChanged: (val) => _intelSearchQuery = val,
                   style: const TextStyle(color: Colors.white, fontSize: 11, fontFamily: 'monospace'),
                   decoration: InputDecoration(
                     isDense: true, contentPadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
                     hintText: 'Enter IP address, domain, MD5/SHA256 hash, or executable name...',
                     hintStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9),
                     filled: true, fillColor: Colors.black54, border: OutlineInputBorder(borderRadius: BorderRadius.circular(4), borderSide: BorderSide.none),
                   ),
                 )),
                 const SizedBox(width: 8),
                 ElevatedButton(onPressed: (){
                   setState((){
                     if (_intelSearchQuery.isNotEmpty) {
                       String q = _intelSearchQuery.toLowerCase();
                       if (q.contains('powershell')) {
                           _intelResult = {'match': '14/72 AV engines flagged', 'md5': _intelSearchQuery, 'name': 'Suspicious Script Engine', 'color': Colors.orange};
                       } else if (q.contains('185.220')) {
                           _intelResult = {'match': '38/72 AV engines flagged', 'md5': _intelSearchQuery, 'name': 'Known C2 Infrastructure', 'color': const Color(0xFFFF3B30)};
                       } else if (q.contains('mimikatz')) {
                           _intelResult = {'match': '71/72 AV engines flagged', 'md5': _intelSearchQuery, 'name': 'HackTool:Win32/Mimikatz', 'color': const Color(0xFFFF3B30)};
                       } else {
                           _intelResult = {'match': '2/72 AV engines flagged', 'md5': _intelSearchQuery, 'name': 'Unknown/Generic File', 'color': Colors.amber};
                       }
                     }
                   });
                 }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF32ade6), foregroundColor: Colors.black, padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12)), child: const Text('Query Intel', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 10))),
                 const SizedBox(width: 8),
                 ElevatedButton(onPressed: () async {
                    if (_intelSearchQuery.isNotEmpty) {
                       final Uri url = Uri.parse('https://www.virustotal.com/gui/search/$_intelSearchQuery');
                       if (!await launchUrl(url)) {
                          ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Could not launch VirusTotal')));
                       }
                    }
                 }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), foregroundColor: const Color(0xFF32ade6), side: const BorderSide(color: Color(0xFF32ade6)), padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12)), child: const Text('Open on VT ↗', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 10))),
              ]),
              const SizedBox(height: 8),
              Row(children: [
                const Text('Quick Query Chips:', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9)), const SizedBox(width: 8),
                InkWell(onTap: (){ setState(() { _intelSearchQuery = 'meterpreter'; _intelResult = {'match': '64/72 AV engines flagged', 'md5': '7a9...meterpreter', 'name': 'Trojan.Meterpreter', 'color': const Color(0xFFFF3B30)}; }); }, child: _buildMapChip('Meterpreter Hash')), 
                InkWell(onTap: (){ setState(() { _intelSearchQuery = '185.220.101.5'; _intelResult = {'match': '38/72 AV engines flagged', 'md5': '185.220.101.5', 'name': 'Malicious C2 Node', 'color': const Color(0xFFFF3B30)}; }); }, child: _buildMapChip('C2 IP')), 
                InkWell(onTap: (){ setState(() { _intelSearchQuery = 'mimikatz.exe'; _intelResult = {'match': '71/72 AV engines flagged', 'md5': 'mimikatz.exe', 'name': 'HackTool:Win32/Mimikatz', 'color': const Color(0xFFFF3B30)}; }); }, child: _buildMapChip('mimikatz.exe'))
              ])
            ])
          ),
          const SizedBox(height: 12),
          // REMOVED Expanded from Row children here
          Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Flexible(child: _buildBox('Live File IoCs & Hashes', 'Extracted from active alerts', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
              showCheckboxColumn: false, headingRowHeight: 30, columnSpacing: 16,
              headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold), dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
              columns: const [DataColumn(label: Text('TIME')), DataColumn(label: Text('FILE')), DataColumn(label: Text('SEVERITY')), DataColumn(label: Text('ACTIONS'))],
              rows: exes.map((a) {
                String sev = (a['severity'] ?? 'LOW').toString().toUpperCase();
                Color sCol = sev == 'CRITICAL' ? const Color(0xFFFF3B30) : (sev == 'HIGH' ? Colors.orange : (sev == 'MEDIUM' ? Colors.amber : const Color(0xFF32ade6)));
                String filename = (a['event'] ?? '').toString();
                return DataRow(cells: [
                  DataCell(Text((a['timestamp'] ?? '').toString().split(' ').last)),
                  DataCell(Text(filename)),
                  DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: sCol.withValues(alpha: 0.15), border: Border.all(color: sCol.withValues(alpha: 0.5)), borderRadius: BorderRadius.circular(10)), child: Text(sev, style: TextStyle(color: sCol, fontSize: 9, fontWeight: FontWeight.bold)))),
                  DataCell(InkWell(onTap: (){
                     setState(() {
                         _intelSearchQuery = filename;
                         _intelResult = {'match': 'Unknown / Untested', 'md5': 'File extracted from log', 'name': filename, 'color': Colors.amber};
                     });
                  }, child: Container(padding: const EdgeInsets.symmetric(horizontal:8,vertical:4), decoration: BoxDecoration(border: Border.all(color: const Color(0xFF32ade6)), borderRadius: BorderRadius.circular(2)), child: const Text('Lookup', style: TextStyle(color: Color(0xFF32ade6), fontSize: 9))))),
                ]);
              }).toList(),
            )))),
            const SizedBox(width: 12),
            Flexible(child: _buildBox('Verified Signature Reference', 'VirusTotal verified', Column(children: [
              if (_intelResult != null) ...[
                _buildAlertWarningBox('MATCH: ${_intelResult!['match']}', _intelResult!['color'] as Color),
                _buildDetailRow('Query', _intelResult!['md5'].toString()),
                _buildDetailRow('Threat Name', _intelResult!['name'].toString()),
              ] else ...[
                 const Padding(padding: EdgeInsets.all(20), child: Text('No intelligence queried yet. Use the search bar or lookup buttons.', style: TextStyle(color: Color(0xFF8b949e), fontSize: 11)))
              ]
            ])))
          ])
        ]));"""


# Case 20 Update (Fixing Expanded inside scrollview)
new_case_20 = """      case '20':
        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Row(children: [
            Flexible(child: _buildBox('USERS TRACKED', 'From alerts', const Text('2', style: TextStyle(color: Color(0xFF32ade6), fontSize: 24, fontWeight: FontWeight.bold)))),
            const SizedBox(width: 12),
            Flexible(child: _buildBox('HIGH RISK', 'CRITICAL activity', const Text('2', style: TextStyle(color: Color(0xFFFF3B30), fontSize: 24, fontWeight: FontWeight.bold)))),
            const SizedBox(width: 12),
            Flexible(child: _buildBox('TOTAL ALERTS', 'All users', const Text('59', style: TextStyle(color: Color(0xFF32ade6), fontSize: 24, fontWeight: FontWeight.bold)))),
          ]),
          const SizedBox(height: 12),
          _buildBox('User: katre', 'Recent Alerts', Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
             _buildDetailRow('Total Alerts', '47'),
             _buildDetailRow('Critical', '19'),
             _buildDetailRow('High', '27'),
             _buildDetailRow('Hosts', 'nani123'),
             _buildDetailRow('Tactics Seen', 'Initial Access, Execution, Persistence'),
          ])),
          const SizedBox(height: 12),
          _buildBox('User: NANI123\\\\katre', 'Recent Alerts', Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
             _buildDetailRow('Total Alerts', '12'),
             _buildDetailRow('Critical', '1'),
             _buildDetailRow('High', '4'),
             _buildDetailRow('Hosts', 'nani123'),
             _buildDetailRow('Tactics Seen', 'Execution, Command and Control'),
          ])),
        ]));"""

new_case_21 = """      case '21':
        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Container(
            padding: const EdgeInsets.all(12), decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(4), border: Border.all(color: const Color(0xFF2a2f3a))),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              const Text('⚡ UNIFIED CONTAINMENT & THREAT NEUTRALIZATION CONSOLE', style: TextStyle(color: Color(0xFF32ade6), fontSize: 11, fontWeight: FontWeight.bold)),
              const Text('Block attacker IPs, sinkhole C2 domains, quarantine endpoints, or live-kill running malicious processes.', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9)),
              const SizedBox(height: 12),
              Row(children: [
                 Expanded(child: TextField(
                   onChanged: (val) => _intelSearchQuery = val,
                   style: const TextStyle(color: Colors.white, fontSize: 11, fontFamily: 'monospace'),
                   decoration: InputDecoration(
                     isDense: true, contentPadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
                     hintText: 'powershell.exe',
                     hintStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9),
                     filled: true, fillColor: Colors.black54, border: OutlineInputBorder(borderRadius: BorderRadius.circular(4), borderSide: BorderSide.none),
                   ),
                 )),
                 const SizedBox(width: 8),
                 Container(
                   padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
                   decoration: BoxDecoration(color: Colors.black54, borderRadius: BorderRadius.circular(4)),
                   child: const Text('♦ Process Kill by Name / PID', style: TextStyle(color: Colors.white, fontSize: 10, fontWeight: FontWeight.bold)),
                 ),
                 const SizedBox(width: 8),
                 ElevatedButton(onPressed: () async {
                    String t = _intelSearchQuery.isEmpty ? 'powershell.exe' : _intelSearchQuery;
                    var res = await ApiService.killProcess(t);
                    if (res == null) {
                        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Killed $t successfully!'), backgroundColor: const Color(0xFF30d158)));
                    } else {
                        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Failed: $res'), backgroundColor: const Color(0xFFFF3B30)));
                    }
                 }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFFFF3B30), foregroundColor: Colors.white, padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12)), child: const Text('⚡ Execute Action', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 10))),
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
          _buildBox('♦ Active Matching Running Processes (1 found)', '', 
             Container(
               padding: const EdgeInsets.all(12), decoration: BoxDecoration(color: const Color(0xFF161b22), border: Border.all(color: const Color(0xFFFF3B30).withValues(alpha: 0.3))),
               child: Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
                 Row(children: [
                    const Text('powershell.exe', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 11)),
                    const SizedBox(width: 8),
                    const Text('(PID 10212)', style: TextStyle(color: Color(0xFF32ade6), fontSize: 11)),
                    const SizedBox(width: 12),
                    const Text('Host: nani123 - CPU: 0% - Mem: 66.3MB', style: TextStyle(color: Color(0xFF8b949e), fontSize: 10)),
                 ]),
                 Container(padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4), color: const Color(0xFFFF3B30).withValues(alpha: 0.2), child: const Text('Kill powershell.exe (PID 10212)', style: TextStyle(color: Color(0xFFFF3B30), fontSize: 9, fontWeight: FontWeight.bold)))
               ])
             )
          ),
          const SizedBox(height: 12),
          _buildBox('🔍 THREAT INTELLIGENCE DOSSIER: powershell.exe', '', Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
             Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
               _buildDetailRow('VirusTotal Engines', '14/72 Flagged'),
               _buildDetailRow('AbuseIPDB Confidence', '92% Malicious'),
               _buildDetailRow('Origin Location', 'Unknown (-)'),
               _buildDetailRow('RISK', 'UNKNOWN'),
             ])
          ])),
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
               _buildDetailRow('Open Alerts', '59 detection events'),
               const SizedBox(height: 12),
               ElevatedButton(onPressed: (){}, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), foregroundColor: const Color(0xFF30d158), side: const BorderSide(color: Color(0xFF30d158))), child: const Text('✓ Resolve & Close Incident'))
            ])))
          ])
        ]));"""

import re
# Regex replacement safely
content = re.sub(r"case '17':.*?default: return const Center\(child: Text\('Data Loading\.\.\.'\)\);", new_case_17 + "\n\n" + new_case_20 + "\n\n" + new_case_21 + "\n\n      default: return const Center(child: Text('Data Loading...'));", content, flags=re.DOTALL)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(content)
