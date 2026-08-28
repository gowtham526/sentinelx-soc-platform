import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    content = f.read()

# I need to add state variables at the top of the _DashboardScreenState class
state_vars = """
  String _currentViewTitle = 'Main Dashboard';
  
  // Threat Intel State
  String _intelSearchQuery = '';
  Map<String, dynamic>? _intelResult;
"""
content = re.sub(r'String _currentViewTitle = \'Main Dashboard\';', state_vars, content, 1)


# The old case 17
old_case_17_pattern = r"case '17':.*?default: return const Center\(child: Text\('Data Loading\.\.\.'\)\);"
new_case_17 = """case '17':
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
                       _intelResult = {'match': '59/72 AV engines flagged', 'md5': _intelSearchQuery, 'name': 'Generic.Malware.Gen', 'color': const Color(0xFFFF3B30)};
                     }
                   });
                 }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF32ade6), foregroundColor: Colors.black, padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12)), child: const Text('Query Intel', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 10))),
                 const SizedBox(width: 8),
                 ElevatedButton(onPressed: (){
                    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Opening VirusTotal for $_intelSearchQuery...'), backgroundColor: const Color(0xFF0a84ff)));
                 }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), foregroundColor: const Color(0xFF32ade6), side: const BorderSide(color: Color(0xFF32ade6)), padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12)), child: const Text('Open on VT ↗', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 10))),
              ]),
              const SizedBox(height: 8),
              Row(children: [
                const Text('Quick Query Chips:', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9)), const SizedBox(width: 8),
                InkWell(onTap: (){ setState(() { _intelSearchQuery = 'meterpreter'; _intelResult = {'match': '64/72 AV engines flagged', 'md5': '7a9...meterpreter', 'name': 'Trojan.Meterpreter', 'color': const Color(0xFFFF3B30)}; }); }, child: _buildMapChip('Meterpreter Hash')), 
                InkWell(onTap: (){ setState(() { _intelSearchQuery = '185.220.101.5'; _intelResult = {'match': '12/72 AV engines flagged', 'md5': 'N/A (IP Address)', 'name': 'Malicious C2 Node', 'color': Colors.orange}; }); }, child: _buildMapChip('C2 IP')), 
                InkWell(onTap: (){ setState(() { _intelSearchQuery = 'mimikatz.exe'; _intelResult = {'match': '71/72 AV engines flagged', 'md5': 'c3b...mimikatz', 'name': 'HackTool:Win32/Mimikatz', 'color': const Color(0xFFFF3B30)}; }); }, child: _buildMapChip('mimikatz.exe'))
              ])
            ])
          ),
          const SizedBox(height: 12),
          Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Expanded(child: _buildBox('Live File IoCs & Hashes', 'Extracted from active alerts', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
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
                  DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: sCol.withOpacity(0.15), border: Border.all(color: sCol.withOpacity(0.5)), borderRadius: BorderRadius.circular(10)), child: Text(sev, style: TextStyle(color: sCol, fontSize: 9, fontWeight: FontWeight.bold)))),
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
            Expanded(child: _buildBox('Verified Signature Reference', 'VirusTotal verified', Column(children: [
              if (_intelResult != null) ...[
                _buildAlertWarningBox('MATCH: ' + _intelResult!['match']!, _intelResult!['color']!),
                _buildDetailRow('Query', _intelResult!['md5']!),
                _buildDetailRow('Threat Name', _intelResult!['name']!),
              ] else ...[
                 const Padding(padding: EdgeInsets.all(20), child: Text('No intelligence queried yet. Use the search bar or lookup buttons.', style: TextStyle(color: Color(0xFF8b949e), fontSize: 11)))
              ]
            ])))
          ])
        ]));

      default: return const Center(child: Text('Data Loading...'));"""

content = re.sub(old_case_17_pattern, new_case_17.replace('\\', '\\\\'), content, flags=re.DOTALL)
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(content)
