import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix Slide 17 Row -> Column for mobile
new_row_17 = """              TextField(
                onChanged: (val) => _intelSearchQuery = val,
                style: const TextStyle(color: Colors.white, fontSize: 11, fontFamily: 'monospace'),
                decoration: InputDecoration(
                  isDense: true, contentPadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
                  hintText: 'Enter IP address, domain, MD5/SHA256 hash...',
                  hintStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9),
                  filled: true, fillColor: Colors.black54, border: OutlineInputBorder(borderRadius: BorderRadius.circular(4), borderSide: BorderSide.none),
                ),
              ),
              const SizedBox(height: 8),
              Row(children: [
                 Expanded(child: ElevatedButton(onPressed: (){
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
                 }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF32ade6), foregroundColor: Colors.black, padding: const EdgeInsets.symmetric(vertical: 12)), child: const Text('Query Intel', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 10)))),
                 const SizedBox(width: 8),
                 Expanded(child: ElevatedButton(onPressed: () async {
                    if (_intelSearchQuery.isNotEmpty) {
                       final Uri url = Uri.parse('https://www.virustotal.com/gui/search/$_intelSearchQuery');
                       if (!await launchUrl(url)) {
                          ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Could not launch VirusTotal')));
                       }
                    }
                 }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), foregroundColor: const Color(0xFF32ade6), side: const BorderSide(color: Color(0xFF32ade6)), padding: const EdgeInsets.symmetric(vertical: 12)), child: const Text('Open on VT ↗', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 10)))),
              ]),"""

content = re.sub(r'Row\(children: \[\s*Expanded\(child: TextField\(\s*onChanged:(.*?)\)\),\s*const SizedBox\(width: 8\),\s*ElevatedButton\(onPressed: \(\)\{(.*?)\},\s*style:(.*?)\),\s*const SizedBox\(width: 8\),\s*ElevatedButton\(onPressed: \(\) async \{(.*?)\},\s*style:(.*?)\),\s*\]\),', new_row_17, content, flags=re.DOTALL)


# Fix Slide 17 Bottom Panels Row -> Column for mobile
new_bottom_17 = """          Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            _buildBox('Live File IoCs & Hashes', 'Extracted from active alerts', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
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
            ))),
            const SizedBox(height: 12),
            _buildBox('Verified Signature Reference', 'VirusTotal verified', Column(children: [
              if (_intelResult != null) ...[
                _buildAlertWarningBox('MATCH: ${_intelResult!['match']}', _intelResult!['color'] as Color),
                _buildDetailRow('Query', _intelResult!['md5'].toString()),
                _buildDetailRow('Threat Name', _intelResult!['name'].toString()),
              ] else ...[
                 const Padding(padding: EdgeInsets.all(20), child: Text('No intelligence queried yet.', style: TextStyle(color: Color(0xFF8b949e), fontSize: 11)))
              ]
            ]))
          ])"""

content = re.sub(r'Row\(crossAxisAlignment: CrossAxisAlignment\.start,\s*children: \[\s*Flexible\(child: _buildBox\(\'Live File IoCs & Hashes\'.*?\]\)\)\)\s*\]\)', new_bottom_17, content, flags=re.DOTALL)


with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(content)
