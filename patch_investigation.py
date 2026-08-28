import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    content = f.read()

# Add a state variable for slide 14 selection
if "int _selectedAlertIndex = 0;" not in content:
    content = content.replace("String _currentViewTitle = 'Live Alerts';", "String _currentViewTitle = 'Live Alerts';\n  int _selectedAlertIndex = 0;")

cases = """
      case '14':
        if (_alerts.isEmpty) return const Center(child: Text('No alerts active.', style: TextStyle(color: Colors.white)));
        if (_selectedAlertIndex >= _alerts.length) _selectedAlertIndex = 0;
        final sel = _alerts[_selectedAlertIndex];
        String sev = (sel['severity'] ?? 'LOW').toString().toUpperCase();
        Color sCol = sev == 'CRITICAL' ? const Color(0xFFFF3B30) : (sev == 'HIGH' ? Colors.orange : (sev == 'MEDIUM' ? Colors.amber : const Color(0xFF32ade6)));
        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          _buildAlertWarningBox('🔴 ISOLATE host from network immediately 🔴 Capture memory dump before remediation 🔴 Preserve forensic evidence 🔴 Notify SOC Lead', const Color(0xFFFF3B30)),
          Expanded(child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Expanded(flex: 1, child: Container(
              decoration: BoxDecoration(color: const Color(0xFF161b22), border: Border.all(color: const Color(0xFF30363d)), borderRadius: BorderRadius.circular(4)),
              child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                Container(padding: const EdgeInsets.all(8), color: const Color(0xFF21262d), child: Text('${_alerts.length} ALERTS — click to view', style: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold))),
                Expanded(child: ListView.builder(
                  itemCount: _alerts.length,
                  itemBuilder: (ctx, i) {
                    final a = _alerts[i];
                    final isSel = i == _selectedAlertIndex;
                    String s = (a['severity'] ?? 'LOW').toString().toUpperCase();
                    Color sc = s == 'CRITICAL' ? const Color(0xFFFF3B30) : (s == 'HIGH' ? Colors.orange : (s == 'MEDIUM' ? Colors.amber : const Color(0xFF32ade6)));
                    return InkWell(
                      onTap: () => setState(() => _selectedAlertIndex = i),
                      child: Container(
                        padding: const EdgeInsets.all(10),
                        decoration: BoxDecoration(color: isSel ? const Color(0xFF1f242d) : Colors.transparent, border: Border(bottom: BorderSide(color: const Color(0xFF30363d)), left: BorderSide(color: isSel ? const Color(0xFF32ade6) : Colors.transparent, width: 3))),
                        child: Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
                          Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                            Text((a['event'] ?? 'Alert').toString(), style: const TextStyle(color: Colors.white, fontSize: 10, fontWeight: FontWeight.bold), maxLines: 1, overflow: TextOverflow.ellipsis),
                            const SizedBox(height: 4),
                            Text('${a['host'] ?? '-'} - ${(a['timestamp'] ?? '').toString().split(' ').last}', style: const TextStyle(color: Color(0xFF8b949e), fontSize: 9))
                          ])),
                          Container(padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 2), decoration: BoxDecoration(color: sc.withOpacity(0.15), border: Border.all(color: sc.withOpacity(0.5)), borderRadius: BorderRadius.circular(4)), child: Text(s, style: TextStyle(color: sc, fontSize: 8, fontWeight: FontWeight.bold)))
                        ])
                      )
                    );
                  }
                ))
              ])
            )),
            const SizedBox(width: 12),
            Expanded(flex: 2, child: SingleChildScrollView(child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
              Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Expanded(child: _buildBox('Alert Information', 'Sysmon Data', Column(children: [
                  _buildDetailRow('Alert ID', 'ALT-${sel['id'] ?? 'Unknown'}'),
                  _buildDetailRow('Event', (sel['event'] ?? '-').toString()),
                  _buildDetailRow('Detail', (sel['detail'] ?? '-').toString().replaceAll(r'\\n', '\\n')),
                  _buildDetailRow('Host', (sel['host'] ?? '-').toString()),
                  _buildDetailRow('User', (sel['user'] ?? '-').toString()),
                  _buildDetailRow('Timestamp', (sel['timestamp'] ?? '-').toString()),
                  _buildDetailRow('Status', (sel['status'] ?? 'Open').toString()),
                  _buildDetailRow('Severity', sev, valColor: sCol),
                ]))),
                const SizedBox(width: 12),
                Expanded(child: _buildBox('Threat Intelligence', 'Live enrichment', Column(children: [
                  _buildDetailRow('MITRE ID', (sel['mitre'] ?? '-').toString()),
                  _buildDetailRow('Tactic', (sel['tactic'] ?? '-').toString()),
                  _buildDetailRow('Technique', (sel['technique'] ?? '-').toString()),
                  _buildDetailRow('VT Score', '0/72'),
                  _buildDetailRow('AbuseIPDB', '0%'),
                  _buildDetailRow('IP', (sel['ip'] ?? '-').toString()),
                  _buildDetailRow('Country', '-'),
                  _buildDetailRow('ISP', '-'),
                ]))),
              ]),
              const SizedBox(height: 12),
              Row(children: [
                ElevatedButton(onPressed: (){}, style: ElevatedButton.styleFrom(backgroundColor: Colors.white, foregroundColor: Colors.black), child: const Text('Mark Investigating', style: TextStyle(fontWeight: FontWeight.bold))),
                const SizedBox(width: 8),
                ElevatedButton(onPressed: (){}, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), side: const BorderSide(color: Color(0xFF30d158)), foregroundColor: const Color(0xFF30d158)), child: const Text('Mark Resolved')),
                const SizedBox(width: 8),
                ElevatedButton(onPressed: (){}, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), side: const BorderSide(color: Color(0xFF8b949e)), foregroundColor: const Color(0xFF8b949e)), child: const Text('False Positive')),
              ])
            ])))
          ])
        ]));

      case '15':
        int psCount = _alerts.where((a) => (a['event'] ?? '').toString().toLowerCase().contains('powershell') || (a['detail'] ?? '').toString().toLowerCase().contains('powershell')).length;
        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          _buildAlertWarningBox('DETECTED: ${_alerts.length} anomalous process chain(s) — $psCount CRITICAL. Click View for full detail and response options.', const Color(0xFFFF3B30)),
          Expanded(child: _buildBox('Anomalous Chains Detected', 'EID 1 — click View to open full alert detail', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
            showCheckboxColumn: false, headingRowHeight: 30, columnSpacing: 16,
            headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold),
            dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
            columns: const [DataColumn(label: Text('TIME')), DataColumn(label: Text('PARENT')), DataColumn(label: Text('CHILD')), DataColumn(label: Text('WHY SUSPICIOUS')), DataColumn(label: Text('MITRE')), DataColumn(label: Text('SEVERITY')), DataColumn(label: Text('ACTIONS'))],
            rows: _alerts.map((a) {
              String sev = (a['severity'] ?? 'LOW').toString().toUpperCase();
              Color sCol = sev == 'CRITICAL' ? const Color(0xFFFF3B30) : (sev == 'HIGH' ? Colors.orange : (sev == 'MEDIUM' ? Colors.amber : const Color(0xFF32ade6)));
              String p = (a['host'] ?? 'unknown').toString();
              String c = (a['event'] ?? '').toString();
              String why = (a['detail'] ?? '').toString().split(r'\\n')[0];
              if (why.length > 30) why = why.substring(0, 30) + '...';
              return DataRow(cells: [
                DataCell(Text((a['timestamp'] ?? '').toString().split(' ').last)),
                DataCell(Text(p, style: const TextStyle(color: Colors.white))),
                DataCell(Text(c, style: const TextStyle(color: Color(0xFFFF3B30)))),
                DataCell(Text(why, style: const TextStyle(color: Colors.amber))),
                DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: const Color(0xFF30363d), borderRadius: BorderRadius.circular(10)), child: Text((a['mitre'] ?? 'T1059.001').toString(), style: const TextStyle(color: Color(0xFF58a6ff), fontSize: 9)))),
                DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: sCol.withOpacity(0.15), border: Border.all(color: sCol.withOpacity(0.5)), borderRadius: BorderRadius.circular(10)), child: Text(sev, style: TextStyle(color: sCol, fontSize: 9, fontWeight: FontWeight.bold)))),
                DataCell(Row(children: [
                  Container(padding: const EdgeInsets.symmetric(horizontal:8,vertical:4), decoration: BoxDecoration(border: Border.all(color: const Color(0xFF32ade6)), borderRadius: BorderRadius.circular(2)), child: const Text('View', style: TextStyle(color: Color(0xFF32ade6), fontSize: 9))),
                  const SizedBox(width: 4),
                  Container(padding: const EdgeInsets.symmetric(horizontal:8,vertical:4), decoration: BoxDecoration(border: Border.all(color: const Color(0xFF30d158)), borderRadius: BorderRadius.circular(2)), child: const Text('RES', style: TextStyle(color: Color(0xFF30d158), fontSize: 9)))
                ])),
              ]);
            }).toList(),
          ))))
        ]));

      case '16':
        List<dynamic> nets = _alerts.where((a) => _isNetAlert(a) || (a['ip'] != null && a['ip'] != '-')).toList();
        dynamic topNet = nets.isNotEmpty ? nets.first : null;
        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          _buildAlertWarningBox('ACTIVE C2 DETECTED: ${topNet != null ? topNet['event'] : 'Suspicious Network Activity'}', const Color(0xFFFF3B30)),
          _buildBox('Top Network Connection', 'EID 3 data', Column(children: [
            _buildDetailRow('Process', topNet != null ? (topNet['event'] ?? 'unknown.exe').toString() : '-'),
            _buildDetailRow('Destination IP', topNet != null ? (topNet['ip'] ?? '-').toString() : '-'),
            _buildDetailRow('Host', topNet != null ? (topNet['host'] ?? '-').toString() : '-'),
            _buildDetailRow('MITRE', topNet != null ? (topNet['mitre'] ?? '-').toString() : '-'),
            _buildDetailRow('Severity', topNet != null ? (topNet['severity'] ?? '-').toString().toUpperCase() : '-'),
            const SizedBox(height: 8),
            Row(children: [
              ElevatedButton(onPressed: (){}, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), side: const BorderSide(color: Color(0xFFFF3B30)), foregroundColor: const Color(0xFFFF3B30)), child: const Text('Block IP')),
              const SizedBox(width: 8),
              ElevatedButton(onPressed: (){}, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), side: const BorderSide(color: Color(0xFF32ade6)), foregroundColor: const Color(0xFF32ade6)), child: const Text('Threat Intel Lookup')),
            ])
          ])),
          const SizedBox(height: 12),
          Expanded(child: _buildBox('All Network Alerts', 'Live from _alerts', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
            showCheckboxColumn: false, headingRowHeight: 30, columnSpacing: 16,
            headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold),
            dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
            columns: const [DataColumn(label: Text('TIME')), DataColumn(label: Text('EVENT')), DataColumn(label: Text('HOST')), DataColumn(label: Text('IP')), DataColumn(label: Text('SEVERITY'))],
            rows: nets.map((a) {
              String sev = (a['severity'] ?? 'LOW').toString().toUpperCase();
              Color sCol = sev == 'CRITICAL' ? const Color(0xFFFF3B30) : (sev == 'HIGH' ? Colors.orange : (sev == 'MEDIUM' ? Colors.amber : const Color(0xFF32ade6)));
              return DataRow(cells: [
                DataCell(Text((a['timestamp'] ?? '').toString().split(' ').last)),
                DataCell(Text((a['event'] ?? '').toString())),
                DataCell(Text((a['host'] ?? '').toString())),
                DataCell(Text((a['ip'] ?? '-').toString(), style: const TextStyle(color: Color(0xFFFF3B30)))),
                DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: sCol.withOpacity(0.15), border: Border.all(color: sCol.withOpacity(0.5)), borderRadius: BorderRadius.circular(10)), child: Text(sev, style: TextStyle(color: sCol, fontSize: 9, fontWeight: FontWeight.bold)))),
              ]);
            }).toList(),
          ))))
        ]));

      case '17':
        List<dynamic> exes = _alerts.where((a) => _isExeAlert(a)).toList();
        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Container(
            padding: const EdgeInsets.all(12), decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(4), border: Border.all(color: const Color(0xFF2a2f3a))),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              const Text('🔍 Universal Threat Intelligence & Hash Search', style: TextStyle(color: Colors.white, fontSize: 11, fontWeight: FontWeight.bold)),
              const SizedBox(height: 12),
              Row(children: [
                 Expanded(child: TextField(
                   style: const TextStyle(color: Colors.white, fontSize: 11, fontFamily: 'monospace'),
                   decoration: InputDecoration(
                     isDense: true, contentPadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
                     hintText: 'Enter IP address, domain, MD5/SHA256 hash, or executable name...',
                     hintStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9),
                     filled: true, fillColor: Colors.black54, border: OutlineInputBorder(borderRadius: BorderRadius.circular(4), borderSide: BorderSide.none),
                   ),
                 )),
                 const SizedBox(width: 8),
                 ElevatedButton(onPressed: (){}, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF32ade6), foregroundColor: Colors.black, padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12)), child: const Text('Query Intel', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 10))),
                 const SizedBox(width: 8),
                 ElevatedButton(onPressed: (){}, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), foregroundColor: const Color(0xFF32ade6), side: const BorderSide(color: Color(0xFF32ade6)), padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12)), child: const Text('Open on VT ↗', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 10))),
              ]),
              const SizedBox(height: 8),
              Row(children: [
                const Text('Quick Query Chips:', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9)), const SizedBox(width: 8),
                _buildMapChip('Meterpreter Hash'), _buildMapChip('C2 IP'), _buildMapChip('mimikatz.exe')
              ])
            ])
          ),
          const SizedBox(height: 12),
          Expanded(child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Expanded(child: _buildBox('Live File IoCs & Hashes', 'Extracted from active alerts', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
              showCheckboxColumn: false, headingRowHeight: 30, columnSpacing: 16,
              headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold), dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
              columns: const [DataColumn(label: Text('TIME')), DataColumn(label: Text('FILE')), DataColumn(label: Text('SEVERITY')), DataColumn(label: Text('ACTIONS'))],
              rows: exes.map((a) {
                String sev = (a['severity'] ?? 'LOW').toString().toUpperCase();
                Color sCol = sev == 'CRITICAL' ? const Color(0xFFFF3B30) : (sev == 'HIGH' ? Colors.orange : (sev == 'MEDIUM' ? Colors.amber : const Color(0xFF32ade6)));
                return DataRow(cells: [
                  DataCell(Text((a['timestamp'] ?? '').toString().split(' ').last)),
                  DataCell(Text((a['event'] ?? '').toString())),
                  DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: sCol.withOpacity(0.15), border: Border.all(color: sCol.withOpacity(0.5)), borderRadius: BorderRadius.circular(10)), child: Text(sev, style: TextStyle(color: sCol, fontSize: 9, fontWeight: FontWeight.bold)))),
                  DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:8,vertical:4), decoration: BoxDecoration(border: Border.all(color: const Color(0xFF32ade6)), borderRadius: BorderRadius.circular(2)), child: const Text('Lookup', style: TextStyle(color: Color(0xFF32ade6), fontSize: 9)))),
                ]);
              }).toList(),
            )))),
            const SizedBox(width: 12),
            Expanded(child: _buildBox('Verified Signature Reference', 'VirusTotal verified', Column(children: [
              _buildAlertWarningBox('MALICIOUS SIGNATURE MATCH: 52/72 AV engines flagged', const Color(0xFFFF3B30)),
              _buildDetailRow('Sample MD5', '4a1...'),
              _buildDetailRow('Threat Name', 'Trojan.Meterpreter.Agent'),
            ])))
          ]))
        ]));
"""

content = content.replace("default: return const Center(child: Text('Data Loading...'));", cases + "\n      default: return const Center(child: Text('Data Loading...'));")

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(content)
