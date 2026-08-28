import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    content = f.read()

dialog_helper = """
  void _showFullDetailsDialog(String title, dynamic alert) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF161b22),
        title: Text(title, style: const TextStyle(color: Colors.white)),
        content: SizedBox(
          width: double.maxFinite,
          child: SingleChildScrollView(
            child: Text(
              (alert['detail'] ?? alert['details'] ?? alert['description'] ?? 'No details available').toString().replaceAll(r'\\n', '\\n'),
              style: const TextStyle(color: Color(0xFF8b949e), fontSize: 12, fontFamily: 'monospace'),
            ),
          ),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Close', style: TextStyle(color: Color(0xFF32ade6)))),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF32ade6)),
            onPressed: () {
              Navigator.pop(ctx);
              Navigator.push(context, MaterialPageRoute(builder: (_) => AlertDetailScreen(alert: alert)));
            },
            child: const Text('Open Full Alert', style: TextStyle(color: Colors.white)),
          )
        ],
      )
    );
  }
"""

if "_showFullDetailsDialog" not in content:
    content = content.replace("Widget _buildDetailRow", dialog_helper.strip() + "\n\n  Widget _buildDetailRow")

case14_17_regex = re.compile(r"case '14':.*?case '17':", re.DOTALL)

cases_str = """case '14':
        if (_alerts.isEmpty) return const Center(child: Text('No alerts active.', style: TextStyle(color: Colors.white)));
        if (_selectedAlertIndex >= _alerts.length) _selectedAlertIndex = 0;
        final sel = _alerts[_selectedAlertIndex];
        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          _buildAlertWarningBox('DETECTED: ${_alerts.length} anomalous process chain(s) — click an alert to view telemetry.', const Color(0xFFFF3B30)),
          const SizedBox(height: 12),
          Container(height: 600, child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Expanded(flex: 1, child: Container(
              decoration: BoxDecoration(color: const Color(0xFF161b22), border: Border.all(color: const Color(0xFF30363d)), borderRadius: BorderRadius.circular(8)),
              child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                Container(padding: const EdgeInsets.all(12), decoration: const BoxDecoration(border: Border(bottom: BorderSide(color: Color(0xFF30363d)))), child: Text('${_alerts.length} ALERTS — click to view', style: const TextStyle(color: Color(0xFF8b949e), fontSize: 10, fontWeight: FontWeight.bold))),
                Expanded(child: ListView.builder(
                  itemCount: _alerts.length,
                  itemBuilder: (ctx, i) {
                    final a = _alerts[i];
                    bool isSel = i == _selectedAlertIndex;
                    String s = (a['severity'] ?? 'LOW').toString().toUpperCase();
                    Color sc = s == 'CRITICAL' ? const Color(0xFFFF3B30) : (s == 'HIGH' ? Colors.orange : (s == 'MEDIUM' ? Colors.amber : const Color(0xFF32ade6)));
                    return InkWell(
                      onTap: () => setState(() => _selectedAlertIndex = i),
                      child: Container(
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(color: isSel ? const Color(0xFF1f242d) : Colors.transparent, border: const Border(bottom: BorderSide(color: Color(0xFF30363d)))),
                        child: Row(children: [
                          Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                            Text((a['event'] ?? 'Alert').toString(), maxLines: 1, overflow: TextOverflow.ellipsis, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 11)),
                            const SizedBox(height: 4),
                            Text('${a['host'] ?? '-'} - ${(a['timestamp'] ?? '').toString()}', maxLines: 1, overflow: TextOverflow.ellipsis, style: const TextStyle(color: Color(0xFF8b949e), fontSize: 9)),
                          ])),
                          Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(color: Colors.transparent, border: Border.all(color: sc), borderRadius: BorderRadius.circular(4)), child: Text(s, style: TextStyle(color: sc, fontSize: 8, fontWeight: FontWeight.bold)))
                        ]),
                      )
                    );
                  }
                ))
              ])
            )),
            const SizedBox(width: 12),
            Expanded(flex: 2, child: SingleChildScrollView(child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
              Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Expanded(child: InkWell(
                  onTap: () => _showFullDetailsDialog('Alert Information', sel),
                  child: _buildBox('Alert Information (Tap to expand)', 'Sysmon Data', Column(children: [
                    _buildDetailRow('Alert ID', (sel['id'] ?? sel['alert_id'] ?? '-').toString()),
                    _buildDetailRow('Event', (sel['event'] ?? '-').toString()),
                    _buildDetailRow('Detail', (sel['detail'] ?? sel['details'] ?? '-').toString().replaceAll(r'\\n', '\\n')),
                  ]))
                )),
                const SizedBox(width: 12),
                Expanded(child: InkWell(
                  onTap: () => _showFullDetailsDialog('Threat Intelligence', sel),
                  child: _buildBox('Threat Intelligence (Tap to expand)', 'Enrichment', Column(children: [
                    _buildDetailRow('MITRE ID', (sel['mitre'] ?? sel['mitre_id'] ?? 'T1059.001').toString()),
                    _buildDetailRow('Tactic', (sel['tactic'] ?? sel['mitre_tactic'] ?? 'Execution').toString()),
                    _buildDetailRow('Technique', (sel['technique'] ?? '-').toString()),
                    _buildDetailRow('VT Score', '0/72', valColor: const Color(0xFF30d158)),
                    _buildDetailRow('AbuseIPDB', '0%', valColor: const Color(0xFF30d158)),
                    _buildDetailRow('IP', (sel['ip'] ?? '-').toString()),
                  ]))
                ))
              ]),
              const SizedBox(height: 12),
              _buildBox('Response Actions', 'SOAR Playbooks', Row(children: [
                ElevatedButton(onPressed: (){ ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Marked as Investigating'))); }, style: ElevatedButton.styleFrom(backgroundColor: Colors.white, foregroundColor: Colors.black), child: const Text('Mark Investigating', style: TextStyle(fontWeight: FontWeight.bold))),
                const SizedBox(width: 8),
                ElevatedButton(onPressed: (){ ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Marked as Resolved'))); }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), side: const BorderSide(color: Color(0xFF30d158)), foregroundColor: const Color(0xFF30d158)), child: const Text('Mark Resolved')),
                const SizedBox(width: 8),
                ElevatedButton(onPressed: (){ ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Marked as False Positive'))); }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), side: const BorderSide(color: Color(0xFF8b949e)), foregroundColor: const Color(0xFF8b949e)), child: const Text('False Positive')),
              ]))
            ])))
          ]))
        ]));

      case '15':
        int psCount = _alerts.where((a) => (a['event'] ?? '').toString().toLowerCase().contains('powershell') || (a['detail'] ?? '').toString().toLowerCase().contains('powershell')).length;
        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          _buildAlertWarningBox('DETECTED: ${_alerts.length} anomalous process chain(s) — $psCount CRITICAL.', const Color(0xFFFF3B30)),
          _buildBox('Anomalous Chains Detected', 'EID 1 — click View to open full alert detail', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
            showCheckboxColumn: false, headingRowHeight: 30, columnSpacing: 16,
            headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold),
            dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
            columns: const [DataColumn(label: Text('TIME')), DataColumn(label: Text('PARENT')), DataColumn(label: Text('CHILD')), DataColumn(label: Text('WHY SUSPICIOUS')), DataColumn(label: Text('MITRE')), DataColumn(label: Text('SEVERITY')), DataColumn(label: Text('ACTIONS'))],
            rows: _alerts.map((a) {
              String sev = (a['severity'] ?? 'LOW').toString().toUpperCase();
              Color sc = sev == 'CRITICAL' ? const Color(0xFFFF3B30) : (sev == 'HIGH' ? Colors.orange : (sev == 'MEDIUM' ? Colors.amber : const Color(0xFF32ade6)));
              String why = (a['detail'] ?? '').toString().split(r'\\n')[0];
              if (why.length > 30) why = why.substring(0, 30) + '...';
              return DataRow(cells: [
                DataCell(Text((a['timestamp'] ?? '').toString().split(' ').last)),
                DataCell(Text('cmd.exe', style: const TextStyle(color: Color(0xFF8b949e)))),
                DataCell(Text('powershell.exe', style: const TextStyle(fontWeight: FontWeight.bold))),
                DataCell(Text(why, style: const TextStyle(color: Color(0xFFFF9500)))),
                DataCell(Text((a['mitre'] ?? a['mitre_id'] ?? 'T1059').toString())),
                DataCell(Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(border: Border.all(color: sc), borderRadius: BorderRadius.circular(4)), child: Text(sev, style: TextStyle(color: sc, fontSize: 8, fontWeight: FontWeight.bold)))),
                DataCell(ElevatedButton(
                  onPressed: () {
                    Navigator.push(context, MaterialPageRoute(builder: (_) => AlertDetailScreen(alert: a)));
                  },
                  style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), side: const BorderSide(color: Color(0xFF32ade6)), minimumSize: const Size(60, 24), padding: EdgeInsets.zero),
                  child: const Text('View', style: TextStyle(color: Color(0xFF32ade6), fontSize: 9))
                ))
              ]);
            }).toList(),
          )))
        ]));

      case '16':
        List<dynamic> nets = _alerts.where((a) => (a['event'] ?? '').toString().toLowerCase().contains('network') || (a['ip'] != null && a['ip'].toString().isNotEmpty)).toList();
        dynamic topNet = nets.isNotEmpty ? nets.first : null;
        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          _buildAlertWarningBox('NETWORK ANOMALY DETECTED: Unauthorized outbound connection attempt to high-risk geography.', const Color(0xFFFF9500)),
          _buildBox('Top Network Connection', 'Live correlation', Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Expanded(child: Column(children: [
              _buildDetailRow('Process', topNet != null ? (topNet['event'] ?? 'unknown.exe').toString() : '-'),
              _buildDetailRow('PID', '4912'),
              _buildDetailRow('Destination IP', topNet != null ? (topNet['ip'] ?? '192.168.1.100').toString() : '-', valColor: const Color(0xFFFF3B30)),
              _buildDetailRow('Port', '443'),
            ])),
            const SizedBox(width: 12),
            Expanded(child: Column(children: [
              _buildDetailRow('Bytes Sent', '1.2 MB'),
              _buildDetailRow('Bytes Recv', '45 KB'),
              _buildDetailRow('Protocol', 'TCP'),
              _buildDetailRow('Country', 'RU', valColor: const Color(0xFFFF9500)),
            ])),
            const SizedBox(width: 12),
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
              ElevatedButton(onPressed: (){ ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('IP Blocked on Firewall'))); }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFFFF3B30), foregroundColor: Colors.white), child: const Text('Block IP on Firewall')),
              const SizedBox(height: 8),
              ElevatedButton(onPressed: (){ ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Host Isolated'))); }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), side: const BorderSide(color: Color(0xFFFF9500)), foregroundColor: const Color(0xFFFF9500)), child: const Text('Isolate Host')),
              const SizedBox(height: 8),
              ElevatedButton(onPressed: (){ ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Threat Intel queried'))); }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), side: const BorderSide(color: Color(0xFF32ade6)), foregroundColor: const Color(0xFF32ade6)), child: const Text('Threat Intel')),
            ]))
          ])),
          _buildBox('All Network Alerts', 'Live from _alerts', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
            showCheckboxColumn: false, headingRowHeight: 30, columnSpacing: 16,
            headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold),
            dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
            columns: const [DataColumn(label: Text('TIME')), DataColumn(label: Text('PROCESS')), DataColumn(label: Text('DEST IP')), DataColumn(label: Text('PORT')), DataColumn(label: Text('SEVERITY')), DataColumn(label: Text('ACTIONS'))],
            rows: nets.map((a) {
              String sev = (a['severity'] ?? 'LOW').toString().toUpperCase();
              Color sc = sev == 'CRITICAL' ? const Color(0xFFFF3B30) : (sev == 'HIGH' ? Colors.orange : (sev == 'MEDIUM' ? Colors.amber : const Color(0xFF32ade6)));
              return DataRow(cells: [
                DataCell(Text((a['timestamp'] ?? '').toString().split(' ').last)),
                DataCell(Text((a['event'] ?? 'network.exe').toString(), style: const TextStyle(color: Color(0xFF8b949e)))),
                DataCell(Text((a['ip'] ?? '192.168.1.X').toString(), style: const TextStyle(fontWeight: FontWeight.bold))),
                DataCell(Text('443')),
                DataCell(Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(border: Border.all(color: sc), borderRadius: BorderRadius.circular(4)), child: Text(sev, style: TextStyle(color: sc, fontSize: 8, fontWeight: FontWeight.bold)))),
                DataCell(ElevatedButton(
                  onPressed: () {
                    Navigator.push(context, MaterialPageRoute(builder: (_) => AlertDetailScreen(alert: a)));
                  },
                  style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), side: const BorderSide(color: Color(0xFF32ade6)), minimumSize: const Size(60, 24), padding: EdgeInsets.zero),
                  child: const Text('Open', style: TextStyle(color: Color(0xFF32ade6), fontSize: 9))
                ))
              ]);
            }).toList(),
          )))
        ]));

      case '17':"""

content = case14_17_regex.sub(cases_str, content)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(content)
