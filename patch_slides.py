import re

with open('sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as src:
    content = src.read()

helpers = """
  bool _isExeAlert(Map<String, dynamic> a) {
    String src = (a['source'] ?? '').toString().toLowerCase();
    String ls = (a['log_source'] ?? '').toString().toLowerCase();
    String ev = (a['event'] ?? '').toString().toLowerCase();
    String det = (a['detail'] ?? '').toString().toLowerCase();
    String mid = (a['mitre_id'] ?? '').toString().toLowerCase();
    return src == 'exe' || ls.contains('app') || ev.contains('exe') || ev.contains('binary') || ev.contains('process') || ev.contains('executable') || ev.contains('payload') || det.contains('.exe') || det.contains(r'\\temp') || det.contains(r'\\appdata') || det.contains(r'temp\\') || det.contains('programdata') || mid.contains('t1204') || mid.contains('t1059.003');
  }

  bool _isPsAlert(Map<String, dynamic> a) {
    String src = (a['source'] ?? '').toString().toLowerCase();
    String ls = (a['log_source'] ?? '').toString().toLowerCase();
    String ev = (a['event'] ?? '').toString().toLowerCase();
    String det = (a['detail'] ?? '').toString().toLowerCase();
    String mid = (a['mitre_id'] ?? '').toString().toLowerCase();
    return src == 'powershell' || ls.contains('powershell') || ev.contains('powershell') || ev.contains('mimikatz') || ev.contains('script') || ev.contains('pwsh') || det.contains('powershell') || det.contains('-enc') || det.contains('encodedcommand') || det.contains('bypass') || det.contains('iex') || det.contains('downloadstring') || det.contains('invoke-') || mid.contains('t1059.001') || mid.contains('t1003');
  }

  bool _isNetAlert(Map<String, dynamic> a) {
    String src = (a['source'] ?? '').toString().toLowerCase();
    String ls = (a['log_source'] ?? '').toString().toLowerCase();
    String ev = (a['event'] ?? '').toString().toLowerCase();
    String det = (a['detail'] ?? '').toString().toLowerCase();
    String mid = (a['mitre_id'] ?? '').toString().toLowerCase();
    bool hasIp = (a['ip'] != null && a['ip'] != '-' && a['ip'] != '127.0.0.1');
    return src == 'network' || src == 'sysmon_network' || ls.contains('net') || ev.contains('network') || ev.contains('connect') || ev.contains('c2') || ev.contains('beacon') || ev.contains('port scan') || ev.contains('socket') || ev.contains('reverse shell') || det.contains('connection') || det.contains('outbound') || det.contains('inbound') || det.contains(':4444') || det.contains(':6666') || det.contains(':1337') || det.contains(':31337') || det.contains(':9001') || det.contains(':8080') || det.contains(':80') || det.contains(':443') || det.contains('port') || mid.contains('t1071') || mid.contains('t1095') || mid.contains('t1041') || (hasIp && (ev.contains('beacon') || ev.contains('c2') || ev.contains('traffic') || ev.contains('connection')));
  }

  bool _isFileAlert(Map<String, dynamic> a) {
    String src = (a['source'] ?? '').toString().toLowerCase();
    String ls = (a['log_source'] ?? '').toString().toLowerCase();
    String ev = (a['event'] ?? '').toString().toLowerCase();
    String det = (a['detail'] ?? '').toString().toLowerCase();
    String mid = (a['mitre_id'] ?? '').toString().toLowerCase();
    return src == 'sysmon_file' || src == 'canary' || ev.contains('file') || ev.contains('drop') || ev.contains('ransomware') || ev.contains('canary') || ev.contains('shadow copy') || det.contains('file') || det.contains('canary') || det.contains('vssadmin') || det.contains('dropped') || mid.contains('t1204.002') || mid.contains('t1486') || mid.contains('t1490');
  }

  bool _isRegAlert(Map<String, dynamic> a) {
    String src = (a['source'] ?? '').toString().toLowerCase();
    String ls = (a['log_source'] ?? '').toString().toLowerCase();
    String ev = (a['event'] ?? '').toString().toLowerCase();
    String det = (a['detail'] ?? '').toString().toLowerCase();
    String mid = (a['mitre_id'] ?? '').toString().toLowerCase();
    return src == 'registry' || ls.contains('reg') || ev.contains('registry') || ev.contains('persistence') || ev.contains('runkey') || ev.contains('run key') || ev.contains('reg.exe') || det.contains('hkcu') || det.contains('hklm') || det.contains(r'currentversion\\run') || det.contains('runonce') || det.contains('autorun') || det.contains('registry') || det.contains('reg add') || mid.contains('t1547') || mid.contains('t1070.004');
  }

  Widget _buildAlertWarningBox(String title, Color c) {
    return Container(
      padding: const EdgeInsets.all(12),
      margin: const EdgeInsets.only(bottom: 12),
      decoration: BoxDecoration(color: c.withOpacity(0.1), border: Border.all(color: c.withOpacity(0.5)), borderRadius: BorderRadius.circular(4)),
      child: Text(title, style: TextStyle(color: c, fontSize: 11)),
    );
  }
}
"""

if "_isExeAlert" not in content:
    content = content[:content.rfind('}')] + helpers

cases = """
      case '9': 
        List<dynamic> exes = _alerts.where((a) => _isExeAlert(a)).toList();
        int cCrit = exes.where((a) => (a['severity']??'').toString().toUpperCase() == 'CRITICAL').length;
        return Padding(
          padding: const EdgeInsets.all(12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              _buildAlertWarningBox('Rule R001 TRIGGERED: ${exes.length} EXE alert(s) detected ($cCrit CRITICAL). EXE files from \\\\Temp\\\\ or \\\\AppData\\\\ are high-risk — malware drops payloads to these writable directories.', const Color(0xFFFF3B30)),
              _buildBox('Detected Suspicious Executables', 'EID 1 — Rule R001 — Click Open for full telemetry', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
                showCheckboxColumn: false, headingRowHeight: 30, dataRowMinHeight: 45, dataRowMaxHeight: 45, columnSpacing: 16,
                headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold),
                dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
                columns: const [DataColumn(label: Text('TIME')), DataColumn(label: Text('EVENT')), DataColumn(label: Text('HOST')), DataColumn(label: Text('USER')), DataColumn(label: Text('MITRE')), DataColumn(label: Text('SEVERITY')), DataColumn(label: Text('ACTION'))],
                rows: exes.take(15).map((a) {
                  String sev = (a['severity'] ?? 'LOW').toString().toUpperCase();
                  Color sCol = sev == 'CRITICAL' ? const Color(0xFFFF3B30) : (sev == 'HIGH' ? Colors.orange : (sev == 'MEDIUM' ? Colors.amber : const Color(0xFF32ade6)));
                  return DataRow(onSelectChanged: (v) { if(v==true) Navigator.push(context, MaterialPageRoute(builder: (_) => AlertDetailScreen(alert: a))); }, cells: [
                    DataCell(Text((a['timestamp'] ?? '').toString().split(' ').last)),
                    DataCell(Text((a['event'] ?? '').toString(), style: const TextStyle(color: Color(0xFFFF3B30)))),
                    DataCell(Text((a['host'] ?? '').toString())),
                    DataCell(Text((a['user'] ?? '').toString())),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: const Color(0xFF30363d), borderRadius: BorderRadius.circular(10)), child: Text((a['mitre'] ?? 'T1204.002').toString(), style: const TextStyle(color: Color(0xFF58a6ff), fontSize: 9)))),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: sCol.withOpacity(0.15), border: Border.all(color: sCol.withOpacity(0.5)), borderRadius: BorderRadius.circular(10)), child: Text(sev, style: TextStyle(color: sCol, fontSize: 9, fontWeight: FontWeight.bold)))),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:8,vertical:4), decoration: BoxDecoration(border: Border.all(color: const Color(0xFF32ade6)), borderRadius: BorderRadius.circular(2)), child: const Text('Open', style: TextStyle(color: Color(0xFF32ade6), fontSize: 9)))),
                  ]);
                }).toList(),
              )))
            ]
          )
        );

      case '10':
        List<dynamic> pss = _alerts.where((a) => _isPsAlert(a)).toList();
        int hCrit = pss.where((a) { var s = (a['severity']??'').toString().toUpperCase(); return s == 'HIGH' || s == 'CRITICAL'; }).length;
        return Padding(
          padding: const EdgeInsets.all(12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              _buildAlertWarningBox('DETECTED: ${pss.length} PowerShell alert(s) — $hCrit HIGH/CRITICAL. Base64-encoded commands hide malicious payloads from AV and log analysis.', const Color(0xFFFF3B30)),
              _buildBox('PowerShell Suspicious Events', 'EID 1 — Rule R002 — Click Open for payload decoding', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
                showCheckboxColumn: false, headingRowHeight: 30, dataRowMinHeight: 45, dataRowMaxHeight: 45, columnSpacing: 16,
                headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold),
                dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
                columns: const [DataColumn(label: Text('TIME')), DataColumn(label: Text('HOST')), DataColumn(label: Text('USER')), DataColumn(label: Text('COMMANDLINE PREVIEW')), DataColumn(label: Text('MITRE')), DataColumn(label: Text('SEVERITY')), DataColumn(label: Text('ACTION'))],
                rows: pss.take(15).map((a) {
                  String sev = (a['severity'] ?? 'LOW').toString().toUpperCase();
                  Color sCol = sev == 'CRITICAL' ? const Color(0xFFFF3B30) : (sev == 'HIGH' ? Colors.orange : (sev == 'MEDIUM' ? Colors.amber : const Color(0xFF32ade6)));
                  List<String> detLines = (a['detail'] ?? '').toString().split(r'\\n');
                  String cmd = detLines.firstWhere((l) => l.toLowerCase().contains('cmdline') || l.toLowerCase().contains('-enc') || l.toLowerCase().contains('powershell'), orElse: () => detLines.isNotEmpty ? detLines[0] : (a['event']??'').toString());
                  if (cmd.length > 50) cmd = cmd.substring(0, 50) + '...';
                  return DataRow(onSelectChanged: (v) { if(v==true) Navigator.push(context, MaterialPageRoute(builder: (_) => AlertDetailScreen(alert: a))); }, cells: [
                    DataCell(Text((a['timestamp'] ?? '').toString().split(' ').last)),
                    DataCell(Text((a['host'] ?? '').toString())),
                    DataCell(Text((a['user'] ?? '').toString())),
                    DataCell(Text(cmd, style: const TextStyle(color: Color(0xFFFF3B30)))),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: const Color(0xFF30363d), borderRadius: BorderRadius.circular(10)), child: Text((a['mitre'] ?? 'T1059.001').toString(), style: const TextStyle(color: Color(0xFF58a6ff), fontSize: 9)))),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: sCol.withOpacity(0.15), border: Border.all(color: sCol.withOpacity(0.5)), borderRadius: BorderRadius.circular(10)), child: Text(sev, style: TextStyle(color: sCol, fontSize: 9, fontWeight: FontWeight.bold)))),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:8,vertical:4), decoration: BoxDecoration(border: Border.all(color: const Color(0xFF32ade6)), borderRadius: BorderRadius.circular(2)), child: const Text('Open', style: TextStyle(color: Color(0xFF32ade6), fontSize: 9)))),
                  ]);
                }).toList(),
              )))
            ]
          )
        );

      case '11':
        List<dynamic> nets = _alerts.where((a) => _isNetAlert(a)).toList();
        List<dynamic> c2s = nets.where((a) { String dt = ((a['detail']??'') + ' ' + (a['event']??'')).toString(); return dt.contains(':4444')||dt.contains(':6666')||dt.contains(' 4444 ')||dt.contains(' 6666 ')||dt.contains(':1337'); }).toList();
        int ips = nets.map((a) => a['ip']).where((ip) => ip != null && ip != '-').toSet().length;
        return Padding(
          padding: const EdgeInsets.all(12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              _buildAlertWarningBox('SUSPICIOUS NETWORK ACTIVITY: ${nets.length} connection alert(s) detected — ${c2s.length} possible C2 beacon(s). Review and block immediately.', const Color(0xFFFF3B30)),
              GridView.count(crossAxisCount: 2, crossAxisSpacing: 8, mainAxisSpacing: 8, childAspectRatio: 2.5, shrinkWrap: true, physics: const NeverScrollableScrollPhysics(), children: [
                _buildStatCard('TOTAL CONNECTIONS', '${nets.length}', 'Flagged events', Colors.white), 
                _buildStatCard('C2 BEACONS', '${c2s.length}', 'Bad ports', const Color(0xFFFF3B30)), 
                _buildStatCard('UNIQUE IPS', '$ips', 'External IPs', Colors.orange), 
                _buildStatCard('BLOCKED IPS', '0', 'Firewall blocked', const Color(0xFF30d158)),
              ]),
              const SizedBox(height: 12),
              _buildBox('Suspicious Connections', 'EID 3 — all flagged network events — Click row to inspect or block', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
                showCheckboxColumn: false, headingRowHeight: 30, dataRowMinHeight: 45, dataRowMaxHeight: 45, columnSpacing: 16,
                headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold),
                dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
                columns: const [DataColumn(label: Text('TIME')), DataColumn(label: Text('PROCESS')), DataColumn(label: Text('DST IP')), DataColumn(label: Text('PORT')), DataColumn(label: Text('RISK')), DataColumn(label: Text('SEVERITY')), DataColumn(label: Text('ACTION'))],
                rows: nets.take(15).map((a) {
                  String sev = (a['severity'] ?? 'LOW').toString().toUpperCase();
                  Color sCol = sev == 'CRITICAL' ? const Color(0xFFFF3B30) : (sev == 'HIGH' ? Colors.orange : (sev == 'MEDIUM' ? Colors.amber : const Color(0xFF32ade6)));
                  String port = '4444'; 
                  if (a['detail'].toString().contains(':')) {
                     var match = RegExp(r':(\d{2,5})').firstMatch(a['detail'].toString());
                     if (match != null) port = match.group(1)!;
                  }
                  bool isC2 = ['4444','6666','1337','31337','9001','8443'].contains(port);
                  return DataRow(onSelectChanged: (v) { if(v==true) Navigator.push(context, MaterialPageRoute(builder: (_) => AlertDetailScreen(alert: a))); }, cells: [
                    DataCell(Text((a['timestamp'] ?? '').toString().split(' ').last)),
                    DataCell(Text((a['event'] ?? '').toString().toLowerCase().contains('powershell') ? 'powershell.exe' : (a['event'] ?? 'unknown.exe').toString())),
                    DataCell(Text((a['ip'] ?? '-').toString())),
                    DataCell(Text(port, style: TextStyle(color: isC2 ? const Color(0xFFFF3B30) : Colors.white))),
                    DataCell(Text(isC2 ? 'C2/RAT Port' : 'Suspicious', style: TextStyle(color: isC2 ? const Color(0xFFFF3B30) : Colors.orange))),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: sCol.withOpacity(0.15), border: Border.all(color: sCol.withOpacity(0.5)), borderRadius: BorderRadius.circular(10)), child: Text(sev, style: TextStyle(color: sCol, fontSize: 9, fontWeight: FontWeight.bold)))),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:8,vertical:4), decoration: BoxDecoration(border: Border.all(color: const Color(0xFF32ade6)), borderRadius: BorderRadius.circular(2)), child: const Text('Open', style: TextStyle(color: Color(0xFF32ade6), fontSize: 9)))),
                  ]);
                }).toList(),
              )))
            ]
          )
        );

      case '12':
        List<dynamic> files = _alerts.where((a) => _isFileAlert(a)).toList();
        return Padding(
          padding: const EdgeInsets.all(12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              _buildAlertWarningBox('FILE INTEGRITY ALERTS: ${files.length} suspicious file drop or canary event(s) detected.', const Color(0xFFFF3B30)),
              _buildBox('Suspicious File Creation Events', 'EID 11 — File Create — high-risk paths flagged', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
                showCheckboxColumn: false, headingRowHeight: 30, dataRowMinHeight: 45, dataRowMaxHeight: 45, columnSpacing: 16,
                headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold),
                dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
                columns: const [DataColumn(label: Text('TIME')), DataColumn(label: Text('FILE CREATED')), DataColumn(label: Text('CREATED BY')), DataColumn(label: Text('MITRE')), DataColumn(label: Text('SEVERITY')), DataColumn(label: Text('ACTION'))],
                rows: files.take(15).map((a) {
                  String sev = (a['severity'] ?? 'LOW').toString().toUpperCase();
                  Color sCol = sev == 'CRITICAL' ? const Color(0xFFFF3B30) : (sev == 'HIGH' ? Colors.orange : (sev == 'MEDIUM' ? Colors.amber : const Color(0xFF32ade6)));
                  String fileN = (a['detail'] ?? '').toString().split(r'\\n')[0];
                  if (fileN.length > 40) fileN = fileN.substring(0, 40) + '...';
                  if (fileN.isEmpty) fileN = (a['event'] ?? '').toString();
                  return DataRow(onSelectChanged: (v) { if(v==true) Navigator.push(context, MaterialPageRoute(builder: (_) => AlertDetailScreen(alert: a))); }, cells: [
                    DataCell(Text((a['timestamp'] ?? '').toString().split(' ').last)),
                    DataCell(Text(fileN, style: TextStyle(color: sev == 'CRITICAL' ? const Color(0xFFFF3B30) : (sev == 'HIGH' ? Colors.orange : Colors.white)))),
                    DataCell(Text((a['user'] ?? '-').toString())),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: const Color(0xFF30363d), borderRadius: BorderRadius.circular(10)), child: Text((a['mitre'] ?? 'T1059.001').toString(), style: const TextStyle(color: Color(0xFF58a6ff), fontSize: 9)))),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: sCol.withOpacity(0.15), border: Border.all(color: sCol.withOpacity(0.5)), borderRadius: BorderRadius.circular(10)), child: Text(sev, style: TextStyle(color: sCol, fontSize: 9, fontWeight: FontWeight.bold)))),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:8,vertical:4), decoration: BoxDecoration(border: Border.all(color: const Color(0xFF32ade6)), borderRadius: BorderRadius.circular(2)), child: const Text('Open', style: TextStyle(color: Color(0xFF32ade6), fontSize: 9)))),
                  ]);
                }).toList(),
              )))
            ]
          )
        );

      case '13':
        List<dynamic> regs = _alerts.where((a) => _isRegAlert(a)).toList();
        int rcrit = regs.where((a) => (a['severity']??'').toString().toUpperCase() == 'CRITICAL').length;
        return Padding(
          padding: const EdgeInsets.all(12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              _buildAlertWarningBox('ALERT: ${regs.length} registry persistence event(s) detected — $rcrit CRITICAL. Registry Run key modifications ensure malware auto-starts on every Windows boot.', const Color(0xFFFF3B30)),
              _buildBox('Registry Events', 'EID 12 (Create) — EID 13 (Set) — EID 14 (Rename)', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
                showCheckboxColumn: false, headingRowHeight: 30, dataRowMinHeight: 45, dataRowMaxHeight: 45, columnSpacing: 16,
                headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold),
                dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
                columns: const [DataColumn(label: Text('TIME')), DataColumn(label: Text('REGISTRY KEY / VALUE')), DataColumn(label: Text('EVENT')), DataColumn(label: Text('MITRE')), DataColumn(label: Text('SEVERITY')), DataColumn(label: Text('ACTION'))],
                rows: regs.take(15).map((a) {
                  String sev = (a['severity'] ?? 'LOW').toString().toUpperCase();
                  Color sCol = sev == 'CRITICAL' ? const Color(0xFFFF3B30) : (sev == 'HIGH' ? Colors.orange : (sev == 'MEDIUM' ? Colors.amber : const Color(0xFF32ade6)));
                  String regK = (a['detail'] ?? '').toString().split(r'\\n')[0];
                  if (regK.length > 40) regK = regK.substring(0, 40) + '...';
                  if (regK.isEmpty) regK = '-';
                  return DataRow(onSelectChanged: (v) { if(v==true) Navigator.push(context, MaterialPageRoute(builder: (_) => AlertDetailScreen(alert: a))); }, cells: [
                    DataCell(Text((a['timestamp'] ?? '').toString().split(' ').last)),
                    DataCell(Text(regK, style: const TextStyle(color: Colors.white))),
                    DataCell(Text((a['event'] ?? '').toString(), style: const TextStyle(color: Color(0xFF32ade6)))),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: const Color(0xFF30363d), borderRadius: BorderRadius.circular(10)), child: Text((a['mitre'] ?? 'T1547.001').toString(), style: const TextStyle(color: Color(0xFF58a6ff), fontSize: 9)))),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: sCol.withOpacity(0.15), border: Border.all(color: sCol.withOpacity(0.5)), borderRadius: BorderRadius.circular(10)), child: Text(sev, style: TextStyle(color: sCol, fontSize: 9, fontWeight: FontWeight.bold)))),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:8,vertical:4), decoration: BoxDecoration(border: Border.all(color: const Color(0xFF32ade6)), borderRadius: BorderRadius.circular(2)), child: const Text('Open', style: TextStyle(color: Color(0xFF32ade6), fontSize: 9)))),
                  ]);
                }).toList(),
              )))
            ]
          )
        );
"""

if "case '9':" not in content:
    content = content.replace("default: return const Center(child: Text('Data Loading...'));", cases + "\\n      default: return const Center(child: Text('Data Loading...'));")

with open('sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as dest:
    dest.write(content)
