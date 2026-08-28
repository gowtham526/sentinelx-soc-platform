import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix case 23 telemetry button
old_telemetry_btn = "ElevatedButton(onPressed: (){}, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), foregroundColor: const Color(0xFF32ade6), side: const BorderSide(color: Color(0xFF32ade6))), child: const Text('🔍 Open Detailed Telemetry ↗', style: TextStyle(fontSize: 10)))"
new_telemetry_btn = """ElevatedButton(onPressed: (){
    if (_alerts.isNotEmpty) {
        Navigator.push(context, MaterialPageRoute(builder: (_) => AlertDetailScreen(alert: _alerts.first))).then((_) => _loadDashboardData());
    } else {
        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('No active alerts to inspect')));
    }
}, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), foregroundColor: const Color(0xFF32ade6), side: const BorderSide(color: Color(0xFF32ade6))), child: const Text('🔍 Open Detailed Telemetry ↗', style: TextStyle(fontSize: 10)))"""
content = content.replace(old_telemetry_btn, new_telemetry_btn)

# Add AI Ranked Threat Queue to case 23
old_case_23_end = """child: const Text('⚡ Recommended Action: Isolate host nani123, terminate parent PID, and sinkhole external IoC.', style: TextStyle(color: Colors.orange, fontSize: 10)))),
        ]));"""
new_case_23_end = """child: const Text('⚡ Recommended Action: Isolate host nani123, terminate parent PID, and sinkhole external IoC.', style: TextStyle(color: Colors.orange, fontSize: 10)))),
          const SizedBox(height: 12),
          _buildBox('AI Ranked Threat Queue (${_alerts.length} alerts analyzed)', 'Correlated severity ranking', 
            SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
              showCheckboxColumn: false, headingRowHeight: 30, columnSpacing: 16,
              headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold), 
              dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
              columns: const [
                  DataColumn(label: Text('AI SCORE')), 
                  DataColumn(label: Text('SEVERITY')), 
                  DataColumn(label: Text('DETECTION EVENT')), 
                  DataColumn(label: Text('MITRE ATT&CK')), 
                  DataColumn(label: Text('HOST')), 
                  DataColumn(label: Text('USER')), 
                  DataColumn(label: Text('ACTION'))
              ],
              rows: _alerts.map((a) {
                  int aiScore = a['severity'] == 'CRITICAL' ? 91 : (a['severity'] == 'HIGH' ? 68 : 42);
                  String aiScoreStr = '$aiScore / 100';
                  Color sevCol = a['severity'] == 'CRITICAL' ? const Color(0xFFFF3B30) : (a['severity'] == 'HIGH' ? Colors.orange : Colors.amber);
                  
                  return DataRow(
                    cells: [
                      DataCell(Text(aiScoreStr, style: TextStyle(color: sevCol, fontWeight: FontWeight.bold))),
                      DataCell(Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(color: sevCol.withOpacity(0.15), border: Border.all(color: sevCol.withOpacity(0.5)), borderRadius: BorderRadius.circular(4)), child: Text((a['severity'] ?? 'UNKNOWN').toString(), style: TextStyle(color: sevCol, fontSize: 8)))),
                      DataCell(Text((a['event'] ?? 'Unknown Event').toString())),
                      DataCell(Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(color: const Color(0xFF32ade6).withOpacity(0.15), border: Border.all(color: const Color(0xFF32ade6).withOpacity(0.5)), borderRadius: BorderRadius.circular(4)), child: Text(((a['mitre_id'] ?? '-') + ' ' + (a['tactic'] ?? '')).toString(), style: const TextStyle(color: Color(0xFF32ade6), fontSize: 8)))),
                      DataCell(Text((a['hostname'] ?? 'unknown').toString())),
                      DataCell(Text((a['user'] ?? 'unknown').toString())),
                      DataCell(ElevatedButton(
                        onPressed: () {
                           Navigator.push(context, MaterialPageRoute(builder: (_) => AlertDetailScreen(alert: a))).then((_) => _loadDashboardData());
                        },
                        style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), foregroundColor: const Color(0xFF32ade6), side: const BorderSide(color: Color(0xFF32ade6))),
                        child: const Text('Inspect', style: TextStyle(fontSize: 9))
                      ))
                    ]
                  );
              }).toList()
            ))
          )
        ]));"""
content = content.replace(old_case_23_end, new_case_23_end)

# Fix case 25 Simulate button
old_sim_btn = "ElevatedButton(onPressed: (){}, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), foregroundColor: const Color(0xFFFF3B30), side: const BorderSide(color: Color(0xFFFF3B30))), child: const Text('🚨 Simulate C2 Attack', style: TextStyle(fontSize: 10)))"
new_sim_btn = "ElevatedButton(onPressed: _showSimulateDialog, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), foregroundColor: const Color(0xFFFF3B30), side: const BorderSide(color: Color(0xFFFF3B30))), child: const Text('🚨 Simulate C2 Attack', style: TextStyle(fontSize: 10)))"
content = content.replace(old_sim_btn, new_sim_btn)


with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(content)
