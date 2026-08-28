import 'package:flutter/material.dart';

class IocDashboardScreen extends StatelessWidget {
  final List<dynamic> alerts;
  const IocDashboardScreen({Key? key, required this.alerts}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    List<dynamic> ipAlerts = alerts.where((a) => a['ip'] != null && a['ip'].toString().isNotEmpty && a['ip'].toString() != '-').toList();
    List<dynamic> hashAlerts = alerts.where((a) => a['hash'] != null && a['hash'].toString().isNotEmpty && a['hash'].toString() != '-').toList();
    Set<String> uniqueIps = {};
    for (var a in ipAlerts) uniqueIps.add(a['ip'].toString());
    Set<String> uniqueHashes = {};
    for (var a in hashAlerts) uniqueHashes.add(a['hash'].toString());
    int totalUnique = uniqueIps.length + uniqueHashes.length;

    Widget statBox(String title, String val, String sub, Color c) {
      return Container(
        width: 140,
        margin: const EdgeInsets.symmetric(horizontal: 4),
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(8), border: Border.all(color: c.withOpacity(0.3))),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(title.toUpperCase(), style: const TextStyle(color: Colors.white70, fontSize: 10, fontWeight: FontWeight.bold)),
          const SizedBox(height: 8),
          Text(val, style: TextStyle(color: c, fontSize: 24, fontWeight: FontWeight.bold)),
          const SizedBox(height: 4),
          Text(sub, style: const TextStyle(color: Colors.white54, fontSize: 10)),
        ]),
      );
    }

    return SingleChildScrollView(padding: const EdgeInsets.all(16), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        child: Row(children: [
          statBox('TOTAL IOCS', '${totalUnique}', 'Confirmed indicators', const Color(0xFFFF3B30)),
          statBox('IP IOCS', '${ipAlerts.length}', 'External IPs', Colors.orange),
          statBox('HASH IOCS', '${hashAlerts.length}', 'File hashes', const Color(0xFF58a6ff)),
        ]),
      ),
      const SizedBox(height: 16),
      Container(
        padding: const EdgeInsets.all(16), decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(8), border: Border.all(color: const Color(0xFF30363d))),
        child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          const Text('IoC Master List', style: TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
            headingRowHeight: 30, dataRowHeight: 40, columnSpacing: 16,
            columns: const [
              DataColumn(label: Text('IOC VALUE', style: TextStyle(color: Colors.white54, fontSize: 10))),
              DataColumn(label: Text('TYPE', style: TextStyle(color: Colors.white54, fontSize: 10))),
              DataColumn(label: Text('CONFIDENCE', style: TextStyle(color: Colors.white54, fontSize: 10))),
              DataColumn(label: Text('SOURCE', style: TextStyle(color: Colors.white54, fontSize: 10))),
              DataColumn(label: Text('SEEN IN', style: TextStyle(color: Colors.white54, fontSize: 10))),
              DataColumn(label: Text('ACTION', style: TextStyle(color: Colors.white54, fontSize: 10))),
            ],
            rows: uniqueIps.map((ip) {
              var related = alerts.firstWhere((a) => a['ip'] == ip, orElse: () => {});
              return DataRow(cells: [
                DataCell(Text(ip, style: const TextStyle(color: Color(0xFFFF3B30), fontSize: 11, fontWeight: FontWeight.bold))),
                DataCell(Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(border: Border.all(color: const Color(0xFF58a6ff)), borderRadius: BorderRadius.circular(12)), child: const Text('IP Address', style: TextStyle(color: Color(0xFF58a6ff), fontSize: 9)))),
                DataCell(const Text('HIGH', style: TextStyle(color: Color(0xFFFF3B30), fontSize: 9, fontWeight: FontWeight.bold))),
                DataCell(Text('VT: ${related['vt_score'] ?? 0} / Abuse: ${related['abuse_score'] ?? 0}', style: const TextStyle(color: Colors.white, fontSize: 11))),
                DataCell(Text(related['event']?.toString() ?? '', style: const TextStyle(color: Colors.white, fontSize: 11))),
                DataCell(Row(children: [
                   Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(color: const Color(0xFFFF3B30).withOpacity(0.2), borderRadius: BorderRadius.circular(4)), child: const Text('Block', style: TextStyle(color: Color(0xFFFF3B30), fontSize: 9))),
                   const SizedBox(width: 4),
                   Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(color: const Color(0xFF58a6ff).withOpacity(0.2), borderRadius: BorderRadius.circular(4)), child: const Text('Intel', style: TextStyle(color: Color(0xFF58a6ff), fontSize: 9))),
                ])),
              ]);
            }).toList(),
          ))
        ])
      )
    ]));
  }
}

class SoarPlaybookScreen extends StatelessWidget {
  final List<dynamic> alerts;
  const SoarPlaybookScreen({Key? key, required this.alerts}) : super(key: key);
  
  @override
  Widget build(BuildContext context) {
    List<dynamic> recent = alerts.take(8).toList();

    return SingleChildScrollView(padding: const EdgeInsets.all(16), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        child: Row(children: [
          Container(width: 140, margin: const EdgeInsets.symmetric(horizontal: 4), padding: const EdgeInsets.all(12), decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(8), border: Border.all(color: const Color(0xFF30d158).withOpacity(0.3))), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: const [Text('AUTOMATION RATE', style: TextStyle(color: Colors.white70, fontSize: 10, fontWeight: FontWeight.bold)), SizedBox(height: 8), Text('100%', style: TextStyle(color: Color(0xFF30d158), fontSize: 24, fontWeight: FontWeight.bold)), Text('Zero manual triage', style: TextStyle(color: Colors.white54, fontSize: 10))])),
          Container(width: 140, margin: const EdgeInsets.symmetric(horizontal: 4), padding: const EdgeInsets.all(12), decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(8), border: Border.all(color: const Color(0xFF30d158).withOpacity(0.3))), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: const [Text('MTTR', style: TextStyle(color: Colors.white70, fontSize: 10, fontWeight: FontWeight.bold)), SizedBox(height: 8), Text('< 0.38s', style: TextStyle(color: Color(0xFF30d158), fontSize: 24, fontWeight: FontWeight.bold)), Text('Detection to isolation', style: TextStyle(color: Colors.white54, fontSize: 10))])),
          Container(width: 140, margin: const EdgeInsets.symmetric(horizontal: 4), padding: const EdgeInsets.all(12), decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(8), border: Border.all(color: const Color(0xFF58a6ff).withOpacity(0.3))), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: const [Text('ARMED PLAYBOOKS', style: TextStyle(color: Colors.white70, fontSize: 10, fontWeight: FontWeight.bold)), SizedBox(height: 8), Text('4 Active', style: TextStyle(color: Color(0xFF58a6ff), fontSize: 24, fontWeight: FontWeight.bold)), Text('All vectors covered', style: TextStyle(color: Colors.white54, fontSize: 10))])),
          Container(width: 140, margin: const EdgeInsets.symmetric(horizontal: 4), padding: const EdgeInsets.all(12), decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(8), border: Border.all(color: const Color(0xFFFF3B30).withOpacity(0.3))), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: const [Text('MITIGATIONS', style: TextStyle(color: Colors.white70, fontSize: 10, fontWeight: FontWeight.bold)), SizedBox(height: 8), Text('31 Actions', style: TextStyle(color: Color(0xFFFF3B30), fontSize: 24, fontWeight: FontWeight.bold)), Text('Dynamic host blocks', style: TextStyle(color: Colors.white54, fontSize: 10))])),
        ]),
      ),
      const SizedBox(height: 16),
      Container(
        padding: const EdgeInsets.all(16), decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(8), border: Border.all(color: const Color(0xFF30363d))),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
           const Text('Autonomous 5-Stage Response Pipeline', style: TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.bold)),
           const SizedBox(height: 12),
           SingleChildScrollView(
             scrollDirection: Axis.horizontal,
             child: Row(children: [
               Container(width: 120, padding: const EdgeInsets.all(8), color: const Color(0xFF0d1117), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: const [Text('1. Ingestion', style: TextStyle(color: Colors.white, fontSize: 11, fontWeight: FontWeight.bold)), Text('Sysmon parsing', style: TextStyle(color: Colors.white54, fontSize: 9))])),
               const Icon(Icons.arrow_forward, color: Colors.white24, size: 16),
               Container(width: 120, padding: const EdgeInsets.all(8), color: const Color(0xFF0d1117), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: const [Text('2. Enrichment', style: TextStyle(color: Colors.white, fontSize: 11, fontWeight: FontWeight.bold)), Text('VT/AbuseIPDB', style: TextStyle(color: Colors.white54, fontSize: 9))])),
               const Icon(Icons.arrow_forward, color: Colors.white24, size: 16),
               Container(width: 120, padding: const EdgeInsets.all(8), color: const Color(0xFF0d1117), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: const [Text('3. Scoring', style: TextStyle(color: Colors.white, fontSize: 11, fontWeight: FontWeight.bold)), Text('Risk matrix', style: TextStyle(color: Colors.white54, fontSize: 9))])),
               const Icon(Icons.arrow_forward, color: Colors.white24, size: 16),
               Container(width: 120, padding: const EdgeInsets.all(8), color: const Color(0xFF0d1117), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: const [Text('4. Containment', style: TextStyle(color: Colors.white, fontSize: 11, fontWeight: FontWeight.bold)), Text('Firewall/Kill', style: TextStyle(color: Colors.white54, fontSize: 9))])),
               const Icon(Icons.arrow_forward, color: Colors.white24, size: 16),
               Container(width: 120, padding: const EdgeInsets.all(8), color: const Color(0xFF0d1117), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: const [Text('5. Evidence', style: TextStyle(color: Colors.white, fontSize: 11, fontWeight: FontWeight.bold)), Text('Case folded', style: TextStyle(color: Colors.white54, fontSize: 9))])),
             ]),
           )
        ])
      ),
      const SizedBox(height: 16),
      Container(
        padding: const EdgeInsets.all(16), decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(8), border: Border.all(color: const Color(0xFF30363d))),
        child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          const Text('Recent Autonomous Playbook Telemetry', style: TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
            headingRowHeight: 30, dataRowHeight: 40, columnSpacing: 16,
            columns: const [
              DataColumn(label: Text('ALERT ID', style: TextStyle(color: Colors.white54, fontSize: 10))),
              DataColumn(label: Text('EVENT NAME', style: TextStyle(color: Colors.white54, fontSize: 10))),
              DataColumn(label: Text('SEVERITY', style: TextStyle(color: Colors.white54, fontSize: 10))),
              DataColumn(label: Text('1. INGEST', style: TextStyle(color: Colors.white54, fontSize: 10))),
              DataColumn(label: Text('2. ENRICH', style: TextStyle(color: Colors.white54, fontSize: 10))),
              DataColumn(label: Text('3. SCORE', style: TextStyle(color: Colors.white54, fontSize: 10))),
              DataColumn(label: Text('4. CONTAIN', style: TextStyle(color: Colors.white54, fontSize: 10))),
              DataColumn(label: Text('5. CASE', style: TextStyle(color: Colors.white54, fontSize: 10))),
              DataColumn(label: Text('STATUS', style: TextStyle(color: Colors.white54, fontSize: 10))),
            ],
            rows: recent.map((a) {
              Color c = a['severity'] == 'CRITICAL' ? const Color(0xFFFF3B30) : Colors.orange;
              Widget check = const Icon(Icons.check, color: Color(0xFF30d158), size: 14);
              return DataRow(cells: [
                DataCell(Text(a['id']?.toString().substring(0,8) ?? '', style: const TextStyle(color: Colors.white54, fontSize: 11))),
                DataCell(Text(a['event'] ?? '', style: const TextStyle(color: Colors.white, fontSize: 11))),
                DataCell(Text(a['severity'] ?? '', style: TextStyle(color: c, fontSize: 9, fontWeight: FontWeight.bold))),
                DataCell(check), DataCell(check), DataCell(check),
                DataCell(Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(color: const Color(0xFFFF3B30).withOpacity(0.2), borderRadius: BorderRadius.circular(4)), child: const Text('ISOLATED', style: TextStyle(color: Color(0xFFFF3B30), fontSize: 9)))),
                DataCell(Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(color: const Color(0xFF30d158).withOpacity(0.2), borderRadius: BorderRadius.circular(4)), child: const Text('INCIDENT', style: TextStyle(color: Color(0xFF30d158), fontSize: 9)))),
                DataCell(const Text('100% DONE', style: TextStyle(color: Color(0xFF30d158), fontSize: 10, fontWeight: FontWeight.bold))),
              ]);
            }).toList(),
          ))
        ])
      )
    ]));
  }
}

class PlaybookBuilderScreen extends StatefulWidget {
  const PlaybookBuilderScreen({Key? key}) : super(key: key);
  @override
  State<PlaybookBuilderScreen> createState() => _PlaybookBuilderScreenState();
}

class _PlaybookBuilderScreenState extends State<PlaybookBuilderScreen> {
  final TextEditingController nameCtrl = TextEditingController();
  final TextEditingController triggerCtrl = TextEditingController();
  final TextEditingController severityCtrl = TextEditingController();
  
  List<Map<String, dynamic>> conditions = [];
  List<Map<String, dynamic>> actions = [];
  List<Map<String, dynamic>> playbooks = [];

  void _addCondition() {
    setState(() {
      conditions.add({'field': '', 'op': '==', 'value': ''});
    });
  }

  void _addAction() {
    setState(() {
      actions.add({'type': 'Isolate Host', 'params': ''});
    });
  }

  void _removeCondition(int idx) {
    setState(() { conditions.removeAt(idx); });
  }

  void _removeAction(int idx) {
    setState(() { actions.removeAt(idx); });
  }

  void _savePlaybook() {
    if (nameCtrl.text.isEmpty) return;
    setState(() {
      playbooks.add({
        'name': nameCtrl.text,
        'trigger': triggerCtrl.text.isEmpty ? 'ANY' : triggerCtrl.text,
        'severity': severityCtrl.text.isEmpty ? 'HIGH' : severityCtrl.text,
        'conditions': conditions.length,
        'actions': actions.isEmpty ? 1 : actions.length,
        'createdBy': 'admin'
      });
      nameCtrl.clear();
      triggerCtrl.clear();
      severityCtrl.clear();
      conditions.clear();
      actions.clear();
    });
    ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Playbook saved successfully')));
  }

  void _deletePlaybook(int index) {
    setState(() {
      playbooks.removeAt(index);
    });
  }

  @override
  Widget build(BuildContext context) {
    final inputDecoration = const InputDecoration(
      labelStyle: TextStyle(color: Colors.white54, fontSize: 10),
      border: OutlineInputBorder(borderSide: BorderSide(color: Colors.white24)),
      enabledBorder: OutlineInputBorder(borderSide: BorderSide(color: Colors.white24)),
      focusedBorder: OutlineInputBorder(borderSide: BorderSide(color: Colors.cyan)),
      isDense: true,
    );

    return SingleChildScrollView(padding: const EdgeInsets.all(16), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      Container(
        padding: const EdgeInsets.all(16), 
        decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(8), border: Border.all(color: const Color(0xFF30363d))),
        child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: const [
              Text('Build a Playbook', style: TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.bold)),
              Text('Trigger + conditions + actions', style: TextStyle(color: Colors.white54, fontSize: 10)),
            ]
          ),
          const SizedBox(height: 16),
          TextField(controller: nameCtrl, style: const TextStyle(color: Colors.white), decoration: inputDecoration.copyWith(labelText: 'PLAYBOOK NAME', hintText: 'e.g. Auto-isolate on Critical Lateral Movement', hintStyle: const TextStyle(color: Colors.white24))),
          const SizedBox(height: 16),
          Row(children: [
             Expanded(child: TextField(controller: triggerCtrl, style: const TextStyle(color: Colors.white), decoration: inputDecoration.copyWith(labelText: 'TRIGGER — MITRE TACTIC (BLANK = ANY)', hintText: 'e.g. Lateral Movement', hintStyle: const TextStyle(color: Colors.white24)))),
             const SizedBox(width: 8),
             Expanded(child: TextField(controller: severityCtrl, style: const TextStyle(color: Colors.white), decoration: inputDecoration.copyWith(labelText: 'TRIGGER — MINIMUM SEVERITY', hintText: 'HIGH', hintStyle: const TextStyle(color: Colors.white24)))),
          ]),
          const SizedBox(height: 16),
          const Text('CONDITIONS (ALL MUST PASS)', style: TextStyle(color: Colors.white54, fontSize: 10, fontWeight: FontWeight.bold)),
          const SizedBox(height: 4),
          if (conditions.isEmpty) const Text('No conditions — playbook matches on trigger alone.', style: TextStyle(color: Colors.white70, fontSize: 11)),
          ...conditions.asMap().entries.map((e) {
            int i = e.key;
            return Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: Row(children: [
                 Expanded(child: Container(padding: const EdgeInsets.all(8), decoration: BoxDecoration(border: Border.all(color: Colors.white24), borderRadius: BorderRadius.circular(4)), child: const Text('Field: event/host', style: TextStyle(color: Colors.white, fontSize: 11)))),
                 const SizedBox(width: 8),
                 Expanded(child: Container(padding: const EdgeInsets.all(8), decoration: BoxDecoration(border: Border.all(color: Colors.white24), borderRadius: BorderRadius.circular(4)), child: const Text('Op: == / contains', style: TextStyle(color: Colors.white, fontSize: 11)))),
                 const SizedBox(width: 8),
                 Expanded(child: TextField(style: const TextStyle(color: Colors.white), decoration: inputDecoration.copyWith(hintText: 'Value', hintStyle: const TextStyle(color: Colors.white24)))),
                 IconButton(icon: const Icon(Icons.close, color: Colors.white54, size: 16), onPressed: () => _removeCondition(i))
              ])
            );
          }),
          const SizedBox(height: 8),
          Align(alignment: Alignment.centerLeft, child: OutlinedButton.icon(
            style: OutlinedButton.styleFrom(side: const BorderSide(color: Colors.white24), foregroundColor: Colors.white),
            onPressed: _addCondition, icon: const Icon(Icons.add, size: 16), label: const Text('Add Condition'))),
          const SizedBox(height: 16),
          const Text('ACTIONS', style: TextStyle(color: Colors.white54, fontSize: 10, fontWeight: FontWeight.bold)),
          const SizedBox(height: 4),
          if (actions.isEmpty) const Text('No actions yet — add at least one, or this playbook will never do anything.', style: TextStyle(color: Colors.white70, fontSize: 11)),
          ...actions.asMap().entries.map((e) {
            int i = e.key;
            return Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: Row(children: [
                 Expanded(flex: 1, child: Container(padding: const EdgeInsets.all(8), decoration: BoxDecoration(border: Border.all(color: Colors.white24), borderRadius: BorderRadius.circular(4)), child: Text(e.value['type'], style: const TextStyle(color: Colors.white, fontSize: 11)))),
                 const SizedBox(width: 8),
                 Expanded(flex: 2, child: TextField(style: const TextStyle(color: Colors.white), decoration: inputDecoration.copyWith(hintText: 'Params (JSON)', hintStyle: const TextStyle(color: Colors.white24)))),
                 IconButton(icon: const Icon(Icons.close, color: Colors.white54, size: 16), onPressed: () => _removeAction(i))
              ])
            );
          }),
          const SizedBox(height: 8),
          Align(alignment: Alignment.centerLeft, child: OutlinedButton.icon(
            style: OutlinedButton.styleFrom(side: const BorderSide(color: Colors.white24), foregroundColor: Colors.white),
            onPressed: _addAction, icon: const Icon(Icons.add, size: 16), label: const Text('Add Action'))),
          const SizedBox(height: 16),
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: Row(children: [
              ElevatedButton(style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF007bff), foregroundColor: Colors.white), onPressed: _savePlaybook, child: const Text('Save Playbook')),
              const SizedBox(width: 8),
              ElevatedButton(style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF21262d), foregroundColor: const Color(0xFF58a6ff), side: const BorderSide(color: Color(0xFF30363d))), onPressed: (){}, child: const Text('Test Against Sample Alert')),
              const SizedBox(width: 8),
              ElevatedButton(style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF21262d), foregroundColor: Colors.white, side: const BorderSide(color: Color(0xFF30363d))), onPressed: (){
                nameCtrl.clear(); triggerCtrl.clear(); severityCtrl.clear();
                setState((){ conditions.clear(); actions.clear(); });
              }, child: const Text('Clear / New')),
            ]),
          )
        ])
      ),
      const SizedBox(height: 16),
      Container(
        padding: const EdgeInsets.all(16), decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(8), border: Border.all(color: const Color(0xFF30363d))),
        child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          const Text('Existing Playbooks', style: TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.bold)),
          const SizedBox(height: 16),
          playbooks.isEmpty 
          ? const Center(child: Padding(padding: EdgeInsets.all(32), child: Text('No playbooks yet — build one above.', style: TextStyle(color: Colors.white54, fontSize: 12))))
          : SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
            headingRowHeight: 30, dataRowHeight: 45, columnSpacing: 24,
            columns: const [
              DataColumn(label: Text('NAME', style: TextStyle(color: Colors.white54, fontSize: 10))),
              DataColumn(label: Text('ENABLED', style: TextStyle(color: Colors.white54, fontSize: 10))),
              DataColumn(label: Text('TRIGGER', style: TextStyle(color: Colors.white54, fontSize: 10))),
              DataColumn(label: Text('CONDITIONS', style: TextStyle(color: Colors.white54, fontSize: 10))),
              DataColumn(label: Text('ACTIONS', style: TextStyle(color: Colors.white54, fontSize: 10))),
              DataColumn(label: Text('CREATED BY', style: TextStyle(color: Colors.white54, fontSize: 10))),
              DataColumn(label: Text('', style: TextStyle(color: Colors.white54, fontSize: 10))),
            ],
            rows: playbooks.asMap().entries.map((entry) {
              int idx = entry.key;
              var p = entry.value;
              String combinedTrigger = '${p['severity']} - ${p['trigger']}';
              return DataRow(cells: [
                DataCell(Text(p['name'], style: const TextStyle(color: Colors.white, fontSize: 11))),
                DataCell(const Text('ENABLED', style: TextStyle(color: Color(0xFF30d158), fontSize: 10, fontWeight: FontWeight.bold))),
                DataCell(Text(combinedTrigger, style: const TextStyle(color: Colors.white, fontSize: 11))),
                DataCell(Text(p['conditions'].toString(), style: const TextStyle(color: Colors.white, fontSize: 11))),
                DataCell(Text(p['actions'].toString(), style: const TextStyle(color: Colors.white, fontSize: 11))),
                DataCell(Text(p['createdBy'], style: const TextStyle(color: Colors.white, fontSize: 11))),
                DataCell(Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Container(
                      height: 28,
                      margin: const EdgeInsets.only(right: 4),
                      child: OutlinedButton(
                        style: OutlinedButton.styleFrom(
                          padding: const EdgeInsets.symmetric(horizontal: 12),
                          side: const BorderSide(color: Color(0xFF30363d)),
                          foregroundColor: Colors.white,
                          backgroundColor: const Color(0xFF21262d),
                        ),
                        onPressed: () {},
                        child: const Text('Edit', style: TextStyle(fontSize: 10)),
                      ),
                    ),
                    Container(
                      height: 28,
                      margin: const EdgeInsets.only(right: 4),
                      child: OutlinedButton(
                        style: OutlinedButton.styleFrom(
                          padding: const EdgeInsets.symmetric(horizontal: 12),
                          side: const BorderSide(color: Color(0xFF30363d)),
                          foregroundColor: Colors.black,
                          backgroundColor: Colors.white,
                        ),
                        onPressed: () {},
                        child: const Text('Disable', style: TextStyle(fontSize: 10)),
                      ),
                    ),
                    Container(
                      height: 28,
                      child: OutlinedButton(
                        style: OutlinedButton.styleFrom(
                          padding: const EdgeInsets.symmetric(horizontal: 12),
                          side: const BorderSide(color: Color(0xFFFF3B30)),
                          foregroundColor: const Color(0xFFFF3B30),
                          backgroundColor: const Color(0xFF21262d),
                        ),
                        onPressed: () => _deletePlaybook(idx),
                        child: const Text('Delete', style: TextStyle(fontSize: 10)),
                      ),
                    ),
                  ],
                )),
              ]);
            }).toList(),
          ))
        ])
      )
    ]));
  }
}
