with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/advanced_soc_playbook_screens.dart', 'r', encoding='utf-8') as f:
    text = f.read()

start = text.find('class PlaybookBuilderScreen extends StatefulWidget')
if start != -1:
    text = text[:start]

new_code = """class PlaybookBuilderScreen extends StatefulWidget {
  const PlaybookBuilderScreen({Key? key}) : super(key: key);
  @override
  State<PlaybookBuilderScreen> createState() => _PlaybookBuilderScreenState();
}

class _PlaybookBuilderScreenState extends State<PlaybookBuilderScreen> {
  final TextEditingController nameCtrl = TextEditingController();
  final TextEditingController triggerCtrl = TextEditingController();
  final TextEditingController severityCtrl = TextEditingController();
  List<Map<String, dynamic>> playbooks = [];

  void _savePlaybook() {
    if (nameCtrl.text.isEmpty) return;
    setState(() {
      playbooks.add({
        'name': nameCtrl.text,
        'trigger': triggerCtrl.text.isEmpty ? 'T1059.001' : triggerCtrl.text,
        'severity': severityCtrl.text.isEmpty ? 'MEDIUM' : severityCtrl.text,
        'conditions': 0,
        'actions': 1,
        'createdBy': 'admin'
      });
      nameCtrl.clear();
      triggerCtrl.clear();
      severityCtrl.clear();
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
          const Text('No conditions — playbook matches on trigger alone.', style: TextStyle(color: Colors.white70, fontSize: 11)),
          const SizedBox(height: 8),
          Align(alignment: Alignment.centerLeft, child: OutlinedButton.icon(
            style: OutlinedButton.styleFrom(side: const BorderSide(color: Colors.white24), foregroundColor: Colors.white),
            onPressed: (){}, icon: const Icon(Icons.add, size: 16), label: const Text('Add Condition'))),
          const SizedBox(height: 16),
          const Text('ACTIONS', style: TextStyle(color: Colors.white54, fontSize: 10, fontWeight: FontWeight.bold)),
          const SizedBox(height: 4),
          const Text('No actions yet — add at least one, or this playbook will never do anything.', style: TextStyle(color: Colors.white70, fontSize: 11)),
          const SizedBox(height: 8),
          Align(alignment: Alignment.centerLeft, child: OutlinedButton.icon(
            style: OutlinedButton.styleFrom(side: const BorderSide(color: Colors.white24), foregroundColor: Colors.white),
            onPressed: (){}, icon: const Icon(Icons.add, size: 16), label: const Text('Add Action'))),
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
"""
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/advanced_soc_playbook_screens.dart', 'w', encoding='utf-8') as f:
    f.write(text + new_code)
