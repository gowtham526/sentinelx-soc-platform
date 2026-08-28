import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

# Add _events variable
if 'List<dynamic> _events = [];' not in text:
    text = text.replace('List<dynamic> _alerts = [];', 'List<dynamic> _alerts = [];\n  List<dynamic> _events = [];')

# Modify _fetchData to fetch events
if 'ApiService.fetchEventsStream()' not in text:
    fetch_func = '''Future<void> _fetchData() async {
    final alerts = await ApiService.fetchAlerts();
    final events = await ApiService.fetchEventsStream();
    if (mounted) {
      setState(() {
        _alerts = alerts;
        _events = events;
      });
    }
  }'''
    # Replace the existing _fetchData completely
    text = re.sub(r'Future<void> _fetchData\(\) async \{[\s\S]*?\}\n  \}', fetch_func, text)


# Replace case '7':
new_case_7 = '''case '7': return Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(children: [
              Expanded(child: _buildStatCard('EVENTS BUFFERED', '${_events.length}', 'In-memory ring buffer', Colors.white)), const SizedBox(width: 8),
              Expanded(child: _buildStatCard('UNIQUE PROCESSES', '${_events.map((e) => e['process_name']).toSet().length}', 'Active executables', const Color(0xFF32ade6))),
            ]),
            const SizedBox(height: 8),
            Row(children: [
              Expanded(child: _buildStatCard('NETWORK / LOLBINS', '${_events.where((e) => e['event_id'].toString().startsWith('3')).length}', 'Sockets & tools', Colors.orange)), const SizedBox(width: 8),
              Expanded(child: _buildStatCard('STREAM HEALTH', 'LIVE', 'Sub-second telemetry', const Color(0xFF30d158))),
            ]),
            const SizedBox(height: 12),
            _buildBox('Live Endpoint Telemetry Stream', 'Ingesting real-time process creations', SingleChildScrollView(
              scrollDirection: Axis.horizontal,
              child: DataTable(
                headingRowHeight: 30, columnSpacing: 16,
                headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold),
                dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
                columns: const [DataColumn(label: Text('TIMESTAMP')), DataColumn(label: Text('EVENT ID')), DataColumn(label: Text('PROCESS NAME')), DataColumn(label: Text('PID')), DataColumn(label: Text('COMMAND LINE')), DataColumn(label: Text('USER')), DataColumn(label: Text('INSPECT'))],
                rows: _events.take(30).map((e) => DataRow(cells: [
                  DataCell(Text((e['timestamp'] ?? '').split('T').last.split('.').first)),
                  DataCell(Container(padding: const EdgeInsets.all(2), color: Colors.orange.withOpacity(0.2), child: Text('EID ${e['event_id']}: ${e['type']}', style: const TextStyle(color: Colors.orange, fontSize: 8)))),
                  DataCell(Text(e['process_name'] ?? 'Unknown', style: const TextStyle(color: Color(0xFF30d158)))),
                  DataCell(Text(e['pid']?.toString() ?? '-')),
                  DataCell(SizedBox(width: 200, child: Text(e['command_line'] ?? '-', overflow: TextOverflow.ellipsis))),
                  DataCell(Text(e['user'] ?? 'System')),
                  DataCell(InkWell(
                    onTap: () {
                      showDialog(context: context, builder: (_) => AlertDialog(
                        backgroundColor: const Color(0xFF161b22),
                        title: const Text('Event Inspector', style: TextStyle(color: Colors.white)),
                        content: SingleChildScrollView(child: Text(e.toString(), style: const TextStyle(color: Colors.green, fontSize: 12, fontFamily: 'monospace'))),
                        actions: [TextButton(onPressed: () => Navigator.pop(context), child: const Text('Close'))]
                      ));
                    },
                    child: Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(border: Border.all(color: const Color(0xFF32ade6)), borderRadius: BorderRadius.circular(4)), child: const Text('Inspect', style: TextStyle(color: Color(0xFF32ade6), fontSize: 9))))
                  ),
                ])).toList(),
              ),
            )),
          ],
        )
      );'''

text = re.sub(r"case '7': return Padding\([\s\S]*?\);\n\n      // M3 - SLIDE 8", new_case_7 + '\n\n      // M3 - SLIDE 8', text)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)
print('Patched dashboard_screen.dart to render dynamic events on Slide 7')
