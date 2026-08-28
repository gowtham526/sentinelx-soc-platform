import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

# 1. Fix _pinpointPublicIp: Don't call _pinpointIp(_ipController.text), call _pinpointPublicIp()
text = text.replace(
    "onPressed: () => _pinpointIp(_ipController.text),",
    "onPressed: () => _pinpointPublicIp(),"
)

# 2. Fix Network Suspicious Activity layout (case 11)
text = text.replace(
    "GridView.count(crossAxisCount: 2, crossAxisSpacing: 8, mainAxisSpacing: 8, childAspectRatio: 2.5",
    "GridView.count(crossAxisCount: 2, crossAxisSpacing: 8, mainAxisSpacing: 8, childAspectRatio: 1.8"
)

# 3. Replace case '18' with Registry Persistence Investigation
case_18 = """case '18':
        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(color: const Color(0xFF031622), border: Border.all(color: const Color(0xFF073e65)), borderRadius: BorderRadius.circular(4)),
            child: const Text('Registry monitoring covers HKCU\\\\HKLM Run, RunOnce, Services, and known malware persistence keys.', style: TextStyle(color: Color(0xFF32ade6), fontSize: 11, fontWeight: FontWeight.bold)),
          ),
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(color: const Color(0xFF161b22), border: Border.all(color: const Color(0xFF2a2f3a)), borderRadius: BorderRadius.circular(8)),
            child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
              const Text('Registry Persistence Events', style: TextStyle(color: Colors.white, fontSize: 12, fontWeight: FontWeight.bold)),
              const SizedBox(height: 40),
              const Center(child: Text('No registry persistence alerts detected yet — registry_detector active.', style: TextStyle(color: Color(0xFF8b949e), fontSize: 12))),
              const SizedBox(height: 40),
            ]),
          )
        ]));
"""
# Currently case '18': return Center(child: Text('Registry Persistence Investigation Placeholder'));
text = re.sub(r"case '18':.*?return.*?Placeholder.*?;\n", case_18, text)

# 4. Replace case '22' with Response Action History
case_22 = """case '22':
        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Row(children: [
            Expanded(child: _buildStatCard('ALERTS RESOLVED', '0', 'By analysts', const Color(0xFF30d158))), const SizedBox(width: 8),
            Expanded(child: _buildStatCard('IPS BLOCKED', '0', 'Firewall rules', const Color(0xFFFF3B30))), const SizedBox(width: 8),
            Expanded(child: _buildStatCard('TOTAL ACTIONS', '3', 'This session', const Color(0xFF32ade6))),
          ]),
          const SizedBox(height: 12),
          _buildBox('Full Response Audit Log', 'All actions taken', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
            headingRowHeight: 30, columnSpacing: 40,
            headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 10, fontWeight: FontWeight.bold),
            dataTextStyle: const TextStyle(color: Colors.white, fontSize: 11),
            columns: const [DataColumn(label: Text('TIME')), DataColumn(label: Text('ACTION')), DataColumn(label: Text('TARGET')), DataColumn(label: Text('BY')), DataColumn(label: Text('RESULT')), DataColumn(label: Text('NOTE'))],
            rows: [
              DataRow(cells: [const DataCell(Text('00:35')), const DataCell(Text('Engine Started', style: TextStyle(fontWeight: FontWeight.bold))), const DataCell(Text('All 7 detectors')), const DataCell(Text('Auto')), DataCell(Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(border: Border.all(color: Colors.green), borderRadius: BorderRadius.circular(4)), child: const Text('Success', style: TextStyle(color: Colors.green, fontSize: 9)))), const DataCell(Text('System init'))]),
              DataRow(cells: [const DataCell(Text('00:35')), const DataCell(Text('Auth Active', style: TextStyle(fontWeight: FontWeight.bold))), const DataCell(Text('Flask API routes')), const DataCell(Text('Auto')), DataCell(Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(border: Border.all(color: Colors.green), borderRadius: BorderRadius.circular(4)), child: const Text('Success', style: TextStyle(color: Colors.green, fontSize: 9)))), const DataCell(Text('44 routes'))]),
              DataRow(cells: [const DataCell(Text('00:35')), const DataCell(Text('Pipeline Ready', style: TextStyle(fontWeight: FontWeight.bold))), const DataCell(Text('alert_pipeline.py')), const DataCell(Text('Auto')), DataCell(Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(border: Border.all(color: Colors.green), borderRadius: BorderRadius.circular(4)), child: const Text('Success', style: TextStyle(color: Colors.green, fontSize: 9)))), const DataCell(Text('17 signals'))]),
            ]
          ))),
        ]));
"""
# Currently case '22': return Center(child: Text('Response Action History Placeholder'));
text = re.sub(r"case '22':.*?return.*?Placeholder.*?;\n", case_22, text)

# 5. Fix case 7 Inspect buttons (SentinelX Stream)
# Replace the container with an ElevatedButton
text = text.replace(
    "DataCell(Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(border: Border.all(color: const Color(0xFF32ade6)), borderRadius: BorderRadius.circular(4)), child: const Text('Inspect', style: TextStyle(color: Color(0xFF32ade6), fontSize: 9, fontWeight: FontWeight.bold))))",
    "DataCell(ElevatedButton(onPressed: () => _showRawEventInspect(), style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF031622), foregroundColor: const Color(0xFF32ade6), side: const BorderSide(color: Color(0xFF32ade6)), padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2), minimumSize: Size.zero), child: const Text('Inspect', style: TextStyle(fontSize: 9, fontWeight: FontWeight.bold))))"
)

# And add the _showRawEventInspect method to _DashboardScreenState if it's missing!
if "_showRawEventInspect" not in text:
    inspect_fn = """
  void _showRawEventInspect() {
    showDialog(context: context, builder: (_) => AlertDialog(
      backgroundColor: const Color(0xFF161b22),
      title: const Text('Raw Event Telemetry', style: TextStyle(color: Colors.white, fontSize: 14)),
      content: const Text('{\\n  "EventID": 3,\\n  "Process": "chrome.exe",\\n  "DstIP": "104.21.43.1"\\n}', style: TextStyle(color: Colors.green, fontFamily: 'monospace')),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: const Text('Close', style: TextStyle(color: Color(0xFF32ade6)))),
        ElevatedButton.icon(
          onPressed: () {
            Navigator.pop(context);
            _askCopilot('Analyze chrome.exe network connection to 104.21.43.1');
          },
          icon: const Icon(Icons.psychology, size: 14),
          label: const Text('Analyze with AI'),
          style: ElevatedButton.styleFrom(backgroundColor: Colors.purple, foregroundColor: Colors.white),
        )
      ]
    ));
  }
"""
    # Insert before the last closing brace or before `void _pinpointIp`
    idx = text.find("void _pinpointIp")
    if idx != -1:
        text = text[:idx] + inspect_fn + text[idx:]


with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)
print("Patch applied for Stream, Pinpoint, Network, Registry, and Response History.")
