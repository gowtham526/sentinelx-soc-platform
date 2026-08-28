import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

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

# Find case '17'
m17 = re.search(r"case '17':.*?(?=case '20':)", text, re.DOTALL)
if m17:
    replacement = m17.group(0) + case_18
    text = text.replace(m17.group(0), replacement)
else:
    print("Could not find case '17'")

# Find case '21'
m21 = re.search(r"case '21':.*?(?=case '23':)", text, re.DOTALL)
if m21:
    replacement = m21.group(0) + case_22
    text = text.replace(m21.group(0), replacement)
else:
    print("Could not find case '21'")

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)
print("Inserted case 18 and 22.")
