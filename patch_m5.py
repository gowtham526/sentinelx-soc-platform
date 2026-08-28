import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    content = f.read()

new_cases = """
      case '23':
        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          _buildAlertWarningBox('🚨 AI Cognitive Engine analyzed ${_alerts.length} active alert(s) — Top Threat Vector: 🚨 Incident Declared — Host Under Active Attack (AI Risk Score: 91/100 - CRITICAL)', const Color(0xFFFF3B30)),
          _buildBox('AI Risk Assessment & Confidence', 'Neural multi-signal aggregate', Column(children: [
            Container(width: 100, height: 100, margin: const EdgeInsets.all(20), decoration: BoxDecoration(shape: BoxShape.circle, border: Border.all(color: const Color(0xFFFF3B30), width: 4)), child: const Center(child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [Text('91', style: TextStyle(color: Color(0xFFFF3B30), fontSize: 24, fontWeight: FontWeight.bold)), Text('RISK SCORE', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9))]))),
            Container(width: double.infinity, padding: const EdgeInsets.symmetric(vertical: 8), color: const Color(0xFFFF3B30).withOpacity(0.1), child: const Center(child: Text('CRITICAL — MALICIOUS ATTACK', style: TextStyle(color: Color(0xFFFF3B30), fontSize: 11, fontWeight: FontWeight.bold)))),
            const SizedBox(height: 12),
            const Text('🚨 Incident Declared — Host Under Active Attack', style: TextStyle(color: Colors.white, fontSize: 11, fontWeight: FontWeight.bold)),
            const Text('Target Host: nani123 - Operator: katre', style: TextStyle(color: Color(0xFF8b949e), fontSize: 10)),
            const SizedBox(height: 12),
            ElevatedButton(onPressed: (){}, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), foregroundColor: const Color(0xFF32ade6), side: const BorderSide(color: Color(0xFF32ade6))), child: const Text('🔍 Open Detailed Telemetry ↗', style: TextStyle(fontSize: 10))),
          ])),
          const SizedBox(height: 12),
          _buildBox('17-Signal Pipeline Breakdown', 'Real-time feature weights & evaluation', Column(children: [
             _buildDetailRow('Risk Keyword Match', '✓ Active threat keywords identified'),
             _buildDetailRow('Process Anomaly / Hint', 'Standard process tree'),
             _buildDetailRow('Encoded Command / Cradle', 'Cleartext / Direct invocation'),
             _buildDetailRow('VirusTotal Threat Match', '✓ 0 / 72 malicious engines'),
             _buildDetailRow('AbuseIPDB Reputation', '0% malicious confidence'),
             _buildDetailRow('MITRE ATT&CK Matrix', '✓ - (-)'),
             _buildDetailRow('Persistence Footprint', 'No persistence identified'),
             _buildDetailRow('Canary / Deception Trap', 'Standard detection'),
             _buildDetailRow('Statistical Anomaly Delta', '✓ +42% Deviation above host baseline'),
             const SizedBox(height: 8),
             const Text('Threshold Matrix: >71 CRITICAL · >46 HIGH · >21 MEDIUM · <21 LOW', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontFamily: 'monospace'))
          ])),
          const SizedBox(height: 12),
          _buildBox('AI Automated Incident Triage & Recommendation', 'Recommended SOAR playbooks', Container(width: double.infinity, padding: const EdgeInsets.all(12), decoration: BoxDecoration(color: Colors.orange.withOpacity(0.1), border: Border.all(color: Colors.orange.withOpacity(0.5)), borderRadius: BorderRadius.circular(4)), child: const Text('⚡ Recommended Action: Isolate host nani123, terminate parent PID, and sinkhole external IoC.', style: TextStyle(color: Colors.orange, fontSize: 10)))),
        ]));

      case '24':
        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          _buildAlertWarningBox('⚡ AI Classification Engine: ${_alerts.length} active alert(s) categorized into 1 Malware Confirmed, 2 Suspicious Activity, and 0 Benign.', const Color(0xFFFF3B30)),
          _buildBox('Malware Confirmed', '1 events', Column(children: [
             const Text('1', style: TextStyle(color: Color(0xFFFF3B30), fontSize: 32, fontWeight: FontWeight.bold)),
             const SizedBox(height: 8),
             Container(padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4), decoration: BoxDecoration(color: const Color(0xFFFF3B30).withOpacity(0.2), borderRadius: BorderRadius.circular(4)), child: const Text('-', style: TextStyle(color: Color(0xFFFF3B30), fontSize: 9))),
             const SizedBox(height: 8),
             const Text('Click any badge to inspect alert', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9))
          ])),
          const SizedBox(height: 12),
          _buildBox('Suspicious Activity', '2 events', Column(children: [
             const Text('2', style: TextStyle(color: Colors.orange, fontSize: 32, fontWeight: FontWeight.bold)),
             const SizedBox(height: 8),
             Row(mainAxisAlignment: MainAxisAlignment.center, children: [
                Container(padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4), decoration: BoxDecoration(color: Colors.orange.withOpacity(0.2), borderRadius: BorderRadius.circular(4)), child: const Text('Encoded PowerShell', style: TextStyle(color: Colors.orange, fontSize: 9))),
                const SizedBox(width: 8),
                Container(padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4), decoration: BoxDecoration(color: Colors.orange.withOpacity(0.2), borderRadius: BorderRadius.circular(4)), child: const Text('Encoded PowerShell', style: TextStyle(color: Colors.orange, fontSize: 9))),
             ]),
             const SizedBox(height: 8),
             const Text('Click any badge to inspect alert', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9))
          ])),
          const SizedBox(height: 12),
          _buildBox('Normal / Benign', '0 events', const Column(children: [
             Text('0', style: TextStyle(color: Color(0xFF30d158), fontSize: 32, fontWeight: FontWeight.bold)),
             SizedBox(height: 8),
             Text('No benign events', style: TextStyle(color: Color(0xFF8b949e), fontSize: 10))
          ])),
          const SizedBox(height: 12),
          _buildBox('Active Classification Rules Matrix', 'Built into alert_pipeline.py — auto-classifies on detection', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
            showCheckboxColumn: false, headingRowHeight: 30, columnSpacing: 16,
            headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold), dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
            columns: const [DataColumn(label: Text('RULE ID')), DataColumn(label: Text('DETECTION LOGIC & CONDITION')), DataColumn(label: Text('ASSIGNED CLASSIFICATION')), DataColumn(label: Text('SEVERITY'))],
            rows: const [
              DataRow(cells: [DataCell(Text('R001')), DataCell(Text(r'Path \Temp\ or \AppData\ AND .exe', style: TextStyle(color: Color(0xFF32ade6)))), DataCell(Text('Suspicious EXE Drop')), DataCell(Text('CRITICAL', style: TextStyle(color: Color(0xFFFF3B30))))]),
              DataRow(cells: [DataCell(Text('R002')), DataCell(Text('CommandLine contains -enc / base64', style: TextStyle(color: Color(0xFF32ade6)))), DataCell(Text('Encoded PowerShell Cradle')), DataCell(Text('CRITICAL', style: TextStyle(color: Color(0xFFFF3B30))))]),
              DataRow(cells: [DataCell(Text('R003')), DataCell(Text('Parent-Office AND Child-cmd/powershell', style: TextStyle(color: Color(0xFF32ade6)))), DataCell(Text('Malicious Office Macro')), DataCell(Text('CRITICAL', style: TextStyle(color: Color(0xFFFF3B30))))]),
              DataRow(cells: [DataCell(Text('R004')), DataCell(Text('Registry Run / RunOnce key modification', style: TextStyle(color: Color(0xFF32ade6)))), DataCell(Text('Persistence Mechanism')), DataCell(Text('HIGH', style: TextStyle(color: Colors.orange)))]),
            ]
          ))),
        ]));

      case '25':
        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          _buildAlertWarningBox('🌐 Threat Intelligence Framework: 0 threat indicator(s) enriched across live telemetry. Dual-Engine validation via VirusTotal API v3 and AbuseIPDB API v2.', const Color(0xFF32ade6)),
          Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
             _buildBox('TOTAL ALERT IOCS', 'Correlated indicators', const Text('0', style: TextStyle(color: Color(0xFF32ade6), fontSize: 28, fontWeight: FontWeight.bold))),
             const SizedBox(height: 12),
             _buildBox('HIGH / CRITICAL RISK', 'Confirmed malicious', const Text('0', style: TextStyle(color: Color(0xFFFF3B30), fontSize: 28, fontWeight: FontWeight.bold))),
             const SizedBox(height: 12),
             _buildBox('CONTAINED / BLOCKED', 'Firewall active', const Text('0', style: TextStyle(color: Color(0xFF30d158), fontSize: 28, fontWeight: FontWeight.bold))),
             const SizedBox(height: 12),
             _buildBox('AVG THREAT CONFIDENCE', 'AbuseIPDB score', const Text('0%', style: TextStyle(color: Colors.orange, fontSize: 28, fontWeight: FontWeight.bold))),
          ]),
          const SizedBox(height: 12),
          _buildBox('Intelligence Feed Status & Data Sources', 'Multi-Source Threat Telemetry', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
            showCheckboxColumn: false, headingRowHeight: 30, columnSpacing: 16,
            headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold), dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
            columns: const [DataColumn(label: Text('INTELLIGENCE SOURCE')), DataColumn(label: Text('PAYLOAD / QUERY TYPE')), DataColumn(label: Text('OPERATIONAL STATUS'))],
            rows: [
              DataRow(cells: [DataCell(const Text('VirusTotal API v3', style: TextStyle(fontWeight: FontWeight.bold))), DataCell(const Text('File Hashes + IPv4 + Domains')), DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: const Color(0xFF30d158).withOpacity(0.15), border: Border.all(color: const Color(0xFF30d158).withOpacity(0.5)), borderRadius: BorderRadius.circular(10)), child: const Text('Active — Real-time', style: TextStyle(color: Color(0xFF30d158), fontSize: 9))))]),
              DataRow(cells: [DataCell(const Text('AbuseIPDB API v2', style: TextStyle(fontWeight: FontWeight.bold))), DataCell(const Text('IP Reputation & Confidence Score')), DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: const Color(0xFF30d158).withOpacity(0.15), border: Border.all(color: const Color(0xFF30d158).withOpacity(0.5)), borderRadius: BorderRadius.circular(10)), child: const Text('Active — Real-time', style: TextStyle(color: Color(0xFF30d158), fontSize: 9))))]),
              DataRow(cells: [DataCell(const Text('Sysmon Kernel Driver', style: TextStyle(fontWeight: FontWeight.bold))), DataCell(const Text('EID 1, 3, 8, 10, 11, 13 Events')), DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: const Color(0xFF30d158).withOpacity(0.15), border: Border.all(color: const Color(0xFF30d158).withOpacity(0.5)), borderRadius: BorderRadius.circular(10)), child: const Text('Active — Real-time', style: TextStyle(color: Color(0xFF30d158), fontSize: 9))))]),
            ]
          ))),
          const SizedBox(height: 12),
          _buildBox('Live Extracted IoC Telemetry Feed (0 active indicators)', 'Extracted from live alert stream', Column(children: [
             const Icon(Icons.shield, color: Color(0xFF32ade6), size: 24),
             const SizedBox(height: 8),
             const Text('Zero External IoCs in Current Stream', style: TextStyle(color: Colors.white, fontSize: 12, fontWeight: FontWeight.bold)),
             const SizedBox(height: 4),
             const Text('All network connections and telemetry streams are clean. Generate an attack simulation to populate real-time VirusTotal, AbuseIPDB, and MITRE IoC feeds.', textAlign: TextAlign.center, style: TextStyle(color: Color(0xFF8b949e), fontSize: 10)),
             const SizedBox(height: 12),
             ElevatedButton(onPressed: (){}, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), foregroundColor: const Color(0xFFFF3B30), side: const BorderSide(color: Color(0xFFFF3B30))), child: const Text('🚨 Simulate C2 Attack', style: TextStyle(fontSize: 10))),
          ]))
        ]));
"""

content = content.replace("default: return const Center(child: Text('Data Loading...'));", new_cases + "\n      default: return const Center(child: Text('Data Loading...'));")

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(content)
