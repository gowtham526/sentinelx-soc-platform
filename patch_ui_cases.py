import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    content = f.read()

# Add case 20 and case 21
new_cases = """
      case '20':
        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Row(children: [
            Expanded(child: _buildBox('USERS TRACKED', 'From alerts', const Text('2', style: TextStyle(color: Color(0xFF32ade6), fontSize: 24, fontWeight: FontWeight.bold)))),
            const SizedBox(width: 12),
            Expanded(child: _buildBox('HIGH RISK', 'CRITICAL activity', const Text('2', style: TextStyle(color: Color(0xFFFF3B30), fontSize: 24, fontWeight: FontWeight.bold)))),
            const SizedBox(width: 12),
            Expanded(child: _buildBox('TOTAL ALERTS', 'All users', const Text('59', style: TextStyle(color: Color(0xFF32ade6), fontSize: 24, fontWeight: FontWeight.bold)))),
          ]),
          const SizedBox(height: 12),
          Expanded(child: _buildBox('User: katre', 'Recent Alerts', Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
             _buildDetailRow('Total Alerts', '47'),
             _buildDetailRow('Critical', '19'),
             _buildDetailRow('High', '27'),
             _buildDetailRow('Hosts', 'nani123'),
             _buildDetailRow('Tactics Seen', 'Initial Access, Execution, Persistence'),
          ]))),
          const SizedBox(height: 12),
          Expanded(child: _buildBox('User: NANI123\\\\katre', 'Recent Alerts', Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
             _buildDetailRow('Total Alerts', '12'),
             _buildDetailRow('Critical', '1'),
             _buildDetailRow('High', '4'),
             _buildDetailRow('Hosts', 'nani123'),
             _buildDetailRow('Tactics Seen', 'Execution, Command and Control'),
          ]))),
        ]));

      case '21':
        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Container(
            padding: const EdgeInsets.all(12), decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(4), border: Border.all(color: const Color(0xFF2a2f3a))),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              const Text('UNIFIED CONTAINMENT & THREAT NEUTRALIZATION CONSOLE', style: TextStyle(color: Color(0xFFFF3B30), fontSize: 11, fontWeight: FontWeight.bold)),
              const SizedBox(height: 12),
              Row(children: [
                 Expanded(child: TextField(
                   style: const TextStyle(color: Colors.white, fontSize: 11, fontFamily: 'monospace'),
                   decoration: InputDecoration(
                     isDense: true, contentPadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
                     hintText: 'Enter IP to block, Domain to sinkhole, or PID to kill...',
                     hintStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9),
                     filled: true, fillColor: Colors.black54, border: OutlineInputBorder(borderRadius: BorderRadius.circular(4), borderSide: BorderSide.none),
                   ),
                 )),
                 const SizedBox(width: 8),
                 ElevatedButton(onPressed: (){
                    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Executing Action... Done!'), backgroundColor: const Color(0xFF30d158)));
                 }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFFFF3B30), foregroundColor: Colors.white, padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12)), child: const Text('Execute Action', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 10))),
              ]),
              const SizedBox(height: 8),
              Row(children: [
                const Text('Quick Targets:', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9)), const SizedBox(width: 8),
                _buildMapChip('powershell.exe'), _buildMapChip('cmd.exe'), _buildMapChip('185.220.101.5')
              ])
            ])
          ),
          const SizedBox(height: 12),
          Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Expanded(child: _buildBox('Firewall Blocklist & Sinkhole Rules', 'Active kernel firewall & network rules', const Padding(
               padding: EdgeInsets.all(20), child: Text('No entries blocked yet', style: TextStyle(color: Color(0xFF8b949e), fontSize: 11))
            ))),
            const SizedBox(width: 12),
            Expanded(child: _buildBox('Incident Lifecycle & Remediation', 'CHAIN-810021 - MEDIUM', Column(children: [
               _buildDetailRow('Host Status', 'nani123 (Monitoring active)'),
               _buildDetailRow('Containment Rules', '0 firewall blocks active'),
               _buildDetailRow('Open Alerts', '59 detection events'),
               const SizedBox(height: 12),
               ElevatedButton(onPressed: (){}, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), foregroundColor: const Color(0xFF30d158), side: const BorderSide(color: Color(0xFF30d158))), child: const Text('Resolve & Close Incident'))
            ])))
          ])
        ]));

      default: return const Center(child: Text('Data Loading...'));"""

content = re.sub(r'default: return const Center\(child: Text\(\'Data Loading\.\.\.\'\)\);', new_cases.replace('\\', '\\\\'), content, flags=re.DOTALL)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(content)
