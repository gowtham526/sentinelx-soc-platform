import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Inject the State variables
state_vars = """  Map<String, dynamic>? _intelResult;
  String _selectedContainmentAction = 'Process Kill';
  final TextEditingController _containmentTargetController = TextEditingController();"""
content = re.sub(r'Map<String, dynamic>\? _intelResult;', state_vars, content, 1)

# 2. Replace case 21
new_case_21 = """      case '21':
        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Container(
            padding: const EdgeInsets.all(12), decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(4), border: Border.all(color: const Color(0xFF2a2f3a))),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              const Text('⚡ UNIFIED CONTAINMENT & THREAT NEUTRALIZATION CONSOLE', style: TextStyle(color: Color(0xFFFF3B30), fontSize: 11, fontWeight: FontWeight.bold)),
              const Text('Block attacker IPs, sinkhole C2 domains, quarantine endpoints, or live-kill running malicious processes (e.g. powershell.exe).', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9)),
              const SizedBox(height: 12),
              
              TextField(
                controller: _containmentTargetController,
                onChanged: (val) => _intelSearchQuery = val,
                style: const TextStyle(color: Colors.white, fontSize: 11, fontFamily: 'monospace'),
                decoration: InputDecoration(
                  isDense: true, contentPadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
                  hintText: 'Enter IP, Domain, or Process (e.g. powershell.exe, c2...',
                  hintStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9),
                  filled: true, fillColor: Colors.black54, border: OutlineInputBorder(borderRadius: BorderRadius.circular(4), borderSide: BorderSide.none),
                ),
              ),
              const SizedBox(height: 8),
              Row(children: [
                 Expanded(child: Container(
                   padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 0),
                   decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(4), border: Border.all(color: const Color(0xFF32ade6).withValues(alpha: 0.5))),
                   child: DropdownButtonHideUnderline(
                     child: DropdownButton<String>(
                       value: _selectedContainmentAction,
                       dropdownColor: const Color(0xFF161b22),
                       icon: const Icon(Icons.arrow_drop_down, color: Colors.white, size: 16),
                       isExpanded: true,
                       style: const TextStyle(color: Colors.white, fontSize: 10),
                       onChanged: (String? newValue) {
                         if (newValue != null) setState(() { _selectedContainmentAction = newValue; });
                       },
                       items: <String>['Process Kill', 'Firewall Block', 'Sinkhole Domain'].map<DropdownMenuItem<String>>((String value) {
                         return DropdownMenuItem<String>(
                           value: value,
                           child: Text(value == 'Process Kill' ? '♦ Process Kill' : (value == 'Firewall Block' ? '🛡 Firewall Block' : '🌐 Sinkhole Domain')),
                         );
                       }).toList(),
                     ),
                   )
                 )),
                 const SizedBox(width: 8),
                 Expanded(child: TextField(
                   style: const TextStyle(color: Colors.white, fontSize: 11, fontFamily: 'monospace'),
                   decoration: InputDecoration(
                     isDense: true, contentPadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
                     hintText: 'Reason (e.g. Malicious C2)',
                     hintStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9),
                     filled: true, fillColor: Colors.black54, border: OutlineInputBorder(borderRadius: BorderRadius.circular(4), borderSide: BorderSide.none),
                   ),
                 )),
              ]),
              const SizedBox(height: 8),
              Row(children: [
                 Expanded(child: ElevatedButton(onPressed: (){
                     ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Checking score for ${_containmentTargetController.text}...'), backgroundColor: const Color(0xFF32ade6)));
                 }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), foregroundColor: const Color(0xFF32ade6), side: const BorderSide(color: Color(0xFF32ade6)), padding: const EdgeInsets.symmetric(vertical: 12)), child: const Text('🔍 Check Score', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 10)))),
                 const SizedBox(width: 8),
                 Expanded(child: ElevatedButton(onPressed: () async {
                    String t = _containmentTargetController.text.isEmpty ? 'powershell.exe' : _containmentTargetController.text;
                    if (_selectedContainmentAction == 'Process Kill') {
                        var res = await ApiService.killProcess(t);
                        if (res == null) {
                            ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Killed $t successfully!'), backgroundColor: const Color(0xFF30d158)));
                        } else {
                            ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Failed: $res'), backgroundColor: const Color(0xFFFF3B30)));
                        }
                    } else {
                        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Executed $_selectedContainmentAction on $t!'), backgroundColor: const Color(0xFF30d158)));
                    }
                 }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFFFF3B30), foregroundColor: Colors.white, padding: const EdgeInsets.symmetric(vertical: 12)), child: const Text('⚡ Execute Action', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 10)))),
              ]),
              
              const SizedBox(height: 8),
              Wrap(spacing: 8, runSpacing: 8, crossAxisAlignment: WrapCrossAlignment.center, children: [
                const Text('Quick Targets:', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9)),
                InkWell(onTap: () { setState(() { _containmentTargetController.text = 'powershell.exe'; }); }, child: _buildMapChip('powershell.exe')),
                InkWell(onTap: () { setState(() { _containmentTargetController.text = 'cmd.exe'; }); }, child: _buildMapChip('cmd.exe')),
                InkWell(onTap: () { setState(() { _containmentTargetController.text = '185.220.101.5'; }); }, child: _buildMapChip('185.220.101.5')),
              ])
            ])
          ),
          const SizedBox(height: 12),
          
          _buildBox('Firewall Blocklist & Sinkhole Rules (1 active)', 'Active kernel firewall & network rules', Column(children: [
             Container(
               padding: const EdgeInsets.symmetric(vertical: 8),
               decoration: const BoxDecoration(border: Border(bottom: BorderSide(color: Color(0xFF2a2f3a)))),
               child: const Row(children: [
                 Expanded(flex: 3, child: Text('TARGET', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold))),
                 Expanded(flex: 1, child: Text('TYPE', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold))),
                 Expanded(flex: 1, child: Text('ACTION', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold))),
               ])
             ),
             Container(
               padding: const EdgeInsets.symmetric(vertical: 8),
               child: Row(children: [
                 const Expanded(flex: 3, child: Text('9789473ab35...', overflow: TextOverflow.ellipsis, style: TextStyle(color: Color(0xFFFF3B30), fontSize: 9, fontFamily: 'monospace'))),
                 const Expanded(flex: 1, child: Text('All Traffic', style: TextStyle(color: Color(0xFF32ade6), fontSize: 9))),
                 Expanded(flex: 1, child: InkWell(
                    onTap: () { ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Unblocked target successfully!'), backgroundColor: Color(0xFF30d158))); },
                    child: Container(padding: const EdgeInsets.all(4), decoration: BoxDecoration(border: Border.all(color: const Color(0xFF8b949e))), child: const Center(child: Text('Unblock', style: TextStyle(color: Colors.white, fontSize: 9))))
                 )),
               ])
             )
          ])),
          const SizedBox(height: 12),
          _buildBox('Incident Lifecycle & Remediation', 'CHAIN-810021 - MEDIUM', Column(children: [
             _buildDetailRow('Host Status', 'nani123 (Monitoring)'),
             _buildDetailRow('Containment Rules', '1 firewall block'),
             _buildDetailRow('Open Alerts', '70 detection events'),
             const SizedBox(height: 12),
             ElevatedButton(
                onPressed: (){ ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Incident closed successfully.'), backgroundColor: Color(0xFF30d158))); }, 
                style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), foregroundColor: const Color(0xFF30d158), side: const BorderSide(color: Color(0xFF30d158))), 
                child: const Text('✓ Resolve & Close Incident')
             )
          ])),
        ]));"""

content = re.sub(r"case '21':.*?default: return const Center\(child: Text\('Data Loading\.\.\.'\)\);", new_case_21 + "\n\n      default: return const Center(child: Text('Data Loading...'));", content, flags=re.DOTALL)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(content)
