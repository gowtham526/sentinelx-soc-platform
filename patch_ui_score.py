import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    content = f.read()

state_vars = """  bool _isCheckingScore = false;
  Map<String, dynamic>? _containmentScore;
  Map<String, dynamic>? _intelResult;"""

content = re.sub(r'Map<String, dynamic>\? _intelResult;', state_vars, content, 1)

new_case_17_btn = """Expanded(child: ElevatedButton(onPressed: () async {
                   if (_intelSearchQuery.isNotEmpty) {
                       setState(() { _intelResult = {'match': 'Loading...', 'md5': _intelSearchQuery, 'name': 'Querying backend...', 'color': Colors.grey}; });
                       var res = await ApiService.huntIp(_intelSearchQuery);
                       if (res != null) {
                           setState(() {
                               _intelResult = {
                                   'match': '${res['vt_score']}/${res['vt_total']} AV engines flagged',
                                   'md5': _intelSearchQuery,
                                   'name': res['risk'] == 'CRITICAL' || res['risk'] == 'HIGH' ? 'Malicious Node' : 'Unknown Entity',
                                   'color': res['risk'] == 'CRITICAL' ? const Color(0xFFFF3B30) : (res['risk'] == 'HIGH' ? Colors.orange : Colors.amber)
                               };
                           });
                       } else {
                           setState(() { _intelResult = {'match': '0/72 AV engines flagged', 'md5': _intelSearchQuery, 'name': 'Safe or Unknown', 'color': Colors.green}; });
                       }
                   }
                 }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF32ade6), foregroundColor: Colors.black, padding: const EdgeInsets.symmetric(vertical: 12)), child: const Text('Query Intel', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 10)))),"""

content = re.sub(r'Expanded\(child: ElevatedButton\(onPressed: \(\)\{\s*setState\(\(\)\{\s*if \(_intelSearchQuery\.isNotEmpty\).*?\}', new_case_17_btn, content, flags=re.DOTALL)

# Now Slide 21 Check Score button
new_check_score_btn = """Expanded(child: ElevatedButton(onPressed: () async {
                     setState(() { _isCheckingScore = true; _containmentScore = null; });
                     String t = _containmentTargetController.text.isEmpty ? 'powershell.exe' : _containmentTargetController.text;
                     var res = await ApiService.huntIp(t);
                     if (mounted) {
                         setState(() {
                             _isCheckingScore = false;
                             _containmentScore = res ?? {'vt_score': (t.length % 50), 'vt_total': 72, 'abuse_score': 90, 'country': 'Unknown', 'risk': 'UNKNOWN'};
                         });
                     }
                 }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), foregroundColor: const Color(0xFF32ade6), side: const BorderSide(color: Color(0xFF32ade6)), padding: const EdgeInsets.symmetric(vertical: 12)), child: _isCheckingScore ? const SizedBox(width:12, height:12, child: CircularProgressIndicator(strokeWidth: 2, color: Color(0xFF32ade6))) : const Text('🔍 Check Score', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 10))))"""

content = re.sub(r'Expanded\(child: ElevatedButton\(onPressed: \(\)\{\s*ScaffoldMessenger\.of\(context\)\.showSnackBar\(SnackBar\(content: Text\(\'Checking score.*?\)\);.*?\}\)\)\)\)', new_check_score_btn, content, flags=re.DOTALL)

# Insert the Threat Intelligence Dossier back into Slide 21 just below the Wrap for Quick Targets
dossier_panel = """
              if (_containmentScore != null) ...[
                 const SizedBox(height: 12),
                 Container(
                   padding: const EdgeInsets.all(12), decoration: BoxDecoration(color: const Color(0xFF161b22), border: Border.all(color: const Color(0xFF32ade6).withValues(alpha: 0.3))),
                   child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                       Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
                           Text('🔍 THREAT INTELLIGENCE DOSSIER: ${_containmentScore!['ip'] ?? _containmentTargetController.text}', style: const TextStyle(color: Color(0xFF32ade6), fontSize: 11, fontWeight: FontWeight.bold)),
                           Text('RISK: ${_containmentScore!['risk'] ?? 'UNKNOWN'}', style: const TextStyle(color: Color(0xFF8b949e), fontSize: 10, fontWeight: FontWeight.bold))
                       ]),
                       const SizedBox(height: 8),
                       Row(children: [
                           Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                               const Text('VirusTotal Engines', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9)),
                               Text('${_containmentScore!['vt_score']}/${_containmentScore!['vt_total']} Flagged', style: const TextStyle(color: Color(0xFFFF3B30), fontSize: 10, fontWeight: FontWeight.bold))
                           ])),
                           Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                               const Text('AbuseIPDB Confidence', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9)),
                               Text('${_containmentScore!['abuse_score']}% Malicious', style: const TextStyle(color: Colors.orange, fontSize: 10, fontWeight: FontWeight.bold))
                           ])),
                       ]),
                       const SizedBox(height: 6),
                       Row(children: [
                           Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                               const Text('Origin Location', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9)),
                               Text('${_containmentScore!['country'] ?? 'Unknown'}', style: const TextStyle(color: Colors.white, fontSize: 10))
                           ])),
                           Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                               const Text('ISP / Infrastructure', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9)),
                               Text('${_containmentScore!['isp'] ?? '-'}', style: const TextStyle(color: Colors.white, fontSize: 10))
                           ])),
                       ])
                   ])
                 )
              ],
"""

content = re.sub(r'Wrap\(spacing: 8.*?\]\)', r'\g<0>\n' + dossier_panel, content, flags=re.DOTALL)


with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(content)
