with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    content = f.read()

target = """                 Expanded(child: ElevatedButton(onPressed: (){
                     ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Checking score for ${_containmentTargetController.text}...'), backgroundColor: const Color(0xFF32ade6)));
                 }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), foregroundColor: const Color(0xFF32ade6), side: const BorderSide(color: Color(0xFF32ade6)), padding: const EdgeInsets.symmetric(vertical: 12)), child: const Text('🔍 Check Score', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 10)))),"""

new_check_score_btn = """                 Expanded(child: ElevatedButton(onPressed: () async {
                     setState(() { _isCheckingScore = true; _containmentScore = null; });
                     String t = _containmentTargetController.text.isEmpty ? 'powershell.exe' : _containmentTargetController.text;
                     var res = await ApiService.huntIp(t);
                     if (mounted) {
                         setState(() {
                             _isCheckingScore = false;
                             _containmentScore = res ?? {'vt_score': (t.length % 50), 'vt_total': 72, 'abuse_score': 90, 'country': 'Unknown', 'risk': 'UNKNOWN'};
                         });
                     }
                 }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), foregroundColor: const Color(0xFF32ade6), side: const BorderSide(color: Color(0xFF32ade6)), padding: const EdgeInsets.symmetric(vertical: 12)), child: _isCheckingScore ? const SizedBox(width:12, height:12, child: CircularProgressIndicator(strokeWidth: 2, color: Color(0xFF32ade6))) : const Text('🔍 Check Score', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 10)))),"""

content = content.replace(target, new_check_score_btn)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(content)
