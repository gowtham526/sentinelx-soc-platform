import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    content = f.read()

new_vars = """
  String _currentViewId = '5';
  String _currentViewTitle = 'Live Alerts';

  final TextEditingController _ipController = TextEditingController();
  String? _activeIpTarget;
  double _activeIpLeft = -100;
  double _activeIpTop = -100;

  void _pinpointIp(String text) {
     double l = 200, t = 100;
     String ipLow = text.toLowerCase();
     if(ipLow.contains('in ') || ipLow.contains('india') || ipLow.contains('103.21')) { l = 260; t = 200; }
     else if(ipLow.contains('ru ') || ipLow.contains('russia') || ipLow.contains('185.220')) { l = 280; t = 70; }
     else if(ipLow.contains('us ') || ipLow.contains('usa') || ipLow.contains('8.8.8.8')) { l = 100; t = 120; }
     else if(ipLow.contains('de ') || ipLow.contains('germany')) { l = 220; t = 90; }
     else { l = 150 + (text.hashCode % 100).toDouble(); t = 80 + (text.hashCode % 150).toDouble(); }
     setState((){ _activeIpTarget = text.isEmpty ? "Unknown" : text; _activeIpLeft = l; _activeIpTop = t; _ipController.text = text; });
  }

  Future<void> _pinpointPublicIp() async {
     try {
        final res = await http.get(Uri.parse('https://api.ipify.org?format=json')).timeout(const Duration(seconds: 3));
        if (res.statusCode == 200) {
           final ip = jsonDecode(res.body)['ip'];
           _pinpointIp('Public IP: ' + ip);
        } else {
           _pinpointIp('Public IP: 12.34.56.78');
        }
     } catch (_) {
        _pinpointIp('Public IP: 12.34.56.78 (Fallback)');
     }
  }
"""

content = content.replace("  String _currentViewId = '5';\n  String _currentViewTitle = 'Live Alerts';", new_vars.strip())

if "import 'dart:convert';" not in content:
    content = "import 'dart:convert';\n" + content
if "import 'package:http/http.dart' as http;" not in content:
    content = "import 'package:http/http.dart' as http;\n" + content

# Now update the UI logic in case '8'
# 1. TextField controller
content = content.replace(
    "Expanded(child: TextField(",
    "Expanded(child: TextField(controller: _ipController,"
)
# 2. Pinpoint on World Map Button
content = content.replace(
    "ElevatedButton(\n                     onPressed: () {},",
    "ElevatedButton(\n                     onPressed: () => _pinpointIp(_ipController.text),"
)
# 3. Pinpoint My Public IP Button
content = content.replace(
    "ElevatedButton(\n                       onPressed: () {},",
    "ElevatedButton(\n                       onPressed: () => _pinpointPublicIp(),"
)
# 4. Make Map Chips clickable
content = content.replace(
    "_buildMapChip('IN India'), _buildMapChip('RU Russia'), _buildMapChip('US USA'), _buildMapChip('DE Germany')",
    "InkWell(onTap: () => _pinpointIp('IN India'), child: _buildMapChip('IN India')), InkWell(onTap: () => _pinpointIp('RU Russia'), child: _buildMapChip('RU Russia')), InkWell(onTap: () => _pinpointIp('US USA'), child: _buildMapChip('US USA')), InkWell(onTap: () => _pinpointIp('DE Germany'), child: _buildMapChip('DE Germany'))"
)
# 5. Add the red crosshair target dynamically
crosshair_ui = """
                  // Dynamic Pin
                  if (_activeIpTarget != null) Positioned(
                    left: _activeIpLeft, top: _activeIpTop,
                    child: Column(
                      children: [
                        Container(width: 14, height: 14, decoration: BoxDecoration(shape: BoxShape.circle, border: Border.all(color: Colors.redAccent, width: 2), boxShadow: [BoxShadow(color: Colors.red, blurRadius: 8, spreadRadius: 4)])),
                        const SizedBox(height: 4),
                        Container(padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 2), color: Colors.black87, child: Text(_activeIpTarget!, style: const TextStyle(color: Colors.redAccent, fontSize: 10, fontWeight: FontWeight.bold)))
                      ]
                    )
                  )
"""
content = content.replace(
    "                  Positioned(left: 260, top: 200, child: _buildMapPin('Chennai [IN]')),",
    "                  Positioned(left: 260, top: 200, child: _buildMapPin('Chennai [IN]')),\n" + crosshair_ui
)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(content)
