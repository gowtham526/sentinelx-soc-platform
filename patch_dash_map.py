import re
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

# Replace _pinpointIp and _pinpointPublicIp
old_code_regex = r'void _pinpointIp\(String text\) \{[\s\S]*?Future<void> _pinpointPublicIp\(\) async \{[\s\S]*?\}'

new_code = '''Future<void> _pinpointIp(String ipToLookup, String labelPrefix) async {
     setState(() { _activeIpTarget = "$labelPrefix Resolving..."; _ipController.text = ipToLookup; });
     final geo = await ApiService.fetchGeo(ipToLookup);
     
     if (geo != null && geo['lat'] != null && geo['lon'] != null) {
         double lat = (geo['lat'] as num).toDouble();
         double lon = (geo['lon'] as num).toDouble();
         
         // Convert lat/lon to map screen coordinates
         // Width roughly 350, Height roughly 250
         // Lon -180 to 180 -> 0 to 350
         // Lat -90 to 90 -> 250 to 0
         
         double l = 175.0 + (lon / 180.0) * 160.0;
         double t = 125.0 - (lat / 90.0) * 100.0;
         
         String city = geo['city'] ?? 'Unknown';
         String country = geo['countryCode'] ?? '';
         
         setState(() {
             _activeIpTarget = "$labelPrefix $ipToLookup\\n$city [$country]";
             _activeIpLeft = l;
             _activeIpTop = t;
         });
     } else {
         // Fallback coordinates (center)
         setState(() {
             _activeIpTarget = "$labelPrefix $ipToLookup\\nLookup Failed";
             _activeIpLeft = 175.0;
             _activeIpTop = 125.0;
         });
     }
  }

  Future<void> _pinpointPublicIp() async {
     try {
        final res = await http.get(Uri.parse('https://api.ipify.org?format=json')).timeout(const Duration(seconds: 3));
        if (res.statusCode == 200) {
           final ip = jsonDecode(res.body)['ip'];
           await _pinpointIp(ip, 'Public IP:');
        } else {
           await _pinpointIp('12.34.56.78', 'Public IP:');
        }
     } catch (_) {
        await _pinpointIp('12.34.56.78', 'Public IP (Fallback):');
     }
  }'''

text = re.sub(old_code_regex, new_code, text)

# I also need to update the buttons in case 8 that might call _pinpointIp synchronously, since I made it async.
# The buttons do: `onPressed: () => _pinpointIp('185.220.101.5')`
# It's fine for onPressed to return void while calling an async function.
# But I changed the signature of _pinpointIp to take (ip, prefix).
# Let's fix the buttons:
text = text.replace("_pinpointIp('103.21.0.0')", "_pinpointIp('103.21.0.0', 'IP:')")
text = text.replace("_pinpointIp('185.220.101.5')", "_pinpointIp('185.220.101.5', 'IP:')")
text = text.replace("_pinpointIp('8.8.8.8')", "_pinpointIp('8.8.8.8', 'IP:')")
text = text.replace("_pinpointIp('18.10.5.5')", "_pinpointIp('18.10.5.5', 'IP:')")
text = text.replace("_pinpointIp(_ipController.text)", "_pinpointIp(_ipController.text, 'Custom IP:')")


with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)
print("Patched World Threat Map to use real API")
