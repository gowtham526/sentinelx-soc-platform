import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

new_code = '''Future<void> _pinpointIp(String ipToLookup, String labelPrefix) async {
     setState(() { _activeIpTarget = "$labelPrefix Resolving..."; _ipController.text = ipToLookup; });
     final geo = await ApiService.fetchGeo(ipToLookup);
     
     if (geo != null && geo['countryCode'] != null) {
         String city = geo['city'] ?? 'Unknown';
         String country = geo['countryCode'] ?? '';
         String region = geo['regionName'] ?? '';
         String textSearch = (city + " " + country + " " + region + " " + ipToLookup).toLowerCase();
         
         double l = 175.0;
         double t = 125.0;
         
         // Hardcoded map coordinates matching the arbitrary SVG polygons on the mobile screen
         if (textSearch.contains('in') || textSearch.contains('india') || textSearch.contains('chennai')) { l = 260; t = 200; }
         else if (textSearch.contains('ru') || textSearch.contains('russia') || textSearch.contains('moscow')) { l = 280; t = 70; }
         else if (textSearch.contains('us') || textSearch.contains('usa') || textSearch.contains('washington')) { l = 100; t = 120; }
         else if (textSearch.contains('de') || textSearch.contains('germany') || textSearch.contains('frankfurt')) { l = 220; t = 90; }
         else if (textSearch.contains('gb') || textSearch.contains('uk') || textSearch.contains('london')) { l = 220; t = 90; }
         else if (textSearch.contains('cn') || textSearch.contains('china') || textSearch.contains('beijing')) { l = 310; t = 140; }
         else {
             // Fallback to random placement on landmasses based on hash
             l = 80.0 + (ipToLookup.hashCode % 200);
             t = 70.0 + (ipToLookup.hashCode % 130);
         }
         
         setState(() {
             _activeIpTarget = "$labelPrefix $ipToLookup\\n$city [$country]";
             _activeIpLeft = l;
             _activeIpTop = t;
         });
     } else {
         setState(() {
             _activeIpTarget = "$labelPrefix $ipToLookup\\nLookup Failed";
             _activeIpLeft = 175.0;
             _activeIpTop = 125.0;
         });
     }
  }'''

# Replace the existing _pinpointIp
text = re.sub(r'Future<void> _pinpointIp\(String ipToLookup, String labelPrefix\) async \{[\s\S]*?\} else \{[\s\S]*?\}\s*\}', new_code, text)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)

print("Replaced _pinpointIp with hardcoded mappings matching the visual polygons")
