with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/advanced_soc_playbook_screens.dart', 'r', encoding='utf-8') as f:
    text = f.read()

import re

old_ioc_logic = """    Set<String> ips = {};
    for (var a in alerts) {
      if (a['ip'] != null && a['ip'].toString().isNotEmpty && a['ip'].toString() != '-') {
        ips.add(a['ip'].toString());
      }
    }"""

new_ioc_logic = """    List<dynamic> ipAlerts = alerts.where((a) => a['ip'] != null && a['ip'].toString().isNotEmpty && a['ip'].toString() != '-').toList();
    List<dynamic> hashAlerts = alerts.where((a) => a['hash'] != null && a['hash'].toString().isNotEmpty && a['hash'].toString() != '-').toList();
    Set<String> uniqueIps = {};
    for (var a in ipAlerts) uniqueIps.add(a['ip'].toString());
    Set<String> uniqueHashes = {};
    for (var a in hashAlerts) uniqueHashes.add(a['hash'].toString());
    int totalUnique = uniqueIps.length + uniqueHashes.length;"""

text = text.replace(old_ioc_logic, new_ioc_logic)
text = text.replace("statBox('TOTAL IOCS', '${ips.length}',", "statBox('TOTAL IOCS', '${totalUnique}',")
text = text.replace("statBox('IP IOCS', '${ips.length}',", "statBox('IP IOCS', '${ipAlerts.length}',")
text = text.replace("statBox('HASH IOCS', '0',", "statBox('HASH IOCS', '${hashAlerts.length}',")
text = text.replace("rows: ips.map((ip) {", "rows: uniqueIps.map((ip) {")

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/advanced_soc_playbook_screens.dart', 'w', encoding='utf-8') as f:
    f.write(text)
