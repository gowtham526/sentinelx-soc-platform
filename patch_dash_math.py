import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

# Fix the main dashboard cards math
fake_math = '''int total = _alerts.length;
    int crit = _alerts.where((a) => (a['severity'] ?? '').toString().toUpperCase() == 'CRITICAL').length;
    int high = _alerts.where((a) => (a['severity'] ?? '').toString().toUpperCase() == 'HIGH').length;
    if (crit == 0 && high == 0 && total > 0) { crit = (total * 0.45).ceil(); high = (total * 0.1).ceil(); }
    int med = (total * 0.18).ceil();
    int low = total - crit - high - med; if (low < 0) low = 0;
    int soarActions = crit;'''

real_math = '''int total = _alerts.length;
    int crit = _alerts.where((a) => (a['severity'] ?? '').toString().toUpperCase() == 'CRITICAL').length;
    int high = _alerts.where((a) => (a['severity'] ?? '').toString().toUpperCase() == 'HIGH').length;
    int med = _alerts.where((a) => (a['severity'] ?? '').toString().toUpperCase() == 'MEDIUM').length;
    int low = _alerts.where((a) => (a['severity'] ?? '').toString().toUpperCase() == 'LOW').length;
    int soarActions = 0;'''

if fake_math in text:
    text = text.replace(fake_math, real_math)

# Fix the threat categories math
fake_threat_math = '''if (_alerts.isNotEmpty && malware == 0 && powershell == 0) {
       malware = _alerts.length; powershell = _alerts.length; network = 2;
    }
    int totalAlerts = isToday ? _alerts.length : _alerts.length * 4 + 7;
    if (totalAlerts <= 0) totalAlerts = 1;'''

real_threat_math = '''int totalAlerts = isToday ? _alerts.length : _alerts.length;
    if (totalAlerts <= 0) totalAlerts = 1;'''

if fake_threat_math in text:
    text = text.replace(fake_threat_math, real_threat_math)

# Fix the weekly multiplier trick too, just in case
fake_weekly = '''makeRow('Malware & Binaries', isToday ? malware : malware * 3 + 2), makeRow('C2 & Reverse Shells', isToday ? c2 : c2 * 4 + 1), makeRow('Network & Port Scan', isToday ? network : network * 2),
      makeRow('Registry Persistence', isToday ? registry : registry * 3 + 1), makeRow('PowerShell & Script Abuse', isToday ? powershell : powershell * 3 + 1), makeRow('Credential & Auth Access', isToday ? auth : auth * 4),'''

real_weekly = '''makeRow('Malware & Binaries', malware), makeRow('C2 & Reverse Shells', c2), makeRow('Network & Port Scan', network),
      makeRow('Registry Persistence', registry), makeRow('PowerShell & Script Abuse', powershell), makeRow('Credential & Auth Access', auth),'''

if fake_weekly in text:
    text = text.replace(fake_weekly, real_weekly)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)
print('Patched fake math out of dashboard_screen.dart')
