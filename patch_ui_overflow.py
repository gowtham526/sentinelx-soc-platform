import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/reporting_screens.dart', 'r', encoding='utf-8') as f:
    text = f.read()

# Fix ExportBox overflow by wrapping the Row children in Expanded where needed
text = text.replace(
    'Text(title, style: const TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.bold)),',
    'Expanded(child: Text(title, style: const TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.bold))),'
)
text = text.replace(
    "Text(statLabel, style: const TextStyle(color: Colors.white70, fontSize: 12, fontWeight: FontWeight.bold)),",
    "Expanded(child: Text(statLabel, style: const TextStyle(color: Colors.white70, fontSize: 12, fontWeight: FontWeight.bold))),"
)

# Fix Incident Row overflow
# Wrap the whole Row of "All Active Incidents" Text to prevent overflow if they are wrapping badly
text = text.replace(
    "Text('All Active Incidents & Attack Chains (${incCount})', style: const TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.bold)),",
    "FittedBox(fit: BoxFit.scaleDown, alignment: Alignment.centerLeft, child: Text('All Active Incidents & Attack Chains (${incCount})', style: const TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.bold))),"
)
text = text.replace(
    "const Text('Autonomous kill-chain correlations and high-severity incidents', style: TextStyle(color: Colors.white54, fontSize: 10)),",
    "FittedBox(fit: BoxFit.scaleDown, alignment: Alignment.centerLeft, child: const Text('Autonomous kill-chain correlations and high-severity incidents', style: TextStyle(color: Colors.white54, fontSize: 10))),"
)

# Fix the Draft AI Report button overflow in the incident row
text = text.replace(
    "OutlinedButton.icon(\n            style: OutlinedButton.styleFrom(side: BorderSide(color: _selectedIncidentIndex == index ? Colors.purpleAccent : Colors.white24), foregroundColor: Colors.white),",
    "SizedBox(width: double.infinity, child: OutlinedButton.icon(\n            style: OutlinedButton.styleFrom(side: BorderSide(color: _selectedIncidentIndex == index ? Colors.purpleAccent : Colors.white24), foregroundColor: Colors.white),"
)
text = text.replace(
    "label: Text(_selectedIncidentIndex == index ? 'Report Drafted' : 'Draft AI Report', style: TextStyle(fontSize: 10, color: _selectedIncidentIndex == index ? Colors.purpleAccent : Colors.white)),\n          )",
    "label: Text(_selectedIncidentIndex == index ? 'Report Drafted' : 'Draft AI Report', style: TextStyle(fontSize: 10, color: _selectedIncidentIndex == index ? Colors.purpleAccent : Colors.white)),\n          ))"
)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/reporting_screens.dart', 'w', encoding='utf-8') as f:
    f.write(text)
print('UI overflow patched.')
