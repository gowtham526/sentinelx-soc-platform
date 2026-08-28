import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

case_29 = """case '29': return Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(color: const Color(0xFF161b22), border: Border.all(color: const Color(0xFF2a2f3a)), borderRadius: BorderRadius.circular(8)),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const Text('All Monitored Endpoints', style: TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.bold)),
                  const SizedBox(height: 12),
                  SingleChildScrollView(
                    scrollDirection: Axis.horizontal,
                    child: DataTable(
                      headingRowHeight: 32, columnSpacing: 35,
                      headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 10, fontWeight: FontWeight.bold),
                      dataTextStyle: const TextStyle(color: Colors.white, fontSize: 11),
                      columns: const [
                        DataColumn(label: Text('HOST')),
                        DataColumn(label: Text('OS')),
                        DataColumn(label: Text('IP')),
                        DataColumn(label: Text('USER')),
                        DataColumn(label: Text('SYSMON')),
                        DataColumn(label: Text('RISK SCORE')),
                        DataColumn(label: Text('ALERTS')),
                        DataColumn(label: Text('STATUS')),
                      ],
                      rows: const [],
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      );
      """

# Insert after case '28': return IocDashboardScreen(alerts: _alerts);
text = text.replace("case '28': return IocDashboardScreen(alerts: _alerts);", "case '28': return IocDashboardScreen(alerts: _alerts);\n      " + case_29)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)
print("Inserted case 29 successfully.")
