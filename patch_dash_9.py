import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

# 1. Update case '29' (Endpoint Summary)
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
                      rows: [],
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      );"""
text = re.sub(r"case '29':.*?return.*?Placeholder.*?;", case_29, text)

# 2. Add Clear Alerts button to case '5' (Live Alerts)
new_live_alerts_container = """Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(color: const Color(0xFF161b22), border: Border.all(color: const Color(0xFF2a2f3a)), borderRadius: BorderRadius.circular(8)),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Text('Live Alert Feed', style: TextStyle(color: Colors.white, fontSize: 12, fontWeight: FontWeight.bold)),
                          const SizedBox(height: 2),
                          const Text('Auto-refreshing real detections - newest first', style: TextStyle(color: Color(0xFF8b949e), fontSize: 10)),
                        ],
                      ),
                      ElevatedButton.icon(
                        onPressed: () async {
                           try {
                             await http.post(Uri.parse('${ApiService.baseUrl}/api/alerts/clear'), headers: {'Authorization': 'Bearer ${ApiService.authToken}'});
                             _loadDashboardData();
                           } catch (e) { }
                        },
                        icon: const Icon(Icons.delete_sweep, size: 12),
                        label: const Text('Clear Alerts', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold)),
                        style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF30363d), foregroundColor: Colors.red, minimumSize: Size.zero, padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8)),
                      )
                    ],
                  ),
                  const SizedBox(height: 12),
                  ListView.builder("""

text = text.replace(
    "_buildBox('Live Alert Feed', 'Auto-refreshing real detections - newest first', ListView.builder(",
    new_live_alerts_container
)

text = text.replace(
    """              },
            )),
          ],
        )
      );""",
    """              },
            )
           ]
          )
         ),
          ],
        )
      );"""
)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)
print("Updated case 29 and case 5.")
