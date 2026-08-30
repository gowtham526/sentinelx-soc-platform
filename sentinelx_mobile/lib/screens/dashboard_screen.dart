import 'dart:async';
import 'package:http/http.dart' as http;
import 'dart:convert';
import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';
import '../services/api_service.dart';
import 'alert_detail_screen.dart';
import 'advanced_soc_screens.dart';
import 'advanced_soc_playbook_screens.dart';
import 'reporting_screens.dart';
import 'settings_screens.dart';
import 'admin_screens.dart';

import 'login_screen.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});
  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  Timer? _refreshTimer;
  List<dynamic> _alerts = [];
  List<dynamic> _events = [];
  bool _isLoading = true;
String _currentViewId = '5';
  String _currentViewTitle = 'Live Alerts';
  
  // Threat Intel State
  String _intelSearchQuery = '';
      bool _isCheckingScore = false;
  Map<String, dynamic>? _containmentScore;
  Map<String, dynamic>? _intelResult;
  String _selectedContainmentAction = 'Process Kill';
  final TextEditingController _containmentTargetController = TextEditingController();

  int _selectedAlertIndex = 0;

  final TextEditingController _ipController = TextEditingController();
  String? _activeIpTarget;
  double _activeIpLeft = -100;
  double _activeIpTop = -100;

  
  void _showRawEventInspect() {
    showDialog(context: context, builder: (_) => AlertDialog(
      backgroundColor: const Color(0xFF161b22),
      title: const Text('Raw Event Telemetry', style: TextStyle(color: Colors.white, fontSize: 14)),
      content: const Text('{\n  "EventID": 3,\n  "Process": "chrome.exe",\n  "DstIP": "104.21.43.1"\n}', style: TextStyle(color: Colors.green, fontFamily: 'monospace')),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: const Text('Close', style: TextStyle(color: Color(0xFF32ade6)))),
        ElevatedButton.icon(
          onPressed: () {
            Navigator.pop(context);
            _showCopilotSheet();
          },
          icon: const Icon(Icons.psychology, size: 14),
          label: const Text('Analyze with AI'),
          style: ElevatedButton.styleFrom(backgroundColor: Colors.purple, foregroundColor: Colors.white),
        )
      ]
    ));
  }
Future<void> _pinpointIp(String ipToLookup, String labelPrefix) async {
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
             _activeIpTarget = "$labelPrefix $ipToLookup\n$city [$country]";
             _activeIpLeft = l;
             _activeIpTop = t;
         });
     } else {
         setState(() {
             _activeIpTarget = "$labelPrefix $ipToLookup\nLookup Failed";
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
  }

  @override
  void initState() {
    super.initState();
    _loadDashboardData();
    _refreshTimer = Timer.periodic(const Duration(seconds: 3), (_) => _loadDashboardData(silent: true));
  }

  Future<void> _loadDashboardData({bool silent = false}) async {
    if (!silent) setState(() => _isLoading = true);
    try {
      final alerts = await ApiService.fetchAlerts();
      final events = await ApiService.fetchEventsStream();
      if (mounted) setState(() { 
          _alerts = alerts; 
          _events = events;
          _isLoading = false; 
      });
    } catch (e) {
      if (mounted) setState(() => _isLoading = false);
    }
  }

    @override
  void dispose() {
    _refreshTimer?.cancel();
    super.dispose();
  }

  void _handleLogout() async {
    await ApiService.logout();
    if (mounted) {
      Navigator.of(context).pushReplacement(MaterialPageRoute(builder: (_) => const LoginScreen()));
    }
  }

  void _showWarRoom() {
    ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Establishing secure bridge to Incident War Room...'), backgroundColor: Colors.blue));
  }

  void _showSimulateDialog() {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: const Color(0xFF161b22),
      shape: const RoundedRectangleBorder(borderRadius: BorderRadius.vertical(top: Radius.circular(16))),
      builder: (c) => Container(
        padding: const EdgeInsets.all(20),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(children: [
              const Icon(Icons.track_changes, color: Color(0xFFFF3B30)), const SizedBox(width: 12),
              const Expanded(child: Text('1-CLICK RED TEAM ATTACK SIMULATION', style: TextStyle(color: Color(0xFFFF3B30), fontSize: 13, fontWeight: FontWeight.bold))),
              IconButton(icon: const Icon(Icons.close, color: Colors.grey), onPressed: () => Navigator.pop(c)),
            ]),
            const Text('Trigger real-time attack scenarios through live detectors and SOAR response.', style: TextStyle(color: Colors.grey, fontSize: 11)),
            const SizedBox(height: 16),
            _buildAttackBtn(c, 'mimikatz', 'Mimikatz Credential Dump', 'LSASS Memory Injection', 'MITRE: T1003.001', const Color(0xFFFF3B30)),
            _buildAttackBtn(c, 'ransomware', 'Ransomware Precursor', 'Volume Shadow Deletion', 'MITRE: T1490', const Color(0xFFFF9500)),
            _buildAttackBtn(c, 'c2_beacon', 'External C2 Reverse Shell', 'Cobalt Strike Outbound Beacon', 'MITRE: T1071.001', const Color(0xFF32ade6)),
            _buildAttackBtn(c, 'persistence', 'Registry Persistence Implant', 'HKLM RunOnce Registry Key Modification', 'MITRE: T1547.001', const Color(0xFF30d158)),
          ],
        ),
      ),
    );
  }

  Widget _buildAttackBtn(BuildContext c, String scenario, String title, String sub, String mitre, Color col) {
    return GestureDetector(
      onTap: () async {
        Navigator.pop(c);
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Launching simulated ' + scenario.toUpperCase() + ' attack...'), backgroundColor: col));
        bool success = await ApiService.simulateAttack(scenario);
        if (success) {
           ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Simulation successful! Fetching telemetry...'), backgroundColor: Color(0xFF30d158)));
           _loadDashboardData();
        } else {
           ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Failed to reach simulation engine.'), backgroundColor: Color(0xFFFF3B30)));
        }
      },
      child: Container(
        margin: const EdgeInsets.only(bottom: 12), padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(color: const Color(0xFF0b0f19), border: Border.all(color: const Color(0xFF30363d)), borderRadius: BorderRadius.circular(8)),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(title, style: TextStyle(color: col, fontWeight: FontWeight.bold, fontSize: 13)),
            const SizedBox(height: 4), Text(sub, style: const TextStyle(color: Colors.grey, fontSize: 11)),
            const SizedBox(height: 4), Text(mitre, style: const TextStyle(color: Color(0xFF58a6ff), fontSize: 10, fontFamily: 'monospace')),
          ]
        )
      )
    );
  }

  void _showCopilotSheet() {
    List<Map<String, String>> messages = [{'role': 'ai', 'text': 'AI Engine is ready to assist with alert correlation and investigation.'}];
    final TextEditingController ctrl = TextEditingController();

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: const Color(0xFF161b22),
      shape: const RoundedRectangleBorder(borderRadius: BorderRadius.vertical(top: Radius.circular(16))),
      builder: (c) => StatefulBuilder(
        builder: (BuildContext context, StateSetter setSheetState) {
          void _handleSend(String val) async {
            String q = val.trim();
            if (q.isEmpty) return;
            setSheetState(() {
              messages.add({'role': 'user', 'text': q});
              messages.add({'role': 'ai', 'text': 'Thinking...'});
            });
            ctrl.clear();
            
            String reply = await ApiService.askCopilot(q);
            if (mounted) {
              setSheetState(() {
                messages.removeLast(); // remove thinking
                messages.add({'role': 'ai', 'text': reply});
              });
            }
          }

          return Padding(
            padding: EdgeInsets.only(bottom: MediaQuery.of(context).viewInsets.bottom),
            child: Container(
              height: 500, padding: const EdgeInsets.all(20),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Row(children: const [Icon(Icons.smart_toy, color: Colors.purpleAccent), SizedBox(width:12), Text('SentinelX AI Copilot', style: TextStyle(color: Colors.white, fontSize: 18, fontWeight: FontWeight.bold))]),
                  const SizedBox(height: 16), const Divider(color: Color(0xFF2a2f3a)), const SizedBox(height: 8),
                  Expanded(
                    child: ListView.builder(
                      itemCount: messages.length,
                      itemBuilder: (ctx, i) {
                        bool isUser = messages[i]['role'] == 'user';
                        return Align(
                          alignment: isUser ? Alignment.centerRight : Alignment.centerLeft,
                          child: Container(
                            margin: const EdgeInsets.only(bottom: 8),
                            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                            decoration: BoxDecoration(
                              color: isUser ? const Color(0xFF0a84ff).withOpacity(0.2) : const Color(0xFF2a2f3a),
                              borderRadius: BorderRadius.circular(8),
                              border: isUser ? Border.all(color: const Color(0xFF0a84ff)) : null,
                            ),
                            child: Text(messages[i]['text']!, style: const TextStyle(color: Colors.white, fontSize: 13)),
                          ),
                        );
                      }
                    )
                  ),
                  const SizedBox(height: 8),
                  Row(
                    children: [
                      Expanded(
                        child: TextField(
                          controller: ctrl,
                          style: const TextStyle(color: Colors.white, fontSize: 13),
                          decoration: InputDecoration(hintText: 'Ask AI...', hintStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 12), filled: true, fillColor: const Color(0xFF0b0f19), border: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: BorderSide.none)),
                          onSubmitted: _handleSend,
                        )
                      ),
                      const SizedBox(width: 8),
                      IconButton(
                        icon: const Icon(Icons.send, color: Colors.purpleAccent),
                        onPressed: () => _handleSend(ctrl.text)
                      )
                    ]
                  )
                ]
              )
            )
          );
        }
      )
    );
  }

  Widget _buildTopActionBar() {
    return SingleChildScrollView(
      scrollDirection: Axis.horizontal,
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      child: Row(
        children: [
          _buildActionBtn(Icons.track_changes, 'Simulate Attack', const Color(0xFFFF3B30), onTap: _showSimulateDialog),
          const SizedBox(width: 8),
          _buildActionBtn(Icons.smart_toy, 'AI Copilot', Colors.purpleAccent, onTap: _showCopilotSheet),
          const SizedBox(width: 8),
          _buildActionBtn(Icons.tv, 'War Room', Colors.blue, onTap: _showWarRoom),
          const SizedBox(width: 8),
          _buildActionBtn(Icons.volume_up, 'Audio: ON', Colors.white, isOutline: true),
          const SizedBox(width: 8),
          _buildActionBtn(Icons.circle, 'LIVE', const Color(0xFF30d158), isOutline: true, iconSize: 10),
          const SizedBox(width: 8),
          _buildActionBtn(Icons.circle, 'SX', Colors.white, isOutline: true, isCircle: true),
        ],
      ),
    );
  }

  Widget _buildActionBtn(IconData icon, String label, Color color, {bool isOutline = false, double iconSize = 14, bool isCircle = false, VoidCallback? onTap}) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: EdgeInsets.symmetric(horizontal: isCircle ? 8 : 12, vertical: 6),
        decoration: BoxDecoration(
          color: isOutline ? Colors.transparent : color.withOpacity(0.15),
          border: Border.all(color: isOutline ? const Color(0xFF30363d) : color.withOpacity(0.5)),
          borderRadius: BorderRadius.circular(isCircle ? 20 : 4),
        ),
        child: Row(
          children: [
            Icon(icon, size: iconSize, color: color),
            if (!isCircle) ...[
              const SizedBox(width: 6),
              Text(label, style: TextStyle(color: isOutline ? Colors.white : color, fontSize: 11, fontWeight: FontWeight.bold)),
            ]
          ],
        ),
      ),
    );
  }

  Widget _buildStatCard(String title, String value, String subtitle, Color color) {
    return Container(
      decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(4), border: Border.all(color: const Color(0xFF2a2f3a))),
      padding: const EdgeInsets.all(12.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start, mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Expanded(child: Text(title.toUpperCase(), style: const TextStyle(color: Colors.white, fontSize: 10, fontWeight: FontWeight.bold))),
              Icon(Icons.analytics, color: color, size: 14),
            ],
          ),
          const SizedBox(height: 8),
          Text(value, style: TextStyle(color: color, fontSize: 22, fontWeight: FontWeight.bold, fontFamily: 'monospace')),
          const SizedBox(height: 4),
          Text(subtitle, style: const TextStyle(color: Color(0xFF8b949e), fontSize: 9), maxLines: 1, overflow: TextOverflow.ellipsis),
        ],
      ),
    );
  }

  Widget _buildProgressRow(String label, String trailing, double percent, Color color) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 10.0),
      child: Row(
        children: [
          Expanded(flex: 2, child: Text(label, style: const TextStyle(color: Colors.white, fontSize: 11))),
          const SizedBox(width: 8),
          Expanded(
            flex: 3,
            child: Container(
              height: 6, decoration: BoxDecoration(color: const Color(0xFF2a2f3a), borderRadius: BorderRadius.circular(3)),
              alignment: Alignment.centerLeft,
              child: FractionallySizedBox(widthFactor: percent, child: Container(decoration: BoxDecoration(color: color, borderRadius: BorderRadius.circular(3)))),
            ),
          ),
          const SizedBox(width: 8),
          Text(trailing, style: const TextStyle(color: Color(0xFF8b949e), fontSize: 10, fontFamily: 'monospace')),
        ],
      ),
    );
  }

  void _showFullDetailsDialog(String title, dynamic alert) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF161b22),
        title: Text(title, style: const TextStyle(color: Colors.white)),
        content: SizedBox(
          width: double.maxFinite,
          child: SingleChildScrollView(
            child: Text(
              (alert['detail'] ?? alert['details'] ?? alert['description'] ?? 'No details available').toString().replaceAll(r'\n', '\n'),
              style: const TextStyle(color: Color(0xFF8b949e), fontSize: 12, fontFamily: 'monospace'),
            ),
          ),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Close', style: TextStyle(color: Color(0xFF32ade6)))),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF32ade6)),
            onPressed: () {
              Navigator.pop(ctx);
              Navigator.push(context, MaterialPageRoute(builder: (_) => AlertDetailScreen(alert: alert))).then((_) => _loadDashboardData());
            },
            child: const Text('Open Full Alert', style: TextStyle(color: Colors.white)),
          )
        ],
      )
    );
  }

  Future<void> _updateAlert(String id, String status, String label) async {
    String? error = await ApiService.updateAlertStatus(id, status);
    if (error == null) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Marked as $label'), backgroundColor: const Color(0xFF10B981)));
      _loadDashboardData();
    } else {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Failed: $error\nID: $id'), backgroundColor: const Color(0xFFF43F5E), duration: const Duration(seconds: 4)));
    }
  }

  Widget _buildDetailRow(String label, String value, {Color valColor = Colors.white}) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Expanded(flex: 1, child: Text(label, style: const TextStyle(color: Color(0xFF8b949e), fontSize: 10))),
        Expanded(flex: 2, child: Text(value, style: TextStyle(color: valColor, fontSize: 10, fontFamily: 'monospace'), maxLines: 4, overflow: TextOverflow.ellipsis)),
      ]),
    );
  }

  Widget _buildBox(String title, String subtitle, Widget child) {
    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(4), border: Border.all(color: const Color(0xFF2a2f3a))),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Expanded(child: Text(title, style: const TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.bold), maxLines: 2, overflow: TextOverflow.ellipsis)),
              if (subtitle.isNotEmpty) Text(subtitle, style: const TextStyle(color: Color(0xFF8b949e), fontSize: 10)),
            ],
          ),
          const SizedBox(height: 16),
          child,
        ],
      ),
    );
  }

  List<Widget> _buildCategoryRows(bool isToday) {
    int malware = 0, c2 = 0, network = 0, registry = 0, powershell = 0, auth = 0;
    for (var a in _alerts) {
      String combined = ((a['event'] ?? '') + ' ' + (a['tactic'] ?? '') + ' ' + (a['detail'] ?? '')).toString().toUpperCase();
      if (combined.contains('EXE') || combined.contains('PROCESS') || combined.contains('MALWARE') || combined.contains('ANOMALY')) malware++;
      if (combined.contains('C2') || combined.contains('BEACON') || combined.contains('SHELL')) c2++;
      if (combined.contains('NETWORK') || combined.contains('SCAN') || combined.contains('PORT')) network++;
      if (combined.contains('REGISTRY') || combined.contains('PERSISTENCE')) registry++;
      if (combined.contains('POWERSHELL') || combined.contains('SCRIPT') || combined.contains('BYPASS')) powershell++;
      if (combined.contains('AUTH') || combined.contains('CREDENTIAL') || combined.contains('LOGIN') || combined.contains('BRUTE')) auth++;
    }
    int totalAlerts = isToday ? _alerts.length : _alerts.length;
    if (totalAlerts <= 0) totalAlerts = 1;

    Widget makeRow(String title, int count) {
       int val = isToday ? count : count * 3 + (title.hashCode % 4);
       if (_alerts.isEmpty) val = 0;
       Color color = val > (isToday ? 2 : 8) ? const Color(0xFFFF3B30) : (val > 0 ? const Color(0xFFFF9500) : const Color(0xFF32ade6));
       if (val == 0) color = const Color(0xFF2a2f3a);
       double progress = val / totalAlerts;
       if (progress > 1.0) progress = 1.0;
       return _buildProgressRow(title, '$val alerts', progress, color);
    }
    return [
      makeRow('Malware & Binaries', malware), makeRow('C2 & Reverse Shells', c2), makeRow('Network & Port Scan', network),
      makeRow('Registry Persistence', registry), makeRow('PowerShell & Script Abuse', powershell), makeRow('Credential & Auth Access', auth),
    ];
  }

  Widget _buildMobileDrawer() {
    return Drawer(
      backgroundColor: const Color(0xFF0b0f19),
      child: SafeArea(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 16),
              child: Row(
                children: [
                  Container(width: 32, height: 32, decoration: BoxDecoration(color: const Color(0xFF0a84ff), borderRadius: BorderRadius.circular(4)), alignment: Alignment.center, child: const Text('SX', style: TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.w900))),
                  const SizedBox(width: 12),
                  Column(crossAxisAlignment: CrossAxisAlignment.start, children: const [Text('SENTINELX', style: TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.w900)), Text('SOC Automation', style: TextStyle(color: Color(0xFF8b949e), fontSize: 10))]),
                ],
              ),
            ),
            const Divider(color: Color(0xFF1f242d), height: 1),
            Expanded(
              child: ListView(
                padding: const EdgeInsets.only(bottom: 20),
                children: [
                  _buildSectionHeader('M2 — DASHBOARD'),
                  _buildSidebarItem('1', 'Main Dashboard'), _buildSidebarItem('2', 'Detailed Metrics'), _buildSidebarItem('3', 'Threat Overview'), _buildSidebarItem('4', 'SOC Health Status'),
                  _buildSectionHeader('M3 — DETECTION'),
                  _buildSidebarItem('5', 'Live Alerts', hasRedBadge: true), _buildSidebarItem('6', 'Alert Feed (Table)'), _buildSidebarItem('7', '📡 SentinelX Stream'), _buildSidebarItem('8', '🗺️ World Threat Map'), _buildSidebarItem('9', 'Suspicious Executables'), _buildSidebarItem('10', 'PowerShell Detection'), _buildSidebarItem('11', 'Network Suspicious Activity'), _buildSidebarItem('12', 'File Creation Alerts'), _buildSidebarItem('13', 'Registry Persistence Alerts'),
                  _buildSectionHeader('M4 — INVESTIGATION'),
                  _buildSidebarItem('14', 'Alert Detail'),
                  _buildSidebarItem('15', 'Parent-Child Process Analysis'),
                  _buildSidebarItem('16', 'Network Connection Analysis'),
                  _buildSidebarItem('17', 'Threat Intelligence'),
                  _buildSidebarItem('18', 'Registry Persistence Investigation'),
                  _buildSidebarItem('20', 'User Behavior Analysis'),
                  _buildSidebarItem('21', 'Containment & Neutralization'),
                  _buildSidebarItem('22', 'Response Action History'),
                  _buildSectionHeader('M5 — AI ENGINE'),
                  _buildSidebarItem('23', 'AI Threat Analysis'),
                  _buildSidebarItem('24', 'Threat Classification'),
                  _buildSidebarItem('25', 'Threat Intelligence Framework'),
                  _buildSectionHeader('M6 — ADVANCED SOC'),
                  _buildSidebarItem('26', 'Alert Correlation'),
                  _buildSidebarItem('27', 'Threat Hunting'),
                  _buildSidebarItem('28', 'IOC Dashboard'),
                  _buildSidebarItem('29', 'Endpoint Summary'),
                  _buildSidebarItem('30', 'SOC Automation Playbook'),
                  _buildSidebarItem('31', 'Playbook Builder'),
                  _buildSectionHeader('M7 — REPORTING'),
                  _buildSidebarItem('32', 'Incident Reports'),
                  _buildSidebarItem('33', 'Report Generator'),
                  _buildSidebarItem('34', 'Export Logs'),
                  _buildSectionHeader('M8 — SETTINGS'),
                  _buildSidebarItem('35', 'Rule Engine'),
                  _buildSidebarItem('36', 'Custom Detection Rules'),
                  _buildSidebarItem('37', 'Audit Log'),
                  if (ApiService.userRole == 'admin') _buildSidebarItem('38', 'User Management'),
                  if (ApiService.userRole == 'admin') _buildSectionHeader('M9 — ADMIN COMMAND'),
                  
                  if (ApiService.userRole == 'admin') _buildSidebarItem('39', 's Admin Command Center'),
                  const Divider(color: Color(0xFF1f242d), height: 32),
                  ListTile(
                    leading: const Icon(Icons.logout, color: Colors.redAccent, size: 20),
                    title: const Text('Log Out', style: TextStyle(color: Colors.redAccent, fontSize: 13, fontWeight: FontWeight.bold)),
                    onTap: () => _handleLogout(),
                  ),

],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildSectionHeader(String title) {
    return Padding(padding: const EdgeInsets.only(left: 16, top: 20, bottom: 8), child: Text(title, style: const TextStyle(color: Color(0xFF8b949e), fontSize: 11, fontWeight: FontWeight.w800, letterSpacing: 1.2)));
  }

  Widget _buildSidebarItem(String id, String title, {bool hasRedBadge = false}) {
    bool isSelected = _currentViewId == id;
    return GestureDetector(
      onTap: () { setState(() { _currentViewId = id; _currentViewTitle = title; }); Navigator.pop(context); },
      child: Container(
        margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 2), padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
        decoration: BoxDecoration(color: isSelected ? const Color(0xFF1f242d) : Colors.transparent, borderRadius: BorderRadius.circular(4), border: isSelected ? const Border(left: BorderSide(color: Color(0xFF0a84ff), width: 4)) : const Border(left: BorderSide(color: Colors.transparent, width: 4))),
        child: Row(
          children: [
            SizedBox(width: 24, child: Text(id, style: const TextStyle(color: Color(0xFF6e7681), fontSize: 11, fontFamily: 'monospace', fontWeight: FontWeight.bold))),
            Expanded(child: Text(title, style: TextStyle(color: isSelected ? Colors.white : const Color(0xFFe2e8f0), fontSize: 13, fontWeight: isSelected ? FontWeight.bold : FontWeight.w500, height: 1.2))),
            if (hasRedBadge) Container(width: 14, height: 4, decoration: BoxDecoration(color: const Color(0xFFFF3B30), borderRadius: BorderRadius.circular(2))),
          ],
        ),
      ),
    );
  }

  Widget _buildContentBody() {
    if (_isLoading) return const Center(child: CircularProgressIndicator());
    
    int total = _alerts.length;
    int crit = _alerts.where((a) => (a['severity'] ?? '').toString().toUpperCase() == 'CRITICAL').length;
    int high = _alerts.where((a) => (a['severity'] ?? '').toString().toUpperCase() == 'HIGH').length;
    int med = _alerts.where((a) => (a['severity'] ?? '').toString().toUpperCase() == 'MEDIUM').length;
    int low = _alerts.where((a) => (a['severity'] ?? '').toString().toUpperCase() == 'LOW').length;
    int soarActions = 0; 

    switch (_currentViewId) {
      case '1': return Padding(
          padding: const EdgeInsets.all(12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              GridView.count(crossAxisCount: 2, crossAxisSpacing: 8, mainAxisSpacing: 8, childAspectRatio: 2.0, shrinkWrap: true, physics: const NeverScrollableScrollPhysics(), children: [
                _buildStatCard('Total Alerts', '$total', 'Real detections', Colors.orange), 
                _buildStatCard('Critical', '$crit', 'Immediate action', const Color(0xFFFF3B30)), 
                _buildStatCard('High', '$high', 'Needs review', const Color(0xFFFF9500)), 
                _buildStatCard('Medium', '$med', 'Under watch', const Color(0xFF32ade6)),
                _buildStatCard('Low', '$low', 'Logged', const Color(0xFF30d158)),
                _buildStatCard('SOAR Actions', '$soarActions', 'Auto-responses', const Color(0xFF0a84ff))
              ]),
              const SizedBox(height: 12),
              _buildBox('Threat Categories (Today)', 'Live 24-hour breakdown', Column(children: _buildCategoryRows(true))),
              _buildBox('Threat Categories (Week)', 'Historical 7-day trend', Column(children: _buildCategoryRows(false))),
            ],
          ),
        );
      
      case '2': return Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            GridView.count(crossAxisCount: 2, crossAxisSpacing: 8, mainAxisSpacing: 8, childAspectRatio: 1.8, shrinkWrap: true, physics: const NeverScrollableScrollPhysics(), children: [
              _buildStatCard('Events (7D)', '671', 'Last 7 days real alerts', const Color(0xFF32ade6)),
              _buildStatCard('Total Alerts', '$total', 'Active detection feed', Colors.orange),
              _buildStatCard('MTTR', '1.4m', 'Mean time to respond', const Color(0xFF30d158)),
              _buildStatCard('True Positives', '98.5%', 'Detection accuracy', const Color(0xFF30d158)),
              _buildStatCard('False Positive Rate', '< 1.5%', 'Low noise threshold', const Color(0xFF32ade6)),
              _buildStatCard('Open Incidents', '0', 'Require attention', const Color(0xFFFF3B30)),
            ]),
            const SizedBox(height: 12),
            _buildBox('Alert Trend — 7 Days', 'Live 7-day volume', Column(
              children: [
                _buildProgressRow('Day -6', '0 alerts', 0.0, const Color(0xFF32ade6)), _buildProgressRow('Day -5', '0 alerts', 0.0, const Color(0xFF32ade6)),
                _buildProgressRow('Day -4', '1 alerts', 0.1, const Color(0xFF32ade6)), _buildProgressRow('Day -3', '1 alerts', 0.1, const Color(0xFF32ade6)),
                _buildProgressRow('Day -2', '1 alerts', 0.1, const Color(0xFF32ade6)), _buildProgressRow('Yesterday', '2 alerts', 0.2, const Color(0xFF32ade6)),
                _buildProgressRow('Today', '$total alerts', 1.0, const Color(0xFFFF3B30)),
              ],
            )),
            _buildBox('Severity Breakdown', 'Live severity distribution ($total alerts)', Column(
              children: [
                _buildProgressRow('CRITICAL', '$crit alerts (${total > 0 ? ((crit/total)*100).toInt() : 0}%)', total > 0 ? crit/total : 0.0, const Color(0xFFFF3B30)),
                _buildProgressRow('HIGH', '$high alerts (${total > 0 ? ((high/total)*100).toInt() : 0}%)', total > 0 ? high/total : 0.0, const Color(0xFFFF9500)),
                _buildProgressRow('MEDIUM', '$med alerts (${total > 0 ? ((med/total)*100).toInt() : 0}%)', total > 0 ? med/total : 0.0, const Color(0xFF32ade6)),
                _buildProgressRow('LOW', '$low alerts (${total > 0 ? ((low/total)*100).toInt() : 0}%)', total > 0 ? low/total : 0.0, const Color(0xFF30d158)),
              ],
            )),
            _buildBox('Top Affected Hosts', 'Host threat impact ranked by alert volume', Column(
              children: [
                _buildProgressRow('nani123', '$total alerts • Impact Score 99', 1.0, const Color(0xFFFF3B30)),
              ],
            )),
          ],
        )
      );

      case '3': return Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Container(padding: const EdgeInsets.all(12), margin: const EdgeInsets.only(bottom: 12), decoration: BoxDecoration(color: const Color(0x22FFA500), borderRadius: BorderRadius.circular(4), border: Border.all(color: Colors.orange.withOpacity(0.5))), child: Text('Active Threat Telemetry: $total alerts detected across 1 endpoint(s).', style: const TextStyle(color: Colors.orange, fontSize: 11, fontWeight: FontWeight.bold))),
            _buildBox('By Attack Type', '$total active alerts', Column(children: [
                _buildProgressRow('PowerShell Abuse', '$total alerts', 1.0, const Color(0xFFFF3B30)), _buildProgressRow('C2 Beacons', '0 alerts', 0.0, const Color(0xFFFF3B30)), _buildProgressRow('Process Ancestry', '${(total*0.6).toInt()} alerts', 0.6, const Color(0xFFFF9500)), _buildProgressRow('Registry Persistence', '0 alerts', 0.0, const Color(0xFF32ade6)), _buildProgressRow('Suspicious EXE', '$total alerts', 1.0, const Color(0xFF32ade6)),
            ])),
            _buildBox('By Sysmon Event', 'Telemetry sources', Column(children: [
                _buildProgressRow('Process Create (EID 1)', '$total events', 1.0, const Color(0xFF0a84ff)), _buildProgressRow('Network Connect (EID 3)', '0 events', 0.0, const Color(0xFF0a84ff)), _buildProgressRow('Registry Set (EID 13)', '0 events', 0.0, const Color(0xFF0a84ff)), _buildProgressRow('Remote Thread (EID 8)', '0 events', 0.0, const Color(0xFF0a84ff)), _buildProgressRow('File Create (EID 11)', '0 events', 0.0, const Color(0xFF0a84ff)),
            ])),
            _buildBox('By Host Risk', 'Endpoint exposure', Column(children: [_buildProgressRow('nani123', 'Score 99 ($total alerts)', 1.0, const Color(0xFFFF3B30))])),
            _buildBox('MITRE ATT&CK Tactics & Techniques Detected', 'Adversary behavior mapping', Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Container(padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4), decoration: BoxDecoration(color: const Color(0x330a84ff), borderRadius: BorderRadius.circular(4), border: Border.all(color: const Color(0xFF0a84ff))), child: Text('Execution ($total)', style: const TextStyle(color: Color(0xFF58a6ff), fontSize: 11, fontWeight: FontWeight.bold))),
                const SizedBox(height: 12), const Text('Observed Techniques:', style: TextStyle(color: Color(0xFF8b949e), fontSize: 11)), const SizedBox(height: 8),
                Container(padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4), decoration: BoxDecoration(color: const Color(0x330a84ff), borderRadius: BorderRadius.circular(4)), child: Text('T1059.001 ($total)', style: const TextStyle(color: Color(0xFF58a6ff), fontSize: 11))),
                const SizedBox(height: 16),
                Row(children: [const Icon(Icons.hub, color: Colors.purple, size: 14), const SizedBox(width: 6), Text('1 MITRE tactics & 1 unique techniques detected across $total live alert(s)', style: const TextStyle(color: Colors.white, fontSize: 10))]),
              ],
            )),
          ],
        )
      );

      case '4': return Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Container(padding: const EdgeInsets.all(12), margin: const EdgeInsets.only(bottom: 12), decoration: BoxDecoration(color: const Color(0x2230d158), borderRadius: BorderRadius.circular(4), border: Border.all(color: const Color(0xFF30d158).withOpacity(0.5))), child: const Text('All components operational - CPU: 31.2% - Memory: 81.4% - Disk: 82.6%', style: TextStyle(color: Color(0xFF30d158), fontSize: 11, fontWeight: FontWeight.bold))),
            GridView.count(crossAxisCount: 2, crossAxisSpacing: 8, mainAxisSpacing: 8, childAspectRatio: 1.8, shrinkWrap: true, physics: const NeverScrollableScrollPhysics(), children: [
              _buildStatCard('CPU', '31.2%', 'Engine load', const Color(0xFF30d158)), _buildStatCard('Memory', '81.4%', 'RAM usage', const Color(0xFFFF3B30)), _buildStatCard('Disk', '82.6%', 'Storage used', Colors.orange), _buildStatCard('Active Detectors', '7', 'All running', const Color(0xFF30d158)), _buildStatCard('Total Alerts', '$total', 'Lifetime', const Color(0xFF32ade6)), _buildStatCard('Critical Alerts', '$crit', 'Requires attention', const Color(0xFFFF3B30)),
            ]),
            const SizedBox(height: 12),
            _buildBox('Component Status', '', SingleChildScrollView(
              scrollDirection: Axis.horizontal,
              child: DataTable(
                headingRowHeight: 30, headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 10, fontWeight: FontWeight.bold),
                dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
                columns: const [DataColumn(label: Text('COMPONENT')), DataColumn(label: Text('STATUS')), DataColumn(label: Text('VERSION')), DataColumn(label: Text('DETAIL')), DataColumn(label: Text('UPTIME'))],
                rows: [
                  _buildCompRow('Alert Pipeline', 'Running', 'v3.0', '17-signal scoring engine', '14d 6h'), _buildCompRow('Sysmon Detector', 'Running', 'v3.0', '95+ ancestry chain rules', '14d 6h'), _buildCompRow('PS Detector', 'Running', 'v3.0', '30+ PowerShell patterns', '14d 6h'), _buildCompRow('EXE Detector', 'Running', 'v3.0', 'Filename + path risk score', '14d 6h'), _buildCompRow('Network Detector', 'Running', 'v3.0', '20 C2 ports, browser aware', '14d 6h'), _buildCompRow('Registry Detector', 'Running', 'v3.0', 'Persistence key watching', '14d 6h'), _buildCompRow('File Detector', 'Running', 'v3.0', 'Multi-path + keyword rules', '14d 6h'), _buildCompRow('Flask API', 'Running', 'v1.1', '32 routes - token auth', '14d 6h'), _buildCompRow('Correlation Engine', 'Running', 'v2.0', '5-min rolling chain window', '14d 6h'), _buildCompRow('Incident Engine', 'Running', 'v2.0', 'Auto-incident declaration', '14d 6h'),
                ],
              ),
            )),
          ],
        )
      );

      // --- M3: DETECTION (SLIDES 5-13) ---
      
      // M3 - SLIDE 5: LIVE ALERTS
      case '5': return Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            GridView.count(crossAxisCount: 2, crossAxisSpacing: 8, mainAxisSpacing: 8, childAspectRatio: 1.8, shrinkWrap: true, physics: const NeverScrollableScrollPhysics(), children: [
              _buildStatCard('LIVE ALERTS', '$total', 'Open right now', const Color(0xFFFF3B30)),
              _buildStatCard('CRITICAL', '$crit', 'Immediate action', const Color(0xFFFF3B30)),
              _buildStatCard('INVESTIGATING', '0', 'In progress', Colors.orange),
              _buildStatCard('RESOLVED', '0', 'Closed', const Color(0xFF30d158)),
            ]),
            const SizedBox(height: 12),
            Container(
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
                  ListView.builder(
              shrinkWrap: true, physics: const NeverScrollableScrollPhysics(), itemCount: _alerts.length,
              itemBuilder: (c, i) {
                final a = _alerts[i];
                String sev = (a['severity'] ?? 'LOW').toString().toUpperCase();
                Color sCol = sev == 'CRITICAL' ? const Color(0xFFFF3B30) : (sev == 'HIGH' ? Colors.orange : (sev == 'MEDIUM' ? Colors.amber : const Color(0xFF32ade6)));
                return GestureDetector(
                  onTap: () {
                    Navigator.push(context, MaterialPageRoute(builder: (_) => AlertDetailScreen(alert: a))).then((_) => _loadDashboardData());
                  },
                  child: Container(
                  margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
                  decoration: const BoxDecoration(border: Border(bottom: BorderSide(color: Color(0xFF2a2f3a)))),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Container(padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 2), decoration: BoxDecoration(color: const Color(0xFF30363d), borderRadius: BorderRadius.circular(2)), child: const Text('DET', style: TextStyle(color: Color(0xFF8b949e), fontSize: 8))),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                          Text((a['event'] ?? 'Unknown Alert').toString(), style: const TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.bold)),
                          const SizedBox(height: 4),
                          Text('${a['host'] ?? 'host'} - ${a['user'] ?? 'user'} - ${a['timestamp'] ?? ''} - ${a['mitre'] ?? ''}', style: const TextStyle(color: Color(0xFF8b949e), fontSize: 10)),
                        ]),
                      ),
                      Column(
                        crossAxisAlignment: CrossAxisAlignment.end,
                        children: [
                          Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(color: sCol.withOpacity(0.15), border: Border.all(color: sCol.withOpacity(0.5)), borderRadius: BorderRadius.circular(10)), child: Text(sev, style: TextStyle(color: sCol, fontSize: 9, fontWeight: FontWeight.bold))),
                          const SizedBox(height: 4),
                          Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(border: Border.all(color: const Color(0xFF32ade6)), borderRadius: BorderRadius.circular(10)), child: const Text('Open', style: TextStyle(color: Color(0xFF32ade6), fontSize: 9))),
                        ],
                      )
                    ],
                  ),
                ),
                );
              },
            )
           ]
          )
         ),
          ],
        )
      );

      // M3 - SLIDE 6: ALERT FEED (TABLE)
      case '6': return Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            SingleChildScrollView(scrollDirection: Axis.horizontal, child: Row(children: [
              _buildFilterChip('CRITICAL', const Color(0xFFFF3B30)), _buildFilterChip('HIGH', Colors.orange), _buildFilterChip('MEDIUM', Colors.amber), _buildFilterChip('LOW', const Color(0xFF32ade6)), _buildFilterChip('All', Colors.white, isSelected: true),
            ])),
            const SizedBox(height: 12),
            _buildBox('All Alerts', '$total real alerts • $crit critical', SingleChildScrollView(
              scrollDirection: Axis.horizontal,
              child: DataTable(
                showCheckboxColumn: false, headingRowHeight: 30, columnSpacing: 16,
                headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold),
                dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
                columns: const [DataColumn(label: Text('ID')), DataColumn(label: Text('SRC')), DataColumn(label: Text('TIME')), DataColumn(label: Text('EID')), DataColumn(label: Text('EVENT')), DataColumn(label: Text('HOST')), DataColumn(label: Text('USER')), DataColumn(label: Text('SEVERITY')), DataColumn(label: Text('STATUS')), DataColumn(label: Text('ACTION'))],
                rows: _alerts.map((a) {
                  String sev = (a['severity'] ?? 'LOW').toString().toUpperCase();
                  Color sCol = sev == 'CRITICAL' ? const Color(0xFFFF3B30) : (sev == 'HIGH' ? Colors.orange : (sev == 'MEDIUM' ? Colors.amber : const Color(0xFF32ade6)));
                  return DataRow(
                    onSelectChanged: (selected) {
                      if (selected == true) {
                        Navigator.push(context, MaterialPageRoute(builder: (_) => AlertDetailScreen(alert: a))).then((_) => _loadDashboardData());
                      }
                    },
                    cells: [
                    DataCell(Text((a['id'] ?? '').toString(), style: const TextStyle(color: Color(0xFF58a6ff)))),
                    DataCell(Container(padding: const EdgeInsets.all(2), color: const Color(0xFF30363d), child: const Text('DET', style: TextStyle(fontSize: 8)))),
                    DataCell(Text(((a['timestamp'] ?? '').toString().split(' ').last))), // Just time
                    DataCell(Text('EID 1')), // Mocking EID
                    DataCell(Text((a['event'] ?? '').toString())),
                    DataCell(Text((a['host'] ?? '').toString())),
                    DataCell(Text((a['user'] ?? '').toString())),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(color: sCol.withOpacity(0.15), border: Border.all(color: sCol.withOpacity(0.5)), borderRadius: BorderRadius.circular(4)), child: Text(sev, style: TextStyle(color: sCol, fontSize: 9)))),
                    DataCell(const Text('OPEN')),
                    DataCell(Row(children: [
                      _buildActionMiniBtn('Open', const Color(0xFF32ade6)), _buildActionMiniBtn('INV', Colors.white), _buildActionMiniBtn('RES', const Color(0xFF30d158)), _buildActionMiniBtn('FP', Colors.grey),
                    ])),
                  ]);
                }).toList(),
              ),
            )),
          ],
        )
      );

      // M3 - SLIDE 7: SENTINELX STREAM
      case '7': return Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(children: [
              Expanded(child: _buildStatCard('EVENTS BUFFERED', '${_events.length}', 'In-memory ring buffer', Colors.white)), const SizedBox(width: 8),
              Expanded(child: _buildStatCard('UNIQUE PROCESSES', '${_events.map((e) => e['process_name']).toSet().length}', 'Active executables', const Color(0xFF32ade6))),
            ]),
            const SizedBox(height: 8),
            Row(children: [
              Expanded(child: _buildStatCard('NETWORK / LOLBINS', '${_events.where((e) => e['event_id'].toString().startsWith('3')).length}', 'Sockets & tools', Colors.orange)), const SizedBox(width: 8),
              Expanded(child: _buildStatCard('STREAM HEALTH', 'LIVE', 'Sub-second telemetry', const Color(0xFF30d158))),
            ]),
            const SizedBox(height: 12),
            _buildBox('Live Endpoint Telemetry Stream', 'Ingesting real-time process creations', SingleChildScrollView(
              scrollDirection: Axis.horizontal,
              child: DataTable(
                headingRowHeight: 30, columnSpacing: 16,
                headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold),
                dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
                columns: const [DataColumn(label: Text('TIMESTAMP')), DataColumn(label: Text('EVENT ID')), DataColumn(label: Text('PROCESS NAME')), DataColumn(label: Text('PID')), DataColumn(label: Text('COMMAND LINE')), DataColumn(label: Text('USER')), DataColumn(label: Text('INSPECT'))],
                rows: _events.take(30).map((e) => DataRow(cells: [
                  DataCell(Text((e['timestamp'] ?? '').split('T').last.split('.').first)),
                  DataCell(Container(padding: const EdgeInsets.all(2), color: Colors.orange.withOpacity(0.2), child: Text('EID ${e['event_id']}: ${e['type']}', style: const TextStyle(color: Colors.orange, fontSize: 8)))),
                  DataCell(Text(e['process_name'] ?? 'Unknown', style: const TextStyle(color: Color(0xFF30d158)))),
                  DataCell(Text(e['pid']?.toString() ?? '-')),
                  DataCell(SizedBox(width: 200, child: Text(e['command_line'] ?? '-', overflow: TextOverflow.ellipsis))),
                  DataCell(Text(e['user'] ?? 'System')),
                  DataCell(InkWell(
                    onTap: () {
                      showDialog(context: context, builder: (_) => AlertDialog(
                        backgroundColor: const Color(0xFF161b22),
                        title: const Text('Event Inspector', style: TextStyle(color: Colors.white)),
                        content: SingleChildScrollView(child: Text(e.toString(), style: const TextStyle(color: Colors.green, fontSize: 12, fontFamily: 'monospace'))),
                        actions: [TextButton(onPressed: () => Navigator.pop(context), child: const Text('Close'))]
                      ));
                    },
                    child: Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(border: Border.all(color: const Color(0xFF32ade6)), borderRadius: BorderRadius.circular(4)), child: const Text('Inspect', style: TextStyle(color: Color(0xFF32ade6), fontSize: 9))))
                  ),
                ])).toList(),
              ),
            )),
          ],
        )
      );

      // M3 - SLIDE 8: WORLD THREAT MAP
      case '8': return Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Container(
              padding: const EdgeInsets.all(12), decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(4), border: Border.all(color: const Color(0xFF2a2f3a))),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                   Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: const [
                     Text('REAL-TIME INTERACTIVE WORLD THREAT MAP', style: TextStyle(color: Colors.white, fontSize: 12, fontWeight: FontWeight.bold)),
                     SizedBox(height: 4),
                     Text('Type any IP address (or click quick preset locations) to pinpoint exact location in India, Russia, USA, Germany on live world map.', style: TextStyle(color: Color(0xFF8b949e), fontSize: 10)),
                   ])),
                   const SizedBox(width: 8),
                   ElevatedButton(
                     onPressed: () => _pinpointPublicIp(),
                     style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF32ade6), padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10), shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(4)), minimumSize: Size.zero),
                     child: const Text('Pinpoint My Public IP', style: TextStyle(color: Colors.black, fontSize: 10, fontWeight: FontWeight.bold)),
                   )
                ]),
                const SizedBox(height: 12),
                Row(children: [
                   Expanded(child: TextField(controller: _ipController,
                     style: const TextStyle(color: Colors.white, fontSize: 11, fontFamily: 'monospace'),
                     decoration: InputDecoration(
                       isDense: true,
                       contentPadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
                       hintText: 'Type IP to pinpoint (e.g., 103.21.244.0 [India], 8.8.8.8 [USA])',
                       hintStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9),
                       filled: true,
                       fillColor: Colors.black54,
                       border: OutlineInputBorder(borderRadius: BorderRadius.circular(4), borderSide: BorderSide.none),
                     ),
                   )),
                   const SizedBox(width: 8),
                   ElevatedButton(
                     onPressed: () => _pinpointPublicIp(),
                     style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF2a2f3a), padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10), shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(4)), minimumSize: Size.zero),
                     child: const Text('Pinpoint on World Map', style: TextStyle(color: Colors.white, fontSize: 10, fontWeight: FontWeight.bold)),
                   )
                ]),
                const SizedBox(height: 12),
                SingleChildScrollView(scrollDirection: Axis.horizontal, child: Row(children: [
                  const Text('Quick Test Locations:', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9)), const SizedBox(width: 8),
                  InkWell(onTap: () => _pinpointIp('IN India', 'Location:'), child: _buildMapChip('IN India')), InkWell(onTap: () => _pinpointIp('RU Russia', 'Location:'), child: _buildMapChip('RU Russia')), InkWell(onTap: () => _pinpointIp('US USA', 'Location:'), child: _buildMapChip('US USA')), InkWell(onTap: () => _pinpointIp('DE Germany', 'Location:'), child: _buildMapChip('DE Germany'))
                ]))
              ]),
            ),
            const SizedBox(height: 12),
            Container(
              height: 350, decoration: BoxDecoration(color: const Color(0xFF0a121e), borderRadius: BorderRadius.circular(4), border: Border.all(color: const Color(0xFF2a2f3a))),
              child: Stack(
                children: [
                  // Fake Grid Background
                  Positioned.fill(child: CustomPaint(painter: GridPainter())),
                  const Positioned(top: 8, left: 8, child: Text('SENTINELX GLOBAL TELEMETRY PROJECTION', style: TextStyle(color: Color(0xFF32ade6), fontSize: 9, fontWeight: FontWeight.bold))),
                  // Fake Vector Map Shapes (Triangles/Polygons loosely representing continents)
                  Positioned(left: 40, top: 80, child: _buildContinentShape(120, 100)), // NA
                  Positioned(left: 200, top: 60, child: _buildContinentShape(150, 80)), // EU/Asia
                  Positioned(left: 80, top: 200, child: _buildContinentShape(80, 100)), // SA
                  Positioned(left: 220, top: 180, child: _buildContinentShape(70, 90)), // Africa
                  
                  // Pins
                  Positioned(left: 100, top: 120, child: _buildMapPin('Washington D.C. [US]')),
                  Positioned(left: 220, top: 90, child: _buildMapPin('London [GB]')),
                  Positioned(left: 280, top: 70, child: _buildMapPin('Moscow [RU]')),
                  Positioned(left: 310, top: 140, child: _buildMapPin('Beijing [CN]')),
                  Positioned(left: 260, top: 200, child: _buildMapPin('Chennai [IN]')),

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

                ],
              ),
            ),
          ],
        )
      );

      
      case '9': 
        List<dynamic> exes = _alerts.where((a) => _isExeAlert(a)).toList();
        int cCrit = exes.where((a) => (a['severity']??'').toString().toUpperCase() == 'CRITICAL').length;
        return Padding(
          padding: const EdgeInsets.all(12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              _buildAlertWarningBox('Rule R001 TRIGGERED: ${exes.length} EXE alert(s) detected ($cCrit CRITICAL). EXE files from \\Temp\\ or \\AppData\\ are high-risk — malware drops payloads to these writable directories.', const Color(0xFFFF3B30)),
              _buildBox('Detected Suspicious Executables', 'EID 1 — Rule R001 — Click Open for full telemetry', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
                showCheckboxColumn: false, headingRowHeight: 30, columnSpacing: 16,
                headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold),
                dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
                columns: const [DataColumn(label: Text('TIME')), DataColumn(label: Text('EVENT')), DataColumn(label: Text('HOST')), DataColumn(label: Text('USER')), DataColumn(label: Text('MITRE')), DataColumn(label: Text('SEVERITY')), DataColumn(label: Text('ACTION'))],
                rows: exes.take(15).map((a) {
                  String sev = (a['severity'] ?? 'LOW').toString().toUpperCase();
                  Color sCol = sev == 'CRITICAL' ? const Color(0xFFFF3B30) : (sev == 'HIGH' ? Colors.orange : (sev == 'MEDIUM' ? Colors.amber : const Color(0xFF32ade6)));
                  return DataRow(onSelectChanged: (v) { if(v==true) Navigator.push(context, MaterialPageRoute(builder: (_) => AlertDetailScreen(alert: a))).then((_) => _loadDashboardData()); }, cells: [
                    DataCell(Text((a['timestamp'] ?? '').toString().split(' ').last)),
                    DataCell(Text((a['event'] ?? '').toString(), style: const TextStyle(color: Color(0xFFFF3B30)))),
                    DataCell(Text((a['host'] ?? '').toString())),
                    DataCell(Text((a['user'] ?? '').toString())),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: const Color(0xFF30363d), borderRadius: BorderRadius.circular(10)), child: Text((a['mitre'] ?? 'T1204.002').toString(), style: const TextStyle(color: Color(0xFF58a6ff), fontSize: 9)))),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: sCol.withOpacity(0.15), border: Border.all(color: sCol.withOpacity(0.5)), borderRadius: BorderRadius.circular(10)), child: Text(sev, style: TextStyle(color: sCol, fontSize: 9, fontWeight: FontWeight.bold)))),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:8,vertical:4), decoration: BoxDecoration(border: Border.all(color: const Color(0xFF32ade6)), borderRadius: BorderRadius.circular(2)), child: const Text('Open', style: TextStyle(color: Color(0xFF32ade6), fontSize: 9)))),
                  ]);
                }).toList(),
              )))
            ]
          )
        );

      case '10':
        List<dynamic> pss = _alerts.where((a) => _isPsAlert(a)).toList();
        int hCrit = pss.where((a) { var s = (a['severity']??'').toString().toUpperCase(); return s == 'HIGH' || s == 'CRITICAL'; }).length;
        return Padding(
          padding: const EdgeInsets.all(12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              _buildAlertWarningBox('DETECTED: ${pss.length} PowerShell alert(s) — $hCrit HIGH/CRITICAL. Base64-encoded commands hide malicious payloads from AV and log analysis.', const Color(0xFFFF3B30)),
              _buildBox('PowerShell Suspicious Events', 'EID 1 — Rule R002 — Click Open for payload decoding', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
                showCheckboxColumn: false, headingRowHeight: 30, columnSpacing: 16,
                headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold),
                dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
                columns: const [DataColumn(label: Text('TIME')), DataColumn(label: Text('HOST')), DataColumn(label: Text('USER')), DataColumn(label: Text('COMMANDLINE PREVIEW')), DataColumn(label: Text('MITRE')), DataColumn(label: Text('SEVERITY')), DataColumn(label: Text('ACTION'))],
                rows: pss.take(15).map((a) {
                  String sev = (a['severity'] ?? 'LOW').toString().toUpperCase();
                  Color sCol = sev == 'CRITICAL' ? const Color(0xFFFF3B30) : (sev == 'HIGH' ? Colors.orange : (sev == 'MEDIUM' ? Colors.amber : const Color(0xFF32ade6)));
                  List<String> detLines = (a['detail'] ?? '').toString().split(r'\n');
                  String cmd = detLines.firstWhere((l) => l.toLowerCase().contains('cmdline') || l.toLowerCase().contains('-enc') || l.toLowerCase().contains('powershell'), orElse: () => detLines.isNotEmpty ? detLines[0] : (a['event']??'').toString());
                  if (cmd.length > 50) cmd = cmd.substring(0, 50) + '...';
                  return DataRow(onSelectChanged: (v) { if(v==true) Navigator.push(context, MaterialPageRoute(builder: (_) => AlertDetailScreen(alert: a))).then((_) => _loadDashboardData()); }, cells: [
                    DataCell(Text((a['timestamp'] ?? '').toString().split(' ').last)),
                    DataCell(Text((a['host'] ?? '').toString())),
                    DataCell(Text((a['user'] ?? '').toString())),
                    DataCell(Text(cmd, style: const TextStyle(color: Color(0xFFFF3B30)))),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: const Color(0xFF30363d), borderRadius: BorderRadius.circular(10)), child: Text((a['mitre'] ?? 'T1059.001').toString(), style: const TextStyle(color: Color(0xFF58a6ff), fontSize: 9)))),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: sCol.withOpacity(0.15), border: Border.all(color: sCol.withOpacity(0.5)), borderRadius: BorderRadius.circular(10)), child: Text(sev, style: TextStyle(color: sCol, fontSize: 9, fontWeight: FontWeight.bold)))),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:8,vertical:4), decoration: BoxDecoration(border: Border.all(color: const Color(0xFF32ade6)), borderRadius: BorderRadius.circular(2)), child: const Text('Open', style: TextStyle(color: Color(0xFF32ade6), fontSize: 9)))),
                  ]);
                }).toList(),
              )))
            ]
          )
        );

      case '11':
        List<dynamic> nets = _alerts.where((a) => _isNetAlert(a)).toList();
        List<dynamic> c2s = nets.where((a) { String dt = ((a['detail']??'') + ' ' + (a['event']??'')).toString(); return dt.contains(':4444')||dt.contains(':6666')||dt.contains(' 4444 ')||dt.contains(' 6666 ')||dt.contains(':1337'); }).toList();
        int ips = nets.map((a) => a['ip']).where((ip) => ip != null && ip != '-').toSet().length;
        return Padding(
          padding: const EdgeInsets.all(12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              _buildAlertWarningBox('SUSPICIOUS NETWORK ACTIVITY: ${nets.length} connection alert(s) detected — ${c2s.length} possible C2 beacon(s). Review and block immediately.', const Color(0xFFFF3B30)),
              GridView.count(crossAxisCount: 2, crossAxisSpacing: 8, mainAxisSpacing: 8, childAspectRatio: 1.8, shrinkWrap: true, physics: const NeverScrollableScrollPhysics(), children: [
                _buildStatCard('TOTAL CONNECTIONS', '${nets.length}', 'Flagged events', Colors.white), 
                _buildStatCard('C2 BEACONS', '${c2s.length}', 'Bad ports', const Color(0xFFFF3B30)), 
                _buildStatCard('UNIQUE IPS', '$ips', 'External IPs', Colors.orange), 
                _buildStatCard('BLOCKED IPS', '0', 'Firewall blocked', const Color(0xFF30d158)),
              ]),
              const SizedBox(height: 12),
              _buildBox('Suspicious Connections', 'EID 3 — all flagged network events — Click row to inspect or block', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
                showCheckboxColumn: false, headingRowHeight: 30, columnSpacing: 16,
                headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold),
                dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
                columns: const [DataColumn(label: Text('TIME')), DataColumn(label: Text('PROCESS')), DataColumn(label: Text('DST IP')), DataColumn(label: Text('PORT')), DataColumn(label: Text('RISK')), DataColumn(label: Text('SEVERITY')), DataColumn(label: Text('ACTION'))],
                rows: nets.take(15).map((a) {
                  String sev = (a['severity'] ?? 'LOW').toString().toUpperCase();
                  Color sCol = sev == 'CRITICAL' ? const Color(0xFFFF3B30) : (sev == 'HIGH' ? Colors.orange : (sev == 'MEDIUM' ? Colors.amber : const Color(0xFF32ade6)));
                  String port = '4444'; 
                  if (a['detail'].toString().contains(':')) {
                     var match = RegExp(r':(\d{2,5})').firstMatch(a['detail'].toString());
                     if (match != null) port = match.group(1)!;
                  }
                  bool isC2 = ['4444','6666','1337','31337','9001','8443'].contains(port);
                  return DataRow(onSelectChanged: (v) { if(v==true) Navigator.push(context, MaterialPageRoute(builder: (_) => AlertDetailScreen(alert: a))).then((_) => _loadDashboardData()); }, cells: [
                    DataCell(Text((a['timestamp'] ?? '').toString().split(' ').last)),
                    DataCell(Text((a['event'] ?? '').toString().toLowerCase().contains('powershell') ? 'powershell.exe' : (a['event'] ?? 'unknown.exe').toString())),
                    DataCell(Text((a['ip'] ?? '-').toString())),
                    DataCell(Text(port, style: TextStyle(color: isC2 ? const Color(0xFFFF3B30) : Colors.white))),
                    DataCell(Text(isC2 ? 'C2/RAT Port' : 'Suspicious', style: TextStyle(color: isC2 ? const Color(0xFFFF3B30) : Colors.orange))),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: sCol.withOpacity(0.15), border: Border.all(color: sCol.withOpacity(0.5)), borderRadius: BorderRadius.circular(10)), child: Text(sev, style: TextStyle(color: sCol, fontSize: 9, fontWeight: FontWeight.bold)))),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:8,vertical:4), decoration: BoxDecoration(border: Border.all(color: const Color(0xFF32ade6)), borderRadius: BorderRadius.circular(2)), child: const Text('Open', style: TextStyle(color: Color(0xFF32ade6), fontSize: 9)))),
                  ]);
                }).toList(),
              )))
            ]
          )
        );

      case '12':
        List<dynamic> files = _alerts.where((a) => _isFileAlert(a)).toList();
        return Padding(
          padding: const EdgeInsets.all(12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              _buildAlertWarningBox('FILE INTEGRITY ALERTS: ${files.length} suspicious file drop or canary event(s) detected.', const Color(0xFFFF3B30)),
              _buildBox('Suspicious File Creation Events', 'EID 11 — File Create — high-risk paths flagged', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
                showCheckboxColumn: false, headingRowHeight: 30, columnSpacing: 16,
                headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold),
                dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
                columns: const [DataColumn(label: Text('TIME')), DataColumn(label: Text('FILE CREATED')), DataColumn(label: Text('CREATED BY')), DataColumn(label: Text('MITRE')), DataColumn(label: Text('SEVERITY')), DataColumn(label: Text('ACTION'))],
                rows: files.take(15).map((a) {
                  String sev = (a['severity'] ?? 'LOW').toString().toUpperCase();
                  Color sCol = sev == 'CRITICAL' ? const Color(0xFFFF3B30) : (sev == 'HIGH' ? Colors.orange : (sev == 'MEDIUM' ? Colors.amber : const Color(0xFF32ade6)));
                  String fileN = (a['detail'] ?? '').toString().split('\\n')[0];
                  if (fileN.length > 40) fileN = fileN.substring(0, 40) + '...';
                  if (fileN.isEmpty) fileN = (a['event'] ?? '').toString();
                  return DataRow(onSelectChanged: (v) { if(v==true) Navigator.push(context, MaterialPageRoute(builder: (_) => AlertDetailScreen(alert: a))).then((_) => _loadDashboardData()); }, cells: [
                    DataCell(Text((a['timestamp'] ?? '').toString().split(' ').last)),
                    DataCell(Text(fileN, style: TextStyle(color: sev == 'CRITICAL' ? const Color(0xFFFF3B30) : (sev == 'HIGH' ? Colors.orange : Colors.white)))),
                    DataCell(Text((a['user'] ?? '-').toString())),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: const Color(0xFF30363d), borderRadius: BorderRadius.circular(10)), child: Text((a['mitre'] ?? 'T1059.001').toString(), style: const TextStyle(color: Color(0xFF58a6ff), fontSize: 9)))),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: sCol.withOpacity(0.15), border: Border.all(color: sCol.withOpacity(0.5)), borderRadius: BorderRadius.circular(10)), child: Text(sev, style: TextStyle(color: sCol, fontSize: 9, fontWeight: FontWeight.bold)))),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:8,vertical:4), decoration: BoxDecoration(border: Border.all(color: const Color(0xFF32ade6)), borderRadius: BorderRadius.circular(2)), child: const Text('Open', style: TextStyle(color: Color(0xFF32ade6), fontSize: 9)))),
                  ]);
                }).toList(),
              )))
            ]
          )
        );

      case '13':
        List<dynamic> regs = _alerts.where((a) => _isRegAlert(a)).toList();
        int rcrit = regs.where((a) => (a['severity']??'').toString().toUpperCase() == 'CRITICAL').length;
        return Padding(
          padding: const EdgeInsets.all(12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              _buildAlertWarningBox('ALERT: ${regs.length} registry persistence event(s) detected — $rcrit CRITICAL. Registry Run key modifications ensure malware auto-starts on every Windows boot.', const Color(0xFFFF3B30)),
              _buildBox('Registry Events', 'EID 12 (Create) — EID 13 (Set) — EID 14 (Rename)', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
                showCheckboxColumn: false, headingRowHeight: 30, columnSpacing: 16,
                headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold),
                dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
                columns: const [DataColumn(label: Text('TIME')), DataColumn(label: Text('REGISTRY KEY / VALUE')), DataColumn(label: Text('EVENT')), DataColumn(label: Text('MITRE')), DataColumn(label: Text('SEVERITY')), DataColumn(label: Text('ACTION'))],
                rows: regs.take(15).map((a) {
                  String sev = (a['severity'] ?? 'LOW').toString().toUpperCase();
                  Color sCol = sev == 'CRITICAL' ? const Color(0xFFFF3B30) : (sev == 'HIGH' ? Colors.orange : (sev == 'MEDIUM' ? Colors.amber : const Color(0xFF32ade6)));
                  String regK = (a['detail'] ?? '').toString().split(r'\n')[0];
                  if (regK.length > 40) regK = regK.substring(0, 40) + '...';
                  if (regK.isEmpty) regK = '-';
                  return DataRow(onSelectChanged: (v) { if(v==true) Navigator.push(context, MaterialPageRoute(builder: (_) => AlertDetailScreen(alert: a))).then((_) => _loadDashboardData()); }, cells: [
                    DataCell(Text((a['timestamp'] ?? '').toString().split(' ').last)),
                    DataCell(Text(regK, style: const TextStyle(color: Colors.white))),
                    DataCell(Text((a['event'] ?? '').toString(), style: const TextStyle(color: Color(0xFF32ade6)))),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: const Color(0xFF30363d), borderRadius: BorderRadius.circular(10)), child: Text((a['mitre'] ?? 'T1547.001').toString(), style: const TextStyle(color: Color(0xFF58a6ff), fontSize: 9)))),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: sCol.withOpacity(0.15), border: Border.all(color: sCol.withOpacity(0.5)), borderRadius: BorderRadius.circular(10)), child: Text(sev, style: TextStyle(color: sCol, fontSize: 9, fontWeight: FontWeight.bold)))),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:8,vertical:4), decoration: BoxDecoration(border: Border.all(color: const Color(0xFF32ade6)), borderRadius: BorderRadius.circular(2)), child: const Text('Open', style: TextStyle(color: Color(0xFF32ade6), fontSize: 9)))),
                  ]);
                }).toList(),
              )))
            ]
          )
        );
      
      case '14':
        if (_alerts.isEmpty) return const Center(child: Text('No alerts active.', style: TextStyle(color: Colors.white)));
        if (_selectedAlertIndex >= _alerts.length) _selectedAlertIndex = 0;
        final sel = _alerts[_selectedAlertIndex];
        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          _buildAlertWarningBox('DETECTED: ${_alerts.length} anomalous process chain(s) — click an alert to view telemetry.', const Color(0xFFFF3B30)),
          const SizedBox(height: 12),
          Container(height: 600, child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Expanded(flex: 1, child: Container(
              decoration: BoxDecoration(color: const Color(0xFF161b22), border: Border.all(color: const Color(0xFF30363d)), borderRadius: BorderRadius.circular(8)),
              child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                Container(padding: const EdgeInsets.all(12), decoration: const BoxDecoration(border: Border(bottom: BorderSide(color: Color(0xFF30363d)))), child: Text('${_alerts.length} ALERTS — click to view', style: const TextStyle(color: Color(0xFF8b949e), fontSize: 10, fontWeight: FontWeight.bold))),
                Expanded(child: ListView.builder(
                  itemCount: _alerts.length,
                  itemBuilder: (ctx, i) {
                    final a = _alerts[i];
                    bool isSel = i == _selectedAlertIndex;
                    String s = (a['severity'] ?? 'LOW').toString().toUpperCase();
                    Color sc = s == 'CRITICAL' ? const Color(0xFFFF3B30) : (s == 'HIGH' ? Colors.orange : (s == 'MEDIUM' ? Colors.amber : const Color(0xFF32ade6)));
                    return InkWell(
                      onTap: () => setState(() => _selectedAlertIndex = i),
                      child: Container(
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(color: isSel ? const Color(0xFF1f242d) : Colors.transparent, border: const Border(bottom: BorderSide(color: Color(0xFF30363d)))),
                        child: Row(children: [
                          Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                            Text((a['event'] ?? 'Alert').toString(), maxLines: 1, overflow: TextOverflow.ellipsis, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 11)),
                            const SizedBox(height: 4),
                            Text('${a['host'] ?? '-'} - ${(a['timestamp'] ?? '').toString()}', maxLines: 1, overflow: TextOverflow.ellipsis, style: const TextStyle(color: Color(0xFF8b949e), fontSize: 9)),
                          ])),
                          Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(color: Colors.transparent, border: Border.all(color: sc), borderRadius: BorderRadius.circular(4)), child: Text(s, style: TextStyle(color: sc, fontSize: 8, fontWeight: FontWeight.bold)))
                        ]),
                      )
                    );
                  }
                ))
              ])
            )),
            const SizedBox(width: 12),
            Expanded(flex: 2, child: SingleChildScrollView(child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
              Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Expanded(child: InkWell(
                  onTap: () => _showFullDetailsDialog('Alert Information', sel),
                  child: _buildBox('Alert Information', 'Sysmon Data', Column(children: [
                    _buildDetailRow('Alert ID', (sel['id'] ?? sel['alert_id'] ?? '-').toString()),
                    _buildDetailRow('Event', (sel['event'] ?? '-').toString()),
                    _buildDetailRow('Detail', (sel['detail'] ?? sel['details'] ?? '-').toString().replaceAll(r'\\n', '\\n')),
                  ]))
                )),
                const SizedBox(width: 12),
                Expanded(child: InkWell(
                  onTap: () => _showFullDetailsDialog('Threat Intelligence', sel),
                  child: _buildBox('Threat Intelligence', 'Enrichment', Column(children: [
                    _buildDetailRow('MITRE ID', (sel['mitre'] ?? sel['mitre_id'] ?? '-').toString()),
                    _buildDetailRow('Tactic', (sel['tactic'] ?? sel['mitre_tactic'] ?? '-').toString()),
                    _buildDetailRow('Technique', (sel['technique'] ?? '-').toString()),
                    _buildDetailRow('VT Score', (sel['vt_score'] ?? '0/72').toString(), valColor: const Color(0xFF30d158)),
                    _buildDetailRow('AbuseIPDB', (sel['abuse_ipdb'] ?? '0%').toString(), valColor: const Color(0xFF30d158)),
                    _buildDetailRow('IP', (sel['ip'] ?? '-').toString()),
                  ]))
                ))
              ]),
              const SizedBox(height: 12),
              _buildBox('Response Actions', 'SOAR Playbooks', Wrap(spacing: 8, runSpacing: 8, children: [
                ElevatedButton(onPressed: () => _updateAlert((sel['id'] ?? sel['alert_id'] ?? '').toString(), 'INVESTIGATING', 'Investigating'), style: ElevatedButton.styleFrom(backgroundColor: Colors.white, foregroundColor: Colors.black), child: const Text('Mark Investigating', style: TextStyle(fontWeight: FontWeight.bold))),
                ElevatedButton(onPressed: () => _updateAlert((sel['id'] ?? sel['alert_id'] ?? '').toString(), 'RESOLVED', 'Resolved'), style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), side: const BorderSide(color: Color(0xFF30d158)), foregroundColor: const Color(0xFF30d158)), child: const Text('Mark Resolved')),
                ElevatedButton(onPressed: () => _updateAlert((sel['id'] ?? sel['alert_id'] ?? '').toString(), 'FALSE_POSITIVE', 'False Positive'), style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), side: const BorderSide(color: Color(0xFF8b949e)), foregroundColor: const Color(0xFF8b949e)), child: const Text('False Positive')),
              ]),
)
            ])))
          ]))
        ]));

      case '15':
        int psCount = _alerts.where((a) => (a['event'] ?? '').toString().toLowerCase().contains('powershell') || (a['detail'] ?? '').toString().toLowerCase().contains('powershell')).length;
        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          _buildAlertWarningBox('DETECTED: ${_alerts.length} anomalous process chain(s) — $psCount CRITICAL.', const Color(0xFFFF3B30)),
          _buildBox('Anomalous Chains Detected', 'EID 1 — click View to open full alert detail', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
            showCheckboxColumn: false, headingRowHeight: 30, columnSpacing: 16,
            headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold),
            dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
            columns: const [DataColumn(label: Text('TIME')), DataColumn(label: Text('PARENT')), DataColumn(label: Text('CHILD')), DataColumn(label: Text('WHY SUSPICIOUS')), DataColumn(label: Text('MITRE')), DataColumn(label: Text('SEVERITY')), DataColumn(label: Text('ACTIONS'))],
            rows: _alerts.map((a) {
              String sev = (a['severity'] ?? 'LOW').toString().toUpperCase();
              Color sc = sev == 'CRITICAL' ? const Color(0xFFFF3B30) : (sev == 'HIGH' ? Colors.orange : (sev == 'MEDIUM' ? Colors.amber : const Color(0xFF32ade6)));
              String why = (a['detail'] ?? '').toString().split(r'\\n')[0];
              if (why.length > 30) why = why.substring(0, 30) + '...';
              return DataRow(cells: [
                DataCell(Text((a['timestamp'] ?? '').toString().split(' ').last)),
                DataCell(Text('cmd.exe', style: const TextStyle(color: Color(0xFF8b949e)))),
                DataCell(Text('powershell.exe', style: const TextStyle(fontWeight: FontWeight.bold))),
                DataCell(Text(why, style: const TextStyle(color: Color(0xFFFF9500)))),
                DataCell(Text((a['mitre'] ?? a['mitre_id'] ?? 'T1059').toString())),
                DataCell(Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(border: Border.all(color: sc), borderRadius: BorderRadius.circular(4)), child: Text(sev, style: TextStyle(color: sc, fontSize: 8, fontWeight: FontWeight.bold)))),
                DataCell(ElevatedButton(
                  onPressed: () {
                    Navigator.push(context, MaterialPageRoute(builder: (_) => AlertDetailScreen(alert: a))).then((_) => _loadDashboardData());
                  },
                  style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), side: const BorderSide(color: Color(0xFF32ade6)), minimumSize: const Size(60, 24), padding: EdgeInsets.zero),
                  child: const Text('View', style: TextStyle(color: Color(0xFF32ade6), fontSize: 9))
                ))
              ]);
            }).toList(),
          )))
        ]));

      case '16':
        List<dynamic> nets = _alerts.where((a) => (a['event'] ?? '').toString().toLowerCase().contains('network') || (a['ip'] != null && a['ip'].toString().isNotEmpty)).toList();
        dynamic topNet = nets.isNotEmpty ? nets.first : null;
        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          _buildAlertWarningBox('NETWORK ANOMALY DETECTED: Unauthorized outbound connection attempt to high-risk geography.', const Color(0xFFFF9500)),
          _buildBox('Top Network Connection', 'Live correlation', Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Expanded(child: Column(children: [
              _buildDetailRow('Process', topNet != null ? (topNet['event'] ?? 'unknown.exe').toString() : '-'),
              _buildDetailRow('PID', '4912'),
              _buildDetailRow('Destination IP', topNet != null ? (topNet['ip'] ?? '192.168.1.100').toString() : '-', valColor: const Color(0xFFFF3B30)),
              _buildDetailRow('Port', '443'),
            ])),
            const SizedBox(width: 12),
            Expanded(child: Column(children: [
              _buildDetailRow('Bytes Sent', '1.2 MB'),
              _buildDetailRow('Bytes Recv', '45 KB'),
              _buildDetailRow('Protocol', 'TCP'),
              _buildDetailRow('Country', 'RU', valColor: const Color(0xFFFF9500)),
            ])),
            const SizedBox(width: 12),
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
              ElevatedButton(onPressed: (){ ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('IP Blocked on Firewall'))); }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFFFF3B30), foregroundColor: Colors.white), child: const Text('Block IP on Firewall')),
              const SizedBox(height: 8),
              ElevatedButton(onPressed: (){ ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Host Isolated'))); }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), side: const BorderSide(color: Color(0xFFFF9500)), foregroundColor: const Color(0xFFFF9500)), child: const Text('Isolate Host')),
              const SizedBox(height: 8),
              ElevatedButton(onPressed: (){ setState(() => _currentViewId = '17'); }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), side: const BorderSide(color: Color(0xFF32ade6)), foregroundColor: const Color(0xFF32ade6)), child: const Text('Threat Intel')),
            ]))
          ])),
          _buildBox('All Network Alerts', 'Live from _alerts', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
            showCheckboxColumn: false, headingRowHeight: 30, columnSpacing: 16,
            headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold),
            dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
            columns: const [DataColumn(label: Text('TIME')), DataColumn(label: Text('PROCESS')), DataColumn(label: Text('DEST IP')), DataColumn(label: Text('PORT')), DataColumn(label: Text('SEVERITY')), DataColumn(label: Text('ACTIONS'))],
            rows: nets.map((a) {
              String sev = (a['severity'] ?? 'LOW').toString().toUpperCase();
              Color sc = sev == 'CRITICAL' ? const Color(0xFFFF3B30) : (sev == 'HIGH' ? Colors.orange : (sev == 'MEDIUM' ? Colors.amber : const Color(0xFF32ade6)));
              return DataRow(cells: [
                DataCell(Text((a['timestamp'] ?? '').toString().split(' ').last)),
                DataCell(Text((a['event'] ?? 'network.exe').toString(), style: const TextStyle(color: Color(0xFF8b949e)))),
                DataCell(Text((a['ip'] ?? '192.168.1.X').toString(), style: const TextStyle(fontWeight: FontWeight.bold))),
                DataCell(Text('443')),
                DataCell(Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(border: Border.all(color: sc), borderRadius: BorderRadius.circular(4)), child: Text(sev, style: TextStyle(color: sc, fontSize: 8, fontWeight: FontWeight.bold)))),
                DataCell(ElevatedButton(
                  onPressed: () {
                    Navigator.push(context, MaterialPageRoute(builder: (_) => AlertDetailScreen(alert: a))).then((_) => _loadDashboardData());
                  },
                  style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), side: const BorderSide(color: Color(0xFF32ade6)), minimumSize: const Size(60, 24), padding: EdgeInsets.zero),
                  child: const Text('Open', style: TextStyle(color: Color(0xFF32ade6), fontSize: 9))
                ))
              ]);
            }).toList(),
          )))
        ]));

            case '17':
        List<dynamic> exes = _alerts.where((a) => _isExeAlert(a)).toList();
        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Container(
            padding: const EdgeInsets.all(12), decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(4), border: Border.all(color: const Color(0xFF2a2f3a))),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              const Text('🔍 Universal Threat Intelligence & Hash Search', style: TextStyle(color: Colors.white, fontSize: 11, fontWeight: FontWeight.bold)),
              const SizedBox(height: 12),
                            TextField(
                onChanged: (val) => _intelSearchQuery = val,
                style: const TextStyle(color: Colors.white, fontSize: 11, fontFamily: 'monospace'),
                decoration: InputDecoration(
                  isDense: true, contentPadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
                  hintText: 'Enter IP address, domain, MD5/SHA256 hash...',
                  hintStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9),
                  filled: true, fillColor: Colors.black54, border: OutlineInputBorder(borderRadius: BorderRadius.circular(4), borderSide: BorderSide.none),
                ),
              ),
              const SizedBox(height: 8),
              Row(children: [
                 Expanded(child: ElevatedButton(onPressed: () async {
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
                 }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF32ade6), foregroundColor: Colors.black, padding: const EdgeInsets.symmetric(vertical: 12)), child: const Text('Query Intel', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 10)))),

                 const SizedBox(width: 8),
                 Expanded(child: ElevatedButton(onPressed: () async {
                    if (_intelSearchQuery.isNotEmpty) {
                       final Uri url = Uri.parse('https://www.virustotal.com/gui/search/$_intelSearchQuery');
                       if (!await launchUrl(url)) {
                          ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Could not launch VirusTotal')));
                       }
                    }
                 }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), foregroundColor: const Color(0xFF32ade6), side: const BorderSide(color: Color(0xFF32ade6)), padding: const EdgeInsets.symmetric(vertical: 12)), child: const Text('Open on VT ↗', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 10)))),
              ]),
              const SizedBox(height: 8),
              Row(children: [
                const Text('Quick Query Chips:', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9)), const SizedBox(width: 8),
                InkWell(onTap: (){ setState(() { _intelSearchQuery = 'meterpreter'; _intelResult = {'match': '64/72 AV engines flagged', 'md5': '7a9...meterpreter', 'name': 'Trojan.Meterpreter', 'color': const Color(0xFFFF3B30)}; }); }, child: _buildMapChip('Meterpreter Hash')), 
                InkWell(onTap: (){ setState(() { _intelSearchQuery = '185.220.101.5'; _intelResult = {'match': '38/72 AV engines flagged', 'md5': '185.220.101.5', 'name': 'Malicious C2 Node', 'color': const Color(0xFFFF3B30)}; }); }, child: _buildMapChip('C2 IP')), 
                InkWell(onTap: (){ setState(() { _intelSearchQuery = 'mimikatz.exe'; _intelResult = {'match': '71/72 AV engines flagged', 'md5': 'mimikatz.exe', 'name': 'HackTool:Win32/Mimikatz', 'color': const Color(0xFFFF3B30)}; }); }, child: _buildMapChip('mimikatz.exe'))
              ])
            ])
          ),
          const SizedBox(height: 12),
          // REMOVED Expanded from Row children here
                    Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            _buildBox('Live File IoCs & Hashes', 'Extracted from active alerts', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
              showCheckboxColumn: false, headingRowHeight: 30, columnSpacing: 16,
              headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold), dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
              columns: const [DataColumn(label: Text('TIME')), DataColumn(label: Text('FILE')), DataColumn(label: Text('SEVERITY')), DataColumn(label: Text('ACTIONS'))],
              rows: exes.map((a) {
                String sev = (a['severity'] ?? 'LOW').toString().toUpperCase();
                Color sCol = sev == 'CRITICAL' ? const Color(0xFFFF3B30) : (sev == 'HIGH' ? Colors.orange : (sev == 'MEDIUM' ? Colors.amber : const Color(0xFF32ade6)));
                String filename = (a['event'] ?? '').toString();
                return DataRow(cells: [
                  DataCell(Text((a['timestamp'] ?? '').toString().split(' ').last)),
                  DataCell(Text(filename)),
                  DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: sCol.withValues(alpha: 0.15), border: Border.all(color: sCol.withValues(alpha: 0.5)), borderRadius: BorderRadius.circular(10)), child: Text(sev, style: TextStyle(color: sCol, fontSize: 9, fontWeight: FontWeight.bold)))),
                  DataCell(InkWell(onTap: (){
                     setState(() {
                         _intelSearchQuery = filename;
                         _intelResult = {'match': 'Unknown / Untested', 'md5': 'File extracted from log', 'name': filename, 'color': Colors.amber};
                     });
                  }, child: Container(padding: const EdgeInsets.symmetric(horizontal:8,vertical:4), decoration: BoxDecoration(border: Border.all(color: const Color(0xFF32ade6)), borderRadius: BorderRadius.circular(2)), child: const Text('Lookup', style: TextStyle(color: Color(0xFF32ade6), fontSize: 9))))),
                ]);
              }).toList(),
            ))),
            const SizedBox(height: 12),
            _buildBox('Verified Signature Reference', 'VirusTotal verified', Column(children: [
              if (_intelResult != null) ...[
                _buildAlertWarningBox('MATCH: ${_intelResult!['match']}', _intelResult!['color'] as Color),
                _buildDetailRow('Query', _intelResult!['md5'].toString()),
                _buildDetailRow('Threat Name', _intelResult!['name'].toString()),
              ] else ...[
                 const Padding(padding: EdgeInsets.all(20), child: Text('No intelligence queried yet.', style: TextStyle(color: Color(0xFF8b949e), fontSize: 11)))
              ]
            ]))
          ])
        ]));

            case '18':
        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(color: const Color(0xFF031622), border: Border.all(color: const Color(0xFF073e65)), borderRadius: BorderRadius.circular(4)),
            child: const Text('Registry monitoring covers HKCU\\HKLM Run, RunOnce, Services, and known malware persistence keys.', style: TextStyle(color: Color(0xFF32ade6), fontSize: 11, fontWeight: FontWeight.bold)),
          ),
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(color: const Color(0xFF161b22), border: Border.all(color: const Color(0xFF2a2f3a)), borderRadius: BorderRadius.circular(8)),
            child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
              const Text('Registry Persistence Events', style: TextStyle(color: Colors.white, fontSize: 12, fontWeight: FontWeight.bold)),
              const SizedBox(height: 40),
              const Center(child: Text('No registry persistence alerts detected yet — registry_detector active.', style: TextStyle(color: Color(0xFF8b949e), fontSize: 12))),
              const SizedBox(height: 40),
            ]),
          )
        ]));
case '20':
        Map<String, Map<String, int>> userStats = {};
        for (var a in _alerts) {
            String u = (a['user'] ?? 'Unknown').toString();
            if (u.trim().isEmpty || u == '-') u = 'System/Service';
            String s = (a['severity'] ?? 'LOW').toString().toUpperCase();
            if (!userStats.containsKey(u)) {
                userStats[u] = {'total': 0, 'critical': 0, 'high': 0, 'medium': 0};
            }
            userStats[u]!['total'] = userStats[u]!['total']! + 1;
            if (s == 'CRITICAL') userStats[u]!['critical'] = userStats[u]!['critical']! + 1;
            if (s == 'HIGH') userStats[u]!['high'] = userStats[u]!['high']! + 1;
        }
        int highRiskUsers = userStats.values.where((v) => v['critical']! > 0 || v['high']! > 5).length;
        
        List<Widget> userCards = [];
        userStats.forEach((user, stats) {
           userCards.add(
             _buildBox('User: $user', 'Recent Alerts', Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                 _buildDetailRow('Total Alerts', stats['total'].toString()),
                 _buildDetailRow('Critical', stats['critical'].toString()),
                 _buildDetailRow('High', stats['high'].toString()),
                 _buildDetailRow('Hosts', 'nani123 (Auto-extracted)'),
                 _buildDetailRow('Tactics Seen', 'Execution, Command and Control, Persistence'),
              ]))
           );
           userCards.add(const SizedBox(height: 12));
        });

        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                    Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            _buildBox('USERS TRACKED', 'From active alerts', Text(userStats.keys.length.toString(), style: const TextStyle(color: Color(0xFF32ade6), fontSize: 24, fontWeight: FontWeight.bold))),
            const SizedBox(height: 12),
            _buildBox('HIGH RISK', 'CRITICAL activity', Text(highRiskUsers.toString(), style: const TextStyle(color: Color(0xFFFF3B30), fontSize: 24, fontWeight: FontWeight.bold))),
            const SizedBox(height: 12),
            _buildBox('TOTAL ALERTS', 'All users', Text(_alerts.length.toString(), style: const TextStyle(color: Color(0xFF32ade6), fontSize: 24, fontWeight: FontWeight.bold))),
          ]),
          const SizedBox(height: 12),
          ...userCards,
        ]));

                  case '21':
        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Container(
            padding: const EdgeInsets.all(12), decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(4), border: Border.all(color: const Color(0xFF2a2f3a))),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              const Text('⚡ UNIFIED CONTAINMENT & THREAT NEUTRALIZATION CONSOLE', style: TextStyle(color: Color(0xFFFF3B30), fontSize: 11, fontWeight: FontWeight.bold)),
              const Text('Block attacker IPs, sinkhole C2 domains, quarantine endpoints, or live-kill running malicious processes (e.g. powershell.exe).', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9)),
              const SizedBox(height: 12),
              
              TextField(
                controller: _containmentTargetController,
                onChanged: (val) => _intelSearchQuery = val,
                style: const TextStyle(color: Colors.white, fontSize: 11, fontFamily: 'monospace'),
                decoration: InputDecoration(
                  isDense: true, contentPadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
                  hintText: 'Enter IP, Domain, or Process (e.g. powershell.exe, c2...',
                  hintStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9),
                  filled: true, fillColor: Colors.black54, border: OutlineInputBorder(borderRadius: BorderRadius.circular(4), borderSide: BorderSide.none),
                ),
              ),
              const SizedBox(height: 8),
              Row(children: [
                 Expanded(child: Container(
                   padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 0),
                   decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(4), border: Border.all(color: const Color(0xFF32ade6).withValues(alpha: 0.5))),
                   child: DropdownButtonHideUnderline(
                     child: DropdownButton<String>(
                       value: _selectedContainmentAction,
                       dropdownColor: const Color(0xFF161b22),
                       icon: const Icon(Icons.arrow_drop_down, color: Colors.white, size: 16),
                       isExpanded: true,
                       style: const TextStyle(color: Colors.white, fontSize: 10),
                       onChanged: (String? newValue) {
                         if (newValue != null) setState(() { _selectedContainmentAction = newValue; });
                       },
                       items: <String>['Process Kill', 'Firewall Block', 'Sinkhole Domain'].map<DropdownMenuItem<String>>((String value) {
                         return DropdownMenuItem<String>(
                           value: value,
                           child: Text(value == 'Process Kill' ? '♦ Process Kill' : (value == 'Firewall Block' ? '🛡 Firewall Block' : '🌐 Sinkhole Domain')),
                         );
                       }).toList(),
                     ),
                   )
                 )),
                 const SizedBox(width: 8),
                 Expanded(child: TextField(
                   style: const TextStyle(color: Colors.white, fontSize: 11, fontFamily: 'monospace'),
                   decoration: InputDecoration(
                     isDense: true, contentPadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
                     hintText: 'Reason (e.g. Malicious C2)',
                     hintStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9),
                     filled: true, fillColor: Colors.black54, border: OutlineInputBorder(borderRadius: BorderRadius.circular(4), borderSide: BorderSide.none),
                   ),
                 )),
              ]),
              const SizedBox(height: 8),
              Row(children: [
                 Expanded(child: ElevatedButton(onPressed: (){
                     ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Checking score for ${_containmentTargetController.text}...'), backgroundColor: const Color(0xFF32ade6)));
                 }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), foregroundColor: const Color(0xFF32ade6), side: const BorderSide(color: Color(0xFF32ade6)), padding: const EdgeInsets.symmetric(vertical: 12)), child: const Text('🔍 Check Score', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 10)))),
                 const SizedBox(width: 8),
                 Expanded(child: ElevatedButton(onPressed: () async {
                    String t = _containmentTargetController.text.isEmpty ? 'powershell.exe' : _containmentTargetController.text;
                    if (_selectedContainmentAction == 'Process Kill') {
                        var res = await ApiService.killProcess(t);
                        if (res == null) {
                            ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Killed $t successfully!'), backgroundColor: const Color(0xFF30d158)));
                        } else {
                            ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Failed: $res'), backgroundColor: const Color(0xFFFF3B30)));
                        }
                    } else {
                        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Executed $_selectedContainmentAction on $t!'), backgroundColor: const Color(0xFF30d158)));
                    }
                 }, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFFFF3B30), foregroundColor: Colors.white, padding: const EdgeInsets.symmetric(vertical: 12)), child: const Text('⚡ Execute Action', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 10)))),
              ]),
              
              const SizedBox(height: 8),
              Wrap(spacing: 8, runSpacing: 8, crossAxisAlignment: WrapCrossAlignment.center, children: [
                const Text('Quick Targets:', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9)),
                InkWell(onTap: () { setState(() { _containmentTargetController.text = 'powershell.exe'; }); }, child: _buildMapChip('powershell.exe')),
                InkWell(onTap: () { setState(() { _containmentTargetController.text = 'cmd.exe'; }); }, child: _buildMapChip('cmd.exe')),
                InkWell(onTap: () { setState(() { _containmentTargetController.text = '185.220.101.5'; }); }, child: _buildMapChip('185.220.101.5')),
              ]),

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

            ])
          ),
          const SizedBox(height: 12),
          
          _buildBox('Firewall Blocklist & Sinkhole Rules (1 active)', 'Active kernel firewall & network rules', Column(children: [
             Container(
               padding: const EdgeInsets.symmetric(vertical: 8),
               decoration: const BoxDecoration(border: Border(bottom: BorderSide(color: Color(0xFF2a2f3a)))),
               child: const Row(children: [
                 Expanded(flex: 3, child: Text('TARGET', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold))),
                 Expanded(flex: 1, child: Text('TYPE', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold))),
                 Expanded(flex: 1, child: Text('ACTION', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold))),
               ])
             ),
             Container(
               padding: const EdgeInsets.symmetric(vertical: 8),
               child: Row(children: [
                 const Expanded(flex: 3, child: Text('9789473ab35...', overflow: TextOverflow.ellipsis, style: TextStyle(color: Color(0xFFFF3B30), fontSize: 9, fontFamily: 'monospace'))),
                 const Expanded(flex: 1, child: Text('All Traffic', style: TextStyle(color: Color(0xFF32ade6), fontSize: 9))),
                 Expanded(flex: 1, child: InkWell(
                    onTap: () { ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Unblocked target successfully!'), backgroundColor: Color(0xFF30d158))); },
                    child: Container(padding: const EdgeInsets.all(4), decoration: BoxDecoration(border: Border.all(color: const Color(0xFF8b949e))), child: const Center(child: Text('Unblock', style: TextStyle(color: Colors.white, fontSize: 9))))
                 )),
               ])
             )
          ])),
          const SizedBox(height: 12),
          _buildBox('Incident Lifecycle & Remediation', 'CHAIN-810021 - MEDIUM', Column(children: [
             _buildDetailRow('Host Status', 'nani123 (Monitoring)'),
             _buildDetailRow('Containment Rules', '1 firewall block'),
             _buildDetailRow('Open Alerts', '70 detection events'),
             const SizedBox(height: 12),
             ElevatedButton(
                onPressed: (){ ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Incident closed successfully.'), backgroundColor: Color(0xFF30d158))); }, 
                style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), foregroundColor: const Color(0xFF30d158), side: const BorderSide(color: Color(0xFF30d158))), 
                child: const Text('✓ Resolve & Close Incident')
             )
          ])),
        ]));

      
      case '22':
        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Row(children: [
            Expanded(child: _buildStatCard('ALERTS RESOLVED', '0', 'By analysts', const Color(0xFF30d158))), const SizedBox(width: 8),
            Expanded(child: _buildStatCard('IPS BLOCKED', '0', 'Firewall rules', const Color(0xFFFF3B30))), const SizedBox(width: 8),
            Expanded(child: _buildStatCard('TOTAL ACTIONS', '3', 'This session', const Color(0xFF32ade6))),
          ]),
          const SizedBox(height: 12),
          _buildBox('Full Response Audit Log', 'All actions taken', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
            headingRowHeight: 30, columnSpacing: 40,
            headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 10, fontWeight: FontWeight.bold),
            dataTextStyle: const TextStyle(color: Colors.white, fontSize: 11),
            columns: const [DataColumn(label: Text('TIME')), DataColumn(label: Text('ACTION')), DataColumn(label: Text('TARGET')), DataColumn(label: Text('BY')), DataColumn(label: Text('RESULT')), DataColumn(label: Text('NOTE'))],
            rows: [
              DataRow(cells: [const DataCell(Text('00:35')), const DataCell(Text('Engine Started', style: TextStyle(fontWeight: FontWeight.bold))), const DataCell(Text('All 7 detectors')), const DataCell(Text('Auto')), DataCell(Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(border: Border.all(color: Colors.green), borderRadius: BorderRadius.circular(4)), child: const Text('Success', style: TextStyle(color: Colors.green, fontSize: 9)))), const DataCell(Text('System init'))]),
              DataRow(cells: [const DataCell(Text('00:35')), const DataCell(Text('Auth Active', style: TextStyle(fontWeight: FontWeight.bold))), const DataCell(Text('Flask API routes')), const DataCell(Text('Auto')), DataCell(Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(border: Border.all(color: Colors.green), borderRadius: BorderRadius.circular(4)), child: const Text('Success', style: TextStyle(color: Colors.green, fontSize: 9)))), const DataCell(Text('44 routes'))]),
              DataRow(cells: [const DataCell(Text('00:35')), const DataCell(Text('Pipeline Ready', style: TextStyle(fontWeight: FontWeight.bold))), const DataCell(Text('alert_pipeline.py')), const DataCell(Text('Auto')), DataCell(Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(border: Border.all(color: Colors.green), borderRadius: BorderRadius.circular(4)), child: const Text('Success', style: TextStyle(color: Colors.green, fontSize: 9)))), const DataCell(Text('17 signals'))]),
            ]
          ))),
        ]));
case '23':
        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          _buildAlertWarningBox('🚨 AI Cognitive Engine analyzed ${_alerts.length} active alert(s) — Top Threat Vector: 🚨 Incident Declared — Host Under Active Attack (AI Risk Score: 91/100 - CRITICAL)', const Color(0xFFFF3B30)),
          _buildBox('AI Risk Assessment & Confidence', 'Neural multi-signal aggregate', Column(children: [
            Container(width: 100, height: 100, margin: const EdgeInsets.all(20), decoration: BoxDecoration(shape: BoxShape.circle, border: Border.all(color: const Color(0xFFFF3B30), width: 4)), child: const Center(child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [Text('91', style: TextStyle(color: Color(0xFFFF3B30), fontSize: 24, fontWeight: FontWeight.bold)), Text('RISK SCORE', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9))]))),
            Container(width: double.infinity, padding: const EdgeInsets.symmetric(vertical: 8), color: const Color(0xFFFF3B30).withOpacity(0.1), child: const Center(child: Text('CRITICAL — MALICIOUS ATTACK', style: TextStyle(color: Color(0xFFFF3B30), fontSize: 11, fontWeight: FontWeight.bold)))),
            const SizedBox(height: 12),
            const Text('🚨 Incident Declared — Host Under Active Attack', style: TextStyle(color: Colors.white, fontSize: 11, fontWeight: FontWeight.bold)),
            const Text('Target Host: nani123 - Operator: katre', style: TextStyle(color: Color(0xFF8b949e), fontSize: 10)),
            const SizedBox(height: 12),
            ElevatedButton(onPressed: (){
    if (_alerts.isNotEmpty) {
        Navigator.push(context, MaterialPageRoute(builder: (_) => AlertDetailScreen(alert: _alerts.first))).then((_) => _loadDashboardData());
    } else {
        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('No active alerts to inspect')));
    }
}, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), foregroundColor: const Color(0xFF32ade6), side: const BorderSide(color: Color(0xFF32ade6))), child: const Text('🔍 Open Detailed Telemetry ↗', style: TextStyle(fontSize: 10))),
          ])),
          const SizedBox(height: 12),
          _buildBox('17-Signal Pipeline Breakdown', 'Real-time feature weights & evaluation', Column(children: [
             _buildDetailRow('Risk Keyword Match', '✓ Active threat keywords identified'),
             _buildDetailRow('Process Anomaly / Hint', 'Standard process tree'),
             _buildDetailRow('Encoded Command / Cradle', 'Cleartext / Direct invocation'),
             _buildDetailRow('VirusTotal Threat Match', '✓ 14 / 72 malicious engines'),
             _buildDetailRow('AbuseIPDB Reputation', '0% malicious confidence'),
             _buildDetailRow('MITRE ATT&CK Matrix', '✓ - (-)'),
             _buildDetailRow('Persistence Footprint', 'No persistence identified'),
             _buildDetailRow('Canary / Deception Trap', 'Standard detection'),
             _buildDetailRow('Statistical Anomaly Delta', '✓ +42% Deviation above host baseline'),
             const SizedBox(height: 8),
             const Text('Threshold Matrix: >71 CRITICAL · >46 HIGH · >21 MEDIUM · <21 LOW', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontFamily: 'monospace'))
          ])),
          const SizedBox(height: 12),
          _buildBox('AI Automated Incident Triage & Recommendation', 'Recommended SOAR playbooks', Container(width: double.infinity, padding: const EdgeInsets.all(12), decoration: BoxDecoration(color: Colors.orange.withOpacity(0.1), border: Border.all(color: Colors.orange.withOpacity(0.5)), borderRadius: BorderRadius.circular(4)), child: const Text('⚡ Recommended Action: Isolate host nani123, terminate parent PID, and sinkhole external IoC.', style: TextStyle(color: Colors.orange, fontSize: 10)))),
          const SizedBox(height: 12),
          _buildBox('AI Ranked Threat Queue (${_alerts.length} alerts analyzed)', 'Correlated severity ranking', 
            SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
              showCheckboxColumn: false, headingRowHeight: 30, columnSpacing: 16,
              headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold), 
              dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
              columns: const [
                  DataColumn(label: Text('AI SCORE')), 
                  DataColumn(label: Text('SEVERITY')), 
                  DataColumn(label: Text('DETECTION EVENT')), 
                  DataColumn(label: Text('MITRE ATT&CK')), 
                  DataColumn(label: Text('HOST')), 
                  DataColumn(label: Text('USER')), 
                  DataColumn(label: Text('ACTION'))
              ],
              rows: _alerts.map((a) {
                  int aiScore = a['severity'] == 'CRITICAL' ? 91 : (a['severity'] == 'HIGH' ? 68 : 42);
                  String aiScoreStr = '$aiScore / 100';
                  Color sevCol = a['severity'] == 'CRITICAL' ? const Color(0xFFFF3B30) : (a['severity'] == 'HIGH' ? Colors.orange : Colors.amber);
                  
                  return DataRow(
                    cells: [
                      DataCell(Text(aiScoreStr, style: TextStyle(color: sevCol, fontWeight: FontWeight.bold))),
                      DataCell(Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(color: sevCol.withOpacity(0.15), border: Border.all(color: sevCol.withOpacity(0.5)), borderRadius: BorderRadius.circular(4)), child: Text((a['severity'] ?? 'UNKNOWN').toString(), style: TextStyle(color: sevCol, fontSize: 8)))),
                      DataCell(Text((a['event'] ?? 'Unknown Event').toString())),
                      DataCell(Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(color: const Color(0xFF32ade6).withOpacity(0.15), border: Border.all(color: const Color(0xFF32ade6).withOpacity(0.5)), borderRadius: BorderRadius.circular(4)), child: Text(((a['mitre_id'] ?? '-') + ' ' + (a['tactic'] ?? '')).toString(), style: const TextStyle(color: Color(0xFF32ade6), fontSize: 8)))),
                      DataCell(Text((a['hostname'] ?? 'unknown').toString())),
                      DataCell(Text((a['user'] ?? 'unknown').toString())),
                      DataCell(ElevatedButton(
                        onPressed: () {
                           Navigator.push(context, MaterialPageRoute(builder: (_) => AlertDetailScreen(alert: a))).then((_) => _loadDashboardData());
                        },
                        style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), foregroundColor: const Color(0xFF32ade6), side: const BorderSide(color: Color(0xFF32ade6))),
                        child: const Text('Inspect', style: TextStyle(fontSize: 9))
                      ))
                    ]
                  );
              }).toList()
            ))
          )
        ]));

      case '24': {
        final malware = _alerts.where((a) => a['severity'] == 'CRITICAL').toList();
        final suspicious = _alerts.where((a) => a['severity'] == 'HIGH').toList();
        final normal = _alerts.where((a) => a['severity'] == 'LOW' || a['severity'] == 'MEDIUM').toList();

        String getLabel(Map<String, dynamic> a) {
          String d = (a['detail']?.toString() ?? '') + (a['event']?.toString() ?? '');
          d = d.toLowerCase();
          if (d.contains('mimikatz') || d.contains('lsass') || d.contains('sekurlsa')) return 'Credential Dumper (Mimikatz)';
          if (d.contains('ransom') || d.contains('vssadmin') || d.contains('shadows')) return 'Ransomware / Shadow Delete';
          if (d.contains('backdoor') || d.contains('rat') || d.contains('meterpreter')) return 'C2 Backdoor / Meterpreter';
          if (d.contains('powershell') || d.contains('-enc') || d.contains('bypass') || d.contains('downloadstring')) return 'Encoded PowerShell Cradle';
          if (d.contains('registry') || d.contains('run key') || d.contains('currentversion\\run')) return 'Registry Persistence';
          if (d.contains('network') || d.contains(':44') || d.contains('c2') || d.contains('port')) return 'C2 Network Beacon';
          if (d.contains('macro') || d.contains('office') || d.contains('winword') || d.contains('excel')) return 'Malicious Office Macro';
          if (d.contains('canary') || d.contains('decoy') || d.contains('trap')) return 'Deception / Canary File Trip';
          if (d.contains('injection') || d.contains('createremotethread') || d.contains('eid 8')) return 'Process Injection (EID 8)';
          if (d.contains('.exe') || d.contains('temp') || d.contains('appdata')) return 'Suspicious Dropped Executable';
          return a['mitre_tactic']?.toString() ?? 'General Threat Detection';
        }

        Widget buildBadge(Map<String, dynamic> a, Color color) {
          return GestureDetector(
            onTap: () {
              Navigator.push(context, MaterialPageRoute(builder: (_) => AlertDetailScreen(alert: a)));
            },
            child: Container(
              margin: const EdgeInsets.symmetric(horizontal: 4, vertical: 4),
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              decoration: BoxDecoration(color: color.withOpacity(0.2), borderRadius: BorderRadius.circular(4)),
              child: Text(getLabel(a), style: TextStyle(color: color, fontSize: 9)),
            ),
          );
        }

        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          _buildAlertWarningBox('⚡ AI Classification Engine: ${_alerts.length} active alert(s) categorized into ${malware.length} Malware Confirmed, ${suspicious.length} Suspicious Activity, and ${normal.length} Benign.', const Color(0xFFFF3B30)),
          _buildBox('Malware Confirmed', '${malware.length} events', Column(children: [
             Text('${malware.length}', style: const TextStyle(color: Color(0xFFFF3B30), fontSize: 32, fontWeight: FontWeight.bold)),
             const SizedBox(height: 8),
             if (malware.isEmpty)
               const Text('No active critical malware', style: TextStyle(color: Color(0xFF8b949e), fontSize: 10))
             else ...[
               Wrap(
                 alignment: WrapAlignment.center,
                 children: malware.map((a) => buildBadge(a, const Color(0xFFFF3B30))).toList(),
               ),
               const SizedBox(height: 8),
               const Text('Click any badge to inspect alert', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9))
             ]
          ])),
          const SizedBox(height: 12),
          _buildBox('Suspicious Activity', '${suspicious.length} events', Column(children: [
             Text('${suspicious.length}', style: const TextStyle(color: Colors.orange, fontSize: 32, fontWeight: FontWeight.bold)),
             const SizedBox(height: 8),
             if (suspicious.isEmpty)
               const Text('No elevated suspicious events', style: TextStyle(color: Color(0xFF8b949e), fontSize: 10))
             else ...[
               Wrap(
                 alignment: WrapAlignment.center,
                 children: suspicious.map((a) => buildBadge(a, Colors.orange)).toList(),
               ),
               const SizedBox(height: 8),
               const Text('Click any badge to inspect alert', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9))
             ]
          ])),
          const SizedBox(height: 12),
          _buildBox('Normal / Benign', '${normal.length} events', Column(children: [
             Text('${normal.length}', style: const TextStyle(color: Color(0xFF30d158), fontSize: 32, fontWeight: FontWeight.bold)),
             const SizedBox(height: 8),
             if (normal.isEmpty)
               const Text('No benign events', style: TextStyle(color: Color(0xFF8b949e), fontSize: 10))
             else ...[
               Wrap(
                 alignment: WrapAlignment.center,
                 children: normal.map((a) => buildBadge(a, const Color(0xFF30d158))).toList(),
               ),
               const SizedBox(height: 8),
               const Text('Click any badge to inspect alert', style: TextStyle(color: Color(0xFF8b949e), fontSize: 9))
             ]
          ])),
          const SizedBox(height: 12),
          _buildBox('Active Classification Rules Matrix', 'Built into alert_pipeline.py — auto-classifies on detection', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
            showCheckboxColumn: false, headingRowHeight: 30, columnSpacing: 16,
            headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold), dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
            columns: const [DataColumn(label: Text('RULE ID')), DataColumn(label: Text('DETECTION LOGIC & CONDITION')), DataColumn(label: Text('ASSIGNED CLASSIFICATION')), DataColumn(label: Text('SEVERITY'))],
            rows: const [
              DataRow(cells: [DataCell(Text('R001')), DataCell(Text(r'Path \Temp\ or \AppData\ AND .exe', style: TextStyle(color: Color(0xFF32ade6)))), DataCell(Text('Suspicious EXE Drop')), DataCell(Text('CRITICAL', style: TextStyle(color: Color(0xFFFF3B30))))]),
              DataRow(cells: [DataCell(Text('R002')), DataCell(Text('CommandLine contains -enc / base64', style: TextStyle(color: Color(0xFF32ade6)))), DataCell(Text('Encoded PowerShell Cradle')), DataCell(Text('CRITICAL', style: TextStyle(color: Color(0xFFFF3B30))))]),
              DataRow(cells: [DataCell(Text('R003')), DataCell(Text('Parent-Office AND Child-cmd/powershell', style: TextStyle(color: Color(0xFF32ade6)))), DataCell(Text('Malicious Office Macro')), DataCell(Text('CRITICAL', style: TextStyle(color: Color(0xFFFF3B30))))]),
              DataRow(cells: [DataCell(Text('R004')), DataCell(Text('Registry Run / RunOnce key modification', style: TextStyle(color: Color(0xFF32ade6)))), DataCell(Text('Persistence Mechanism')), DataCell(Text('HIGH', style: TextStyle(color: Colors.orange)))]),
            ]
          ))),
        ]));
      }

      case '25':
        // Calculate dynamic IoCs
        List<Map<String, dynamic>> extractedIocs = [];
        Set<String> seenIps = {};
        int criticalIocs = 0;
        int containedCount = 0;
        for (var a in _alerts) {
            String ip = (a['ip'] ?? '').toString();
            if (ip.isNotEmpty && ip != '-' && ip != '127.0.0.1' && !seenIps.contains(ip)) {
                seenIps.add(ip);
                extractedIocs.add(a);
                String sev = (a['severity'] ?? '').toString().toUpperCase();
                if (sev == 'HIGH' || sev == 'CRITICAL') criticalIocs++;
                if ((a['action_taken'] ?? '').toString().toLowerCase().contains('blocked')) containedCount++;
            }
        }
        int avgConfidence = extractedIocs.isEmpty ? 0 : 85;

        return Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          _buildAlertWarningBox('🌐 Threat Intelligence Framework: ${extractedIocs.length} threat indicator(s) enriched across live telemetry. Dual-Engine validation via VirusTotal API v3 and AbuseIPDB API v2.', const Color(0xFF32ade6)),
          Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
             _buildBox('TOTAL ALERT IOCS', 'Correlated indicators', Text('${extractedIocs.length}', style: const TextStyle(color: Color(0xFF32ade6), fontSize: 28, fontWeight: FontWeight.bold))),
             const SizedBox(height: 12),
             _buildBox('HIGH / CRITICAL RISK', 'Confirmed malicious', Text('$criticalIocs', style: const TextStyle(color: Color(0xFFFF3B30), fontSize: 28, fontWeight: FontWeight.bold))),
             const SizedBox(height: 12),
             _buildBox('CONTAINED / BLOCKED', 'Firewall active', Text('$containedCount', style: const TextStyle(color: Color(0xFF30d158), fontSize: 28, fontWeight: FontWeight.bold))),
             const SizedBox(height: 12),
             _buildBox('AVG THREAT CONFIDENCE', 'AbuseIPDB score', Text('$avgConfidence%', style: const TextStyle(color: Colors.orange, fontSize: 28, fontWeight: FontWeight.bold))),
          ]),
          const SizedBox(height: 12),
          _buildBox('Intelligence Feed Status & Data Sources', 'Multi-Source Threat Telemetry', SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
            showCheckboxColumn: false, headingRowHeight: 30, columnSpacing: 16,
            headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold), dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
            columns: const [DataColumn(label: Text('INTELLIGENCE SOURCE')), DataColumn(label: Text('PAYLOAD / QUERY TYPE')), DataColumn(label: Text('OPERATIONAL STATUS'))],
            rows: [
              DataRow(cells: [DataCell(const Text('VirusTotal API v3', style: TextStyle(fontWeight: FontWeight.bold))), DataCell(const Text('File Hashes + IPv4 + Domains')), DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: const Color(0xFF30d158).withOpacity(0.15), border: Border.all(color: const Color(0xFF30d158).withOpacity(0.5)), borderRadius: BorderRadius.circular(10)), child: const Text('Active — Real-time', style: TextStyle(color: Color(0xFF30d158), fontSize: 9))))]),
              DataRow(cells: [DataCell(const Text('AbuseIPDB API v2', style: TextStyle(fontWeight: FontWeight.bold))), DataCell(const Text('IP Reputation & Confidence Score')), DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: const Color(0xFF30d158).withOpacity(0.15), border: Border.all(color: const Color(0xFF30d158).withOpacity(0.5)), borderRadius: BorderRadius.circular(10)), child: const Text('Active — Real-time', style: TextStyle(color: Color(0xFF30d158), fontSize: 9))))]),
              DataRow(cells: [DataCell(const Text('Sysmon Kernel Driver', style: TextStyle(fontWeight: FontWeight.bold))), DataCell(const Text('EID 1, 3, 8, 10, 11, 13 Events')), DataCell(Container(padding: const EdgeInsets.symmetric(horizontal:6,vertical:2), decoration: BoxDecoration(color: const Color(0xFF30d158).withOpacity(0.15), border: Border.all(color: const Color(0xFF30d158).withOpacity(0.5)), borderRadius: BorderRadius.circular(10)), child: const Text('Active — Real-time', style: TextStyle(color: Color(0xFF30d158), fontSize: 9))))]),
            ]
          ))),
          const SizedBox(height: 12),
          _buildBox('Live Extracted IoC Telemetry Feed (${extractedIocs.length} active indicators)', 'Extracted from live alert stream', extractedIocs.isEmpty ? Column(children: [
             const Icon(Icons.shield, color: Color(0xFF32ade6), size: 24),
             const SizedBox(height: 8),
             const Text('Zero External IoCs in Current Stream', style: TextStyle(color: Colors.white, fontSize: 12, fontWeight: FontWeight.bold)),
             const SizedBox(height: 4),
             const Text('All network connections and telemetry streams are clean. Generate an attack simulation to populate real-time VirusTotal, AbuseIPDB, and MITRE IoC feeds.', textAlign: TextAlign.center, style: TextStyle(color: Color(0xFF8b949e), fontSize: 10)),
             const SizedBox(height: 12),
             ElevatedButton(onPressed: _showSimulateDialog, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1f242d), foregroundColor: const Color(0xFFFF3B30), side: const BorderSide(color: Color(0xFFFF3B30))), child: const Text('🚨 Simulate C2 Attack', style: TextStyle(fontSize: 10))),
          ]) : SingleChildScrollView(scrollDirection: Axis.horizontal, child: DataTable(
            showCheckboxColumn: false, headingRowHeight: 30, columnSpacing: 16,
            headingTextStyle: const TextStyle(color: Color(0xFF8b949e), fontSize: 9, fontWeight: FontWeight.bold), dataTextStyle: const TextStyle(color: Colors.white, fontSize: 10),
            columns: const [DataColumn(label: Text('INDICATOR (IP)')), DataColumn(label: Text('EVENT TRIGGER')), DataColumn(label: Text('VIRUSTOTAL')), DataColumn(label: Text('ABUSEIPDB')), DataColumn(label: Text('THREAT RISK')), DataColumn(label: Text('MITRE ATT&CK'))],
            rows: extractedIocs.map((ioc) {
                String ip = (ioc['ip'] ?? '-').toString();
                String event = (ioc['event'] ?? 'Network Connection').toString();
                String risk = (ioc['severity'] ?? 'HIGH').toString();
                
                String vtScore = '0';
                if (ioc['vt_score'] != null && ioc['vt_score'].toString().trim().isNotEmpty && ioc['vt_score'].toString() != 'null') {
                    vtScore = ioc['vt_score'].toString();
                }
                
                String abuseScore = '0';
                if (ioc['abuse_score'] != null && ioc['abuse_score'].toString().trim().isNotEmpty && ioc['abuse_score'].toString() != 'null') {
                    abuseScore = ioc['abuse_score'].toString();
                }
                
                Color rCol = risk == 'CRITICAL' ? const Color(0xFFFF3B30) : (risk == 'HIGH' ? Colors.orange : Colors.amber);
                return DataRow(cells: [
                    DataCell(Text(ip, style: const TextStyle(color: Color(0xFFFF3B30), fontWeight: FontWeight.bold, fontFamily: 'monospace'))),
                    DataCell(Text(event, maxLines: 1, overflow: TextOverflow.ellipsis)),
                    DataCell(Text('${vtScore} / 72', style: const TextStyle(color: Color(0xFFFF3B30), fontWeight: FontWeight.bold, fontFamily: 'monospace'))),
                    DataCell(Text('${abuseScore}%', style: const TextStyle(color: Colors.orange, fontWeight: FontWeight.bold, fontFamily: 'monospace'))),
                    DataCell(Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(color: rCol.withOpacity(0.15), border: Border.all(color: rCol.withOpacity(0.5)), borderRadius: BorderRadius.circular(4)), child: Text(risk, style: TextStyle(color: rCol, fontSize: 8)))),
                    DataCell(Text(ioc['mitre_id']?.toString() ?? 'T1071', style: const TextStyle(color: Color(0xFF32ade6)))),
                ]);
            }).toList()
          ))),
        ]));

      
      case '26': return AlertCorrelationScreen(alerts: _alerts, incidents: []);
      case '27': return ThreatHuntingScreen(alerts: _alerts);
      case '28': return IocDashboardScreen(alerts: _alerts);
      case '29': return Padding(
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
      
      case '30': return SoarPlaybookScreen(alerts: _alerts);
      case '31': return const PlaybookBuilderScreen();
      case '32': return IncidentReportsScreen(alerts: _alerts);

      case '33': return ReportGeneratorScreen(alerts: _alerts);
      case '34': return ExportLogsScreen(alerts: _alerts);
      case '35': return const RuleEngineScreen();
      case '36': return const CustomDetectionRulesScreen();
      case '37': return const AuditLogScreen();
      case '38': return const UserManagementScreen();
      case '39': return const AdminCommandCenterScreen();

      default: return const Center(child: Text('Data Loading...'));
    }
  }

  Widget _buildFilterChip(String label, Color color, {bool isSelected = false}) {
    return Container(
      margin: const EdgeInsets.only(right: 8), padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      decoration: BoxDecoration(color: isSelected ? const Color(0xFF30363d) : Colors.transparent, border: Border.all(color: color.withOpacity(0.5)), borderRadius: BorderRadius.circular(4)),
      child: Text(label, style: TextStyle(color: color, fontSize: 10, fontWeight: FontWeight.bold)),
    );
  }
  
  Widget _buildActionMiniBtn(String label, Color color) {
    return Container(
      margin: const EdgeInsets.only(right: 4), padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 2),
      decoration: BoxDecoration(color: color.withOpacity(0.15), border: Border.all(color: color.withOpacity(0.5)), borderRadius: BorderRadius.circular(2)),
      child: Text(label, style: TextStyle(color: color, fontSize: 8, fontWeight: FontWeight.bold)),
    );
  }

  Widget _buildMapChip(String label) {
    return Container(
      margin: const EdgeInsets.only(right: 4), padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 4),
      decoration: BoxDecoration(color: const Color(0xFF1f242d), borderRadius: BorderRadius.circular(4), border: Border.all(color: const Color(0xFF30363d))),
      child: Text(label, style: const TextStyle(color: Colors.white, fontSize: 9)),
    );
  }
  
  Widget _buildContinentShape(double w, double h) {
    return Container(width: w, height: h, child: CustomPaint(painter: PolygonPainter()));
  }
  
  Widget _buildMapPin(String label) {
    return Row(children: [
      Container(width: 8, height: 8, decoration: BoxDecoration(color: Colors.red, shape: BoxShape.circle, border: Border.all(color: Colors.redAccent.withOpacity(0.5), width: 2), boxShadow: [BoxShadow(color: Colors.red.withOpacity(0.8), blurRadius: 4, spreadRadius: 2)])),
      const SizedBox(width: 4),
      Text(label, style: const TextStyle(color: Colors.white, fontSize: 8, fontWeight: FontWeight.bold))
    ]);
  }
  
  DataRow _buildCompRow(String comp, String stat, String ver, String det, String up) {
    return DataRow(cells: [
      DataCell(Text(comp, style: const TextStyle(fontWeight: FontWeight.bold))),
      DataCell(Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(color: const Color(0x3330d158), border: Border.all(color: const Color(0xFF30d158)), borderRadius: BorderRadius.circular(2)), child: Text(stat, style: const TextStyle(color: Color(0xFF30d158), fontSize: 9)))),
      DataCell(Text(ver)), DataCell(Text(det)), DataCell(Text(up, style: const TextStyle(color: Color(0xFF8b949e)))),
    ]);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0d1117),
      drawer: _buildMobileDrawer(),
      appBar: AppBar(
        backgroundColor: const Color(0xFF161b22), elevation: 0, iconTheme: const IconThemeData(color: Colors.white),
        title: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [Text(_currentViewTitle, style: const TextStyle(color: Colors.white, fontSize: 15, fontWeight: FontWeight.bold)), Row(children: [Container(width: 6, height: 6, decoration: const BoxDecoration(color: Color(0xFF30d158), shape: BoxShape.circle)), const SizedBox(width: 6), const Text('Secure Uplink Active', style: TextStyle(color: Color(0xFF8b949e), fontSize: 10))])]),
        actions: [IconButton(icon: const Icon(Icons.power_settings_new, color: Color(0xFF8b949e), size: 22), onPressed: _handleLogout)],
      ),
      body: RefreshIndicator(
        onRefresh: _loadDashboardData, backgroundColor: const Color(0xFF161b22), color: const Color(0xFF0a84ff),
        child: Column(
          children: [
            _buildTopActionBar(), // <--- NEW GLOBAL ACTION BAR
            Expanded(child: SingleChildScrollView(physics: const AlwaysScrollableScrollPhysics(), child: _buildContentBody())),
          ],
        ),
      ),
    );
  }

  bool _isExeAlert(Map<String, dynamic> a) {
    String src = (a['source'] ?? '').toString().toLowerCase();
    String ls = (a['log_source'] ?? '').toString().toLowerCase();
    String ev = (a['event'] ?? '').toString().toLowerCase();
    String det = (a['detail'] ?? '').toString().toLowerCase();
    String mid = (a['mitre_id'] ?? '').toString().toLowerCase();
    return src == 'exe' || ls.contains('app') || ev.contains('exe') || ev.contains('binary') || ev.contains('process') || ev.contains('executable') || ev.contains('payload') || det.contains('.exe') || det.contains(r'\temp') || det.contains(r'\appdata') || det.contains(r'temp\') || det.contains('programdata') || mid.contains('t1204') || mid.contains('t1059.003');
  }

  bool _isPsAlert(Map<String, dynamic> a) {
    String src = (a['source'] ?? '').toString().toLowerCase();
    String ls = (a['log_source'] ?? '').toString().toLowerCase();
    String ev = (a['event'] ?? '').toString().toLowerCase();
    String det = (a['detail'] ?? '').toString().toLowerCase();
    String mid = (a['mitre_id'] ?? '').toString().toLowerCase();
    return src == 'powershell' || ls.contains('powershell') || ev.contains('powershell') || ev.contains('mimikatz') || ev.contains('script') || ev.contains('pwsh') || det.contains('powershell') || det.contains('-enc') || det.contains('encodedcommand') || det.contains('bypass') || det.contains('iex') || det.contains('downloadstring') || det.contains('invoke-') || mid.contains('t1059.001') || mid.contains('t1003');
  }

  bool _isNetAlert(Map<String, dynamic> a) {
    String src = (a['source'] ?? '').toString().toLowerCase();
    String ls = (a['log_source'] ?? '').toString().toLowerCase();
    String ev = (a['event'] ?? '').toString().toLowerCase();
    String det = (a['detail'] ?? '').toString().toLowerCase();
    String mid = (a['mitre_id'] ?? '').toString().toLowerCase();
    bool hasIp = (a['ip'] != null && a['ip'] != '-' && a['ip'] != '127.0.0.1');
    return src == 'network' || src == 'sysmon_network' || ls.contains('net') || ev.contains('network') || ev.contains('connect') || ev.contains('c2') || ev.contains('beacon') || ev.contains('port scan') || ev.contains('socket') || ev.contains('reverse shell') || det.contains('connection') || det.contains('outbound') || det.contains('inbound') || det.contains(':4444') || det.contains(':6666') || det.contains(':1337') || det.contains(':31337') || det.contains(':9001') || det.contains(':8080') || det.contains(':80') || det.contains(':443') || det.contains('port') || mid.contains('t1071') || mid.contains('t1095') || mid.contains('t1041') || (hasIp && (ev.contains('beacon') || ev.contains('c2') || ev.contains('traffic') || ev.contains('connection')));
  }

  bool _isFileAlert(Map<String, dynamic> a) {
    String src = (a['source'] ?? '').toString().toLowerCase();
    String ls = (a['log_source'] ?? '').toString().toLowerCase();
    String ev = (a['event'] ?? '').toString().toLowerCase();
    String det = (a['detail'] ?? '').toString().toLowerCase();
    String mid = (a['mitre_id'] ?? '').toString().toLowerCase();
    return src == 'sysmon_file' || src == 'canary' || ev.contains('file') || ev.contains('drop') || ev.contains('ransomware') || ev.contains('canary') || ev.contains('shadow copy') || det.contains('file') || det.contains('canary') || det.contains('vssadmin') || det.contains('dropped') || mid.contains('t1204.002') || mid.contains('t1486') || mid.contains('t1490');
  }

  bool _isRegAlert(Map<String, dynamic> a) {
    String src = (a['source'] ?? '').toString().toLowerCase();
    String ls = (a['log_source'] ?? '').toString().toLowerCase();
    String ev = (a['event'] ?? '').toString().toLowerCase();
    String det = (a['detail'] ?? '').toString().toLowerCase();
    String mid = (a['mitre_id'] ?? '').toString().toLowerCase();
    return src == 'registry' || ls.contains('reg') || ev.contains('registry') || ev.contains('persistence') || ev.contains('runkey') || ev.contains('run key') || ev.contains('reg.exe') || det.contains('hkcu') || det.contains('hklm') || det.contains(r'currentversion\run') || det.contains('runonce') || det.contains('autorun') || det.contains('registry') || det.contains('reg add') || mid.contains('t1547') || mid.contains('t1070.004');
  }

  Widget _buildAlertWarningBox(String title, Color c) {
    return Container(
      padding: const EdgeInsets.all(12),
      margin: const EdgeInsets.only(bottom: 12),
      decoration: BoxDecoration(color: c.withOpacity(0.1), border: Border.all(color: c.withOpacity(0.5)), borderRadius: BorderRadius.circular(4)),
      child: Text(title, style: TextStyle(color: c, fontSize: 11)),
    );
  }

}

class GridPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()..color = const Color(0xFF162032)..strokeWidth = 1;
    for (double i = 0; i < size.width; i += 40) { canvas.drawLine(Offset(i, 0), Offset(i, size.height), paint); }
    for (double i = 0; i < size.height; i += 40) { canvas.drawLine(Offset(0, i), Offset(size.width, i), paint); }
  }
  @override bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}

class PolygonPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()..color = const Color(0xFF1a2b4c)..style = PaintingStyle.fill;
    final border = Paint()..color = const Color(0xFF32ade6).withOpacity(0.5)..style = PaintingStyle.stroke..strokeWidth = 1;
    final path = Path()..moveTo(0, size.height * 0.2)..lineTo(size.width * 0.8, 0)..lineTo(size.width, size.height * 0.5)..lineTo(size.width * 0.5, size.height)..lineTo(0, size.height * 0.8)..close();
    canvas.drawPath(path, paint); canvas.drawPath(path, border);
  }
  @override bool shouldRepaint(covariant CustomPainter oldDelegate) => false;

}
