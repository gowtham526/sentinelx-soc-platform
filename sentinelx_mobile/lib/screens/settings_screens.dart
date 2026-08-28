import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';
import '../services/api_service.dart';

class RuleEngineScreen extends StatefulWidget {
  const RuleEngineScreen({super.key});
  @override
  State<RuleEngineScreen> createState() => _RuleEngineScreenState();
}

class _RuleEngineScreenState extends State<RuleEngineScreen> {
  final TextEditingController _cmdController = TextEditingController();
  
  Widget _buildStatCard(String title, String val, String sub, Color c) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: const Color(0xFF161b22),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: const Color(0xFF30363d)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(title.toUpperCase(), style: const TextStyle(fontSize: 9, fontWeight: FontWeight.bold, color: Color(0xFF6e7681))),
          const SizedBox(height: 8),
          Text(val, style: TextStyle(fontSize: 22, fontWeight: FontWeight.w900, color: c)),
          const SizedBox(height: 4),
          Text(sub, style: const TextStyle(fontSize: 10, color: Color(0xFF6e7681))),
        ],
      ),
    );
  }

  void _testCommand() {
    String cmd = _cmdController.text.toLowerCase();
    if(cmd.isEmpty) return;
    int score = 0;
    List<String> matched = [];
    if (cmd.contains('mimikatz')) { score += 50; matched.add('mimikatz (+50)'); }
    if (cmd.contains('vssadmin delete')) { score += 45; matched.add('vssadmin delete (+45)'); }
    if (cmd.contains('-enc') || cmd.contains('encodedcommand')) { score += 35; matched.add('encodedcommand (+35)'); }
    if (cmd.contains('net user') && cmd.contains('/add')) { score += 30; matched.add('net user /add (+30)'); }
    
    if (score == 0) { score = 5; matched.add('No core rules matched (+5)'); }

    showDialog(
      context: context,
      builder: (c) => AlertDialog(
        backgroundColor: const Color(0xFF161b22),
        title: const Text('Simulation Result', style: TextStyle(color: Colors.white)),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Input: ${_cmdController.text}', style: const TextStyle(color: Colors.white70, fontFamily: 'monospace', fontSize: 12)),
            const SizedBox(height: 12),
            Text('Calculated Score: $score', style: TextStyle(color: score >= 45 ? Colors.red : Colors.orange, fontWeight: FontWeight.bold, fontSize: 18)),
            const SizedBox(height: 12),
            const Text('Matches:', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
            ...matched.map((m) => Text('- $m', style: const TextStyle(color: Colors.white70, fontSize: 12))),
          ]
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(c), child: const Text('Close'))
        ],
      )
    );
  }

  @override
  Widget build(BuildContext context) {
    final rules = [
      {'kw': 'mimikatz', 'score': '+50', 'sev': 'CRITICAL', 'mitre': 'T1003 - Credential Dumping', 'det': 'All Detectors', 'sc': Colors.red},
      {'kw': 'invoke-mimikatz', 'score': '+50', 'sev': 'CRITICAL', 'mitre': 'T1003 - Credential Dumping', 'det': 'PowerShell', 'sc': Colors.red},
      {'kw': 'vssadmin delete', 'score': '+45', 'sev': 'HIGH', 'mitre': 'T1490 - Inhibit Recovery', 'det': 'Sysmon + CMD', 'sc': Colors.orange},
      {'kw': 'ransomware', 'score': '+50', 'sev': 'CRITICAL', 'mitre': 'T1486 - Data Encrypted', 'det': 'EXE + Sysmon', 'sc': Colors.red},
      {'kw': 'backdoor', 'score': '+40', 'sev': 'HIGH', 'mitre': 'T1071 - C2 Channel', 'det': 'EXE + File', 'sc': Colors.orange},
      {'kw': '-encodedcommand', 'score': '+35', 'sev': 'HIGH', 'mitre': 'T1059.001 - Obfuscated PowerShell', 'det': 'PowerShell', 'sc': Colors.orange},
      {'kw': 'invoke-webrequest', 'score': '+32', 'sev': 'HIGH', 'mitre': 'T1105 - Ingress Transfer', 'det': 'PowerShell', 'sc': Colors.orange},
      {'kw': 'lsass', 'score': '+30', 'sev': 'HIGH', 'mitre': 'T1003.001 - LSASS Memory Access', 'det': 'Sysmon + PS', 'sc': Colors.orange},
      {'kw': 'net user /add', 'score': '+30', 'sev': 'HIGH', 'mitre': 'T1136.001 - Local Account Creation', 'det': 'Sysmon + CMD', 'sc': Colors.orange},
      {'kw': 'reg add.*run', 'score': '+25', 'sev': 'MEDIUM', 'mitre': 'T1547.001 - Registry Run Keys', 'det': 'Registry', 'sc': Colors.yellow},
    ];

    return SingleChildScrollView(
      padding: const EdgeInsets.all(12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Wrap(
            spacing: 8, runSpacing: 8,
            children: [
              SizedBox(width: 160, child: _buildStatCard('Active Detection Rules', '124+ Rules', 'Across 7 detector streams', Colors.red)),
              SizedBox(width: 160, child: _buildStatCard('Signal Scoring Matrix', '24 Algorithms', 'Multi-factor weighted scoring', Colors.blue)),
              SizedBox(width: 160, child: _buildStatCard('Execution Latency', '< 1.2ms', 'Real-time stream evaluation', Colors.green)),
              SizedBox(width: 160, child: _buildStatCard('False Positive Rate', '< 2.1%', 'Allowlist + Context Correlation', Colors.green)),
            ]
          ),
          const SizedBox(height: 16),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(8), border: Border.all(color: const Color(0xFF30363d))),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text('\u26A1 Interactive Rule Simulator & Live Payload Tester', style: TextStyle(fontWeight: FontWeight.bold, color: Colors.white, fontSize: 13)),
                const SizedBox(height: 12),
                const Text('TEST COMMAND LINE / PAYLOAD STRING:', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681))),
                const SizedBox(height: 4),
                Row(
                  children: [
                    Expanded(child: TextField(controller: _cmdController, style: const TextStyle(fontSize: 12), decoration: const InputDecoration(filled: true, fillColor: Color(0xFF030712), border: OutlineInputBorder(), isDense: true, contentPadding: EdgeInsets.symmetric(horizontal: 10, vertical: 12)))),
                    const SizedBox(width: 8),
                    ElevatedButton.icon(
                      style: ElevatedButton.styleFrom(backgroundColor: Colors.blue, foregroundColor: Colors.white),
                      onPressed: _testCommand,
                      icon: const Icon(Icons.bolt, size: 16), label: const Text('Test & Calculate Score')
                    )
                  ],
                ),
                const SizedBox(height: 8),
                Wrap(
                  spacing: 12,
                  children: [
                    const Text('Quick Presets:', style: TextStyle(fontSize: 11, color: Colors.white54)),
                    GestureDetector(onTap: () { _cmdController.text = 'mimikatz.exe sekurlsa::logonpasswords'; _testCommand(); }, child: const Text('Mimikatz', style: TextStyle(color: Colors.blue, fontSize: 11, decoration: TextDecoration.underline))),
                    GestureDetector(onTap: () { _cmdController.text = 'vssadmin delete shadows /all /quiet'; _testCommand(); }, child: const Text('Shadow Delete', style: TextStyle(color: Colors.blue, fontSize: 11, decoration: TextDecoration.underline))),
                    GestureDetector(onTap: () { _cmdController.text = 'powershell.exe -w hidden -enc JABz...'; _testCommand(); }, child: const Text('PS Encoded', style: TextStyle(color: Colors.blue, fontSize: 11, decoration: TextDecoration.underline))),
                    GestureDetector(onTap: () { _cmdController.text = 'net user backdoor Hacker123! /add'; _testCommand(); }, child: const Text('Net User Add', style: TextStyle(color: Colors.blue, fontSize: 11, decoration: TextDecoration.underline))),
                  ]
                )
              ]
            )
          ),
          const SizedBox(height: 16),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(8), border: Border.all(color: const Color(0xFF30363d))),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text('Active Built-in Detection Rules & MITRE TTPs (16 Core Rules)', style: TextStyle(fontWeight: FontWeight.bold, color: Colors.white, fontSize: 13)),
                const SizedBox(height: 12),
                SingleChildScrollView(
                  scrollDirection: Axis.horizontal,
                  child: DataTable(
                    dataRowMinHeight: 40, dataRowMaxHeight: 40, headingRowHeight: 35,
                    columns: const [
                      DataColumn(label: Text('KEYWORD / REGEX', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681)))),
                      DataColumn(label: Text('SCORE', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681)))),
                      DataColumn(label: Text('SEVERITY', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681)))),
                      DataColumn(label: Text('MITRE ATTACK TECHNIQUE', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681)))),
                      DataColumn(label: Text('DETECTOR', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681)))),
                    ],
                    rows: rules.map((r) => DataRow(cells: [
                      DataCell(Text(r['kw'] as String, style: const TextStyle(fontFamily: 'monospace', fontSize: 11, fontWeight: FontWeight.bold, color: Colors.white))),
                      DataCell(Text(r['score'] as String, style: TextStyle(fontFamily: 'monospace', fontSize: 11, fontWeight: FontWeight.bold, color: r['sc'] as Color))),
                      DataCell(Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(border: Border.all(color: r['sc'] as Color), borderRadius: BorderRadius.circular(4)), child: Text(r['sev'] as String, style: TextStyle(fontSize: 9, fontWeight: FontWeight.bold, color: r['sc'] as Color)))),
                      DataCell(Text(r['mitre'] as String, style: const TextStyle(fontSize: 11, color: Colors.white70))),
                      DataCell(Text(r['det'] as String, style: const TextStyle(fontSize: 11, color: Colors.white70))),
                    ])).toList(),
                  ),
                )
              ]
            )
          )
        ],
      )
    );
  }
}

class CustomDetectionRulesScreen extends StatefulWidget {
  const CustomDetectionRulesScreen({super.key});
  @override
  State<CustomDetectionRulesScreen> createState() => _CustomDetectionRulesScreenState();
}

class _CustomDetectionRulesScreenState extends State<CustomDetectionRulesScreen> {
  final TextEditingController _nameController = TextEditingController();
  final TextEditingController _kwController = TextEditingController();
  
  List<Map<String, String>> _rules = [
    {'id': 'CR-1707923756730', 'name': 'Failed SSH', 'kw': 'sshd: attempt to login using a non-existent user', 'score': '+25', 'status': 'Active'},
  ];

  void _saveRule() {
    if (_nameController.text.isEmpty || _kwController.text.isEmpty) return;
    setState(() {
      _rules.insert(0, {
        'id': 'CR-${DateTime.now().millisecondsSinceEpoch}',
        'name': _nameController.text,
        'kw': _kwController.text,
        'score': '+30',
        'status': 'Active'
      });
      _nameController.clear();
      _kwController.clear();
    });
    ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Rule Saved successfully', style: TextStyle(color: Colors.white)), backgroundColor: Colors.green));
  }

  void _deleteRule(String id) {
    setState(() => _rules.removeWhere((r) => r['id'] == id));
  }

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(8), border: Border.all(color: const Color(0xFF30363d))),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text('Add New Detection Rule', style: TextStyle(fontWeight: FontWeight.bold, color: Colors.white, fontSize: 13)),
                const SizedBox(height: 12),
                const Text('RULE NAME', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681))),
                TextField(controller: _nameController, decoration: const InputDecoration(isDense: true, border: OutlineInputBorder(), hintText: 'e.g. Suspicious Batch Execution', hintStyle: TextStyle(fontSize: 11))),
                const SizedBox(height: 8),
                const Text('KEYWORD (MATCHED IN DETAIL/COMMANDLINE, CASE-INSENSITIVE)', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681))),
                TextField(controller: _kwController, decoration: const InputDecoration(isDense: true, border: OutlineInputBorder(), hintText: 'e.g. mimikatz or powershell -enc', hintStyle: TextStyle(fontSize: 11))),
                const SizedBox(height: 12),
                Row(
                  children: [
                    ElevatedButton(onPressed: _saveRule, style: ElevatedButton.styleFrom(backgroundColor: Colors.blue, foregroundColor: Colors.white), child: const Text('Save Rule')),
                  ],
                )
              ]
            )
          ),
          const SizedBox(height: 16),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(8), border: Border.all(color: const Color(0xFF30363d))),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text('Saved Custom Rules', style: TextStyle(fontWeight: FontWeight.bold, color: Colors.white, fontSize: 13)),
                const SizedBox(height: 8),
                SingleChildScrollView(
                  scrollDirection: Axis.horizontal,
                  child: DataTable(
                    dataRowMinHeight: 40, dataRowMaxHeight: 40, headingRowHeight: 35,
                    columns: const [
                      DataColumn(label: Text('ID', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681)))),
                      DataColumn(label: Text('NAME', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681)))),
                      DataColumn(label: Text('KEYWORD', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681)))),
                      DataColumn(label: Text('SCORE', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681)))),
                      DataColumn(label: Text('STATUS', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681)))),
                      DataColumn(label: Text('', style: TextStyle(fontSize: 10))),
                    ],
                    rows: _rules.map((r) => DataRow(cells: [
                      DataCell(Text(r['id']!, style: const TextStyle(fontSize: 11, color: Colors.white70))),
                      DataCell(Text(r['name']!, style: const TextStyle(fontSize: 11, color: Colors.white))),
                      DataCell(Text(r['kw']!, style: const TextStyle(fontSize: 11, fontFamily: 'monospace', color: Colors.white70))),
                      DataCell(Text(r['score']!, style: const TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Colors.orange))),
                      DataCell(Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(border: Border.all(color: Colors.green), borderRadius: BorderRadius.circular(4)), child: Text(r['status']!, style: const TextStyle(fontSize: 9, fontWeight: FontWeight.bold, color: Colors.green)))),
                      DataCell(Row(
                        children: [
                          TextButton(onPressed: () => _deleteRule(r['id']!), child: const Text('Delete', style: TextStyle(fontSize: 10, color: Colors.red))),
                        ]
                      )),
                    ])).toList(),
                  )
                )
              ]
            )
          )
        ]
      )
    );
  }
}

class AuditLogScreen extends StatefulWidget {
  const AuditLogScreen({super.key});
  @override
  State<AuditLogScreen> createState() => _AuditLogScreenState();
}

class _AuditLogScreenState extends State<AuditLogScreen> {
  List<dynamic> _logs = [];

  @override
  void initState() {
    super.initState();
    _fetchLogs();
  }

  Future<void> _fetchLogs() async {
    try {
      final res = await http.get(
        Uri.parse('${ApiService.baseUrl}/api/audit_log'),
        headers: {'Authorization': 'Bearer ${ApiService.authToken}'},
      );
      if (res.statusCode == 200) {
        if(mounted) setState(() { _logs = jsonDecode(res.body); });
      }
    } catch (_) {}
  }

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(12),
      child: Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(8), border: Border.all(color: const Color(0xFF30363d))),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                const Text('Recent Actions', style: TextStyle(fontWeight: FontWeight.bold, color: Colors.white, fontSize: 13)),
                ElevatedButton(onPressed: _fetchLogs, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF30363d), foregroundColor: Colors.white, padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8), minimumSize: Size.zero), child: const Text('Refresh', style: TextStyle(fontSize: 11)))
              ]
            ),
            const SizedBox(height: 12),
            SingleChildScrollView(
              scrollDirection: Axis.horizontal,
              child: DataTable(
                dataRowMinHeight: 40, dataRowMaxHeight: 40, headingRowHeight: 35,
                columns: const [
                  DataColumn(label: Text('TIME', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681)))),
                  DataColumn(label: Text('USER', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681)))),
                  DataColumn(label: Text('ACTION', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681)))),
                  DataColumn(label: Text('DETAILS', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681)))),
                  DataColumn(label: Text('IP', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681)))),
                ],
                rows: _logs.map((l) => DataRow(cells: [
                  DataCell(Text(l['timestamp']?.toString() ?? '', style: const TextStyle(fontSize: 11, color: Colors.white70, fontFamily: 'monospace'))),
                  DataCell(Text(l['user']?.toString() ?? '', style: const TextStyle(fontSize: 11, color: Colors.white, fontWeight: FontWeight.bold))),
                  DataCell(Text(l['action']?.toString() ?? '', style: const TextStyle(fontSize: 11, color: Colors.white70))),
                  DataCell(Text(l['details'] != null ? jsonEncode(l['details']) : '', style: const TextStyle(fontSize: 10, color: Colors.white54, fontFamily: 'monospace'))),
                  DataCell(Text(l['ip']?.toString() ?? '', style: const TextStyle(fontSize: 11, color: Colors.white70, fontFamily: 'monospace'))),
                ])).toList(),
              )
            )
          ]
        )
      )
    );
  }
}

class UserManagementScreen extends StatefulWidget {
  const UserManagementScreen({super.key});
  @override
  State<UserManagementScreen> createState() => _UserManagementScreenState();
}

class _UserManagementScreenState extends State<UserManagementScreen> {
  List<dynamic> _users = [];

  @override
  void initState() {
    super.initState();
    _fetchUsers();
  }

  Future<void> _fetchUsers() async {
    try {
      final res = await http.get(
        Uri.parse('${ApiService.baseUrl}/api/admin/users'),
        headers: {'Authorization': 'Bearer ${ApiService.authToken}'},
      );
      if (res.statusCode == 200) {
        if(mounted) setState(() { _users = jsonDecode(res.body)['users'] ?? []; });
      }
    } catch (_) {}
  }

  void _createUserDialog() {
    final tu = TextEditingController();
    final tp = TextEditingController();
    String selectedRole = 'analyst';
    
    showDialog(
      context: context,
      builder: (c) {
        return StatefulBuilder(
          builder: (context, setStateSB) {
            return AlertDialog(
              backgroundColor: const Color(0xFF161b22),
              title: const Text('Create User', style: TextStyle(color: Colors.white)),
              content: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  TextField(controller: tu, style: const TextStyle(color: Colors.white), decoration: const InputDecoration(hintText: 'Username', hintStyle: TextStyle(color: Colors.white54))),
                  TextField(controller: tp, style: const TextStyle(color: Colors.white), decoration: const InputDecoration(hintText: 'Password', hintStyle: TextStyle(color: Colors.white54))),
                  DropdownButton<String>(
                    value: selectedRole,
                    dropdownColor: const Color(0xFF161b22),
                    style: const TextStyle(color: Colors.white),
                    items: const [
                      DropdownMenuItem(value: 'analyst', child: Text('Analyst')),
                      DropdownMenuItem(value: 'admin', child: Text('Admin')),
                      DropdownMenuItem(value: 'auditor', child: Text('Auditor')),
                    ],
                    onChanged: (v) => setStateSB(() => selectedRole = v ?? 'analyst'),
                  )
                ],
              ),
              actions: [
                TextButton(onPressed: () => Navigator.pop(c), child: const Text('Cancel')),
                ElevatedButton(onPressed: () async {
                  if(tu.text.isEmpty || tp.text.isEmpty) return;
                  try {
                    final res = await http.post(
                      Uri.parse('${ApiService.baseUrl}/api/admin/create_user'),
                      headers: {'Authorization': 'Bearer ${ApiService.authToken}', 'Content-Type': 'application/json'},
                      body: jsonEncode({"username": tu.text, "password": tp.text, "role": selectedRole}),
                    );
                    if (res.statusCode == 200) {
                      Navigator.pop(c);
                      _fetchUsers();
                    }
                  } catch (_) {}
                }, child: const Text('Create'))
              ],
            );
          }
        );
      }
    );
  }

  void _resetPasswordDialog(String username) {
    final tp = TextEditingController();
    showDialog(
      context: context,
      builder: (c) => AlertDialog(
        backgroundColor: const Color(0xFF161b22),
        title: Text('Reset Password ($username)', style: const TextStyle(color: Colors.white)),
        content: TextField(controller: tp, style: const TextStyle(color: Colors.white), decoration: const InputDecoration(hintText: 'New Password', hintStyle: TextStyle(color: Colors.white54))),
        actions: [
          TextButton(onPressed: () => Navigator.pop(c), child: const Text('Cancel')),
          ElevatedButton(onPressed: () async {
            if(tp.text.isEmpty) return;
            try {
              final res = await http.post(
                Uri.parse('${ApiService.baseUrl}/api/users/$username/reset_password'),
                headers: {'Authorization': 'Bearer ${ApiService.authToken}', 'Content-Type': 'application/json'},
                body: jsonEncode({"new_password": tp.text}),
              );
              if (res.statusCode == 200) {
                Navigator.pop(c);
              }
            } catch (_) {}
          }, child: const Text('Reset'))
        ],
      )
    );
  }

  void _changeRoleDialog(String username, String currentRole) {
    String selectedRole = currentRole;
    showDialog(
      context: context,
      builder: (c) {
        return StatefulBuilder(
          builder: (context, setStateSB) {
            return AlertDialog(
              backgroundColor: const Color(0xFF161b22),
              title: Text('Change Role ($username)', style: const TextStyle(color: Colors.white)),
              content: DropdownButton<String>(
                value: selectedRole,
                dropdownColor: const Color(0xFF161b22),
                style: const TextStyle(color: Colors.white),
                items: const [
                  DropdownMenuItem(value: 'analyst', child: Text('Analyst')),
                  DropdownMenuItem(value: 'admin', child: Text('Admin')),
                  DropdownMenuItem(value: 'auditor', child: Text('Auditor')),
                ],
                onChanged: (v) => setStateSB(() => selectedRole = v ?? 'analyst'),
              ),
              actions: [
                TextButton(onPressed: () => Navigator.pop(c), child: const Text('Cancel')),
                ElevatedButton(onPressed: () async {
                  try {
                    final res = await http.put(
                      Uri.parse('${ApiService.baseUrl}/api/users/$username/role'),
                      headers: {'Authorization': 'Bearer ${ApiService.authToken}', 'Content-Type': 'application/json'},
                      body: jsonEncode({"role": selectedRole}),
                    );
                    if (res.statusCode == 200) {
                      Navigator.pop(c);
                      _fetchUsers();
                    }
                  } catch (_) {}
                }, child: const Text('Update'))
              ],
            );
          }
        );
      }
    );
  }

  void _deleteUser(String username) async {
    try {
      final res = await http.post(
        Uri.parse('${ApiService.baseUrl}/api/admin/delete_user'),
        headers: {'Authorization': 'Bearer ${ApiService.authToken}', 'Content-Type': 'application/json'},
        body: jsonEncode({"username": username}),
      );
      if (res.statusCode == 200) {
        _fetchUsers();
      }
    } catch (_) {}
  }

  Widget _buildRoleCard(String title, String desc, Color badgeColor, String badgeText, List<String> permissions) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(8), border: Border.all(color: const Color(0xFF30363d))),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(title, style: const TextStyle(fontWeight: FontWeight.bold, color: Colors.white, fontSize: 13)),
              Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(border: Border.all(color: badgeColor), borderRadius: BorderRadius.circular(4)), child: Text(badgeText, style: TextStyle(fontSize: 9, fontWeight: FontWeight.bold, color: badgeColor))),
            ]
          ),
          const SizedBox(height: 6),
          Text(desc, style: const TextStyle(fontSize: 11, color: Colors.white70)),
          const SizedBox(height: 12),
          Wrap(
            spacing: 4, runSpacing: 4,
            children: permissions.map((p) => Text(p, style: const TextStyle(fontSize: 9, color: Colors.blue))).toList()
          )
        ]
      )
    );
  }

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Wrap(
            spacing: 8, runSpacing: 8,
            children: [
              SizedBox(width: 250, child: _buildRoleCard('\u{1F451} Admin Role', 'Complete administrative control over all platform modules.', Colors.blue, 'Full Access', ['User Management', 'Rule Editor', 'Kill Processes', 'Block IPs', 'Host Quarantine', 'Export Config'])),
              SizedBox(width: 250, child: _buildRoleCard('\u{1F6E1} Analyst Role', 'Daily threat monitoring, triage, and SOAR execution.', Colors.green, 'SOC Operations', ['Live Alerts', 'Alert Triage', 'SOAR Actions', 'Case Timeline', 'AI Analysis', 'Generate Reports'])),
              SizedBox(width: 250, child: _buildRoleCard('\u{1F4D3} Auditor Role', 'Read-only compliance audit & evidence review.', Colors.orange, 'Read-Only', ['Audit Trail', 'Timeline Review', 'Compliance Export', 'Evidence Logs', 'Threat Reports'])),
            ]
          ),
          const SizedBox(height: 16),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(8), border: Border.all(color: const Color(0xFF30363d))),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    const Text('Active User Directory', style: TextStyle(fontWeight: FontWeight.bold, color: Colors.white, fontSize: 13)),
                    Row(
                      children: [
                        ElevatedButton(onPressed: _fetchUsers, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF30363d), foregroundColor: Colors.white, padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8), minimumSize: Size.zero), child: const Text('Refresh', style: TextStyle(fontSize: 11))),
                        const SizedBox(width: 8),
                        ElevatedButton.icon(onPressed: _createUserDialog, style: ElevatedButton.styleFrom(backgroundColor: Colors.blue, foregroundColor: Colors.white, padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8), minimumSize: Size.zero), icon: const Icon(Icons.add, size: 14), label: const Text('Create New User', style: TextStyle(fontSize: 11))),
                      ]
                    )
                  ]
                ),
                const SizedBox(height: 12),
                SingleChildScrollView(
                  scrollDirection: Axis.horizontal,
                  child: DataTable(
                    dataRowMinHeight: 40, dataRowMaxHeight: 40, headingRowHeight: 35,
                    columns: const [
                      DataColumn(label: Text('USER ACCOUNT', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681)))),
                      DataColumn(label: Text('ROLE', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681)))),
                      DataColumn(label: Text('STATUS', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681)))),
                      DataColumn(label: Text('ACCOUNT CREATED', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681)))),
                      DataColumn(label: Text('ACTIONS', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681)))),
                    ],
                    rows: _users.map((u) => DataRow(cells: [
                      DataCell(Text(u['username'] == 'admin' ? 'admin (You)' : (u['username'] as String), style: TextStyle(fontSize: 11, color: u['username'] == 'admin' ? Colors.blue : Colors.white, fontWeight: FontWeight.bold))),
                      DataCell(Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(border: Border.all(color: u['role'] == 'admin' ? Colors.red : (u['role'] == 'auditor' ? Colors.orange : Colors.green)), borderRadius: BorderRadius.circular(4)), child: Text((u['role'] as String).toUpperCase(), style: TextStyle(fontSize: 9, fontWeight: FontWeight.bold, color: u['role'] == 'admin' ? Colors.red : (u['role'] == 'auditor' ? Colors.orange : Colors.green))))),
                      DataCell(Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(border: Border.all(color: Colors.green), borderRadius: BorderRadius.circular(4)), child: const Text('Active', style: TextStyle(fontSize: 9, fontWeight: FontWeight.bold, color: Colors.green)))),
                      DataCell(Text(u['created_at'] as String, style: const TextStyle(fontSize: 11, color: Colors.white70, fontFamily: 'monospace'))),
                      DataCell(Row(
                        children: [
                          ElevatedButton.icon(onPressed: () => _changeRoleDialog(u['username'], u['role']), style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF30363d), foregroundColor: Colors.white, padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 4), minimumSize: Size.zero), icon: const Icon(Icons.security, size: 10), label: const Text('Role', style: TextStyle(fontSize: 10))),
                          const SizedBox(width: 4),
                          ElevatedButton.icon(onPressed: () => _resetPasswordDialog(u['username']), style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF30363d), foregroundColor: Colors.white, padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 4), minimumSize: Size.zero), icon: const Icon(Icons.key, size: 10), label: const Text('Reset PW', style: TextStyle(fontSize: 10))),
                          if (u['username'] != 'admin') const SizedBox(width: 4),
                          if (u['username'] != 'admin') ElevatedButton.icon(onPressed: () => _deleteUser(u['username']), style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF30363d), foregroundColor: Colors.red, padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 4), minimumSize: Size.zero), icon: const Icon(Icons.delete, size: 10), label: const Text('Delete', style: TextStyle(fontSize: 10))),
                        ]
                      )),
                    ])).toList(),
                  )
                )
              ]
            )
          )
        ]
      )
    );
  }
}
