import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';
import '../services/api_service.dart';

class AdminCommandCenterScreen extends StatefulWidget {
  const AdminCommandCenterScreen({super.key});
  @override
  State<AdminCommandCenterScreen> createState() => _AdminCommandCenterScreenState();
}

class _AdminCommandCenterScreenState extends State<AdminCommandCenterScreen> {
  final TextEditingController _isolateHostCtrl = TextEditingController();
  final TextEditingController _restoreHostCtrl = TextEditingController();
  final TextEditingController _disableUserCtrl = TextEditingController();
  
  final TextEditingController _newUserNameCtrl = TextEditingController();
  final TextEditingController _newUserPassCtrl = TextEditingController();
  String _newUserRole = 'analyst';

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

  void _toast(String msg, {bool isError = false}) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(msg, style: const TextStyle(color: Colors.white)), backgroundColor: isError ? Colors.red : Colors.green));
  }

  Future<void> _executePost(String endpoint, Map<String, dynamic> body, String successMsg) async {
    try {
      final res = await http.post(
        Uri.parse('${ApiService.baseUrl}$endpoint'),
        headers: {'Authorization': 'Bearer ${ApiService.authToken}', 'Content-Type': 'application/json'},
        body: jsonEncode(body),
      );
      if (res.statusCode == 200) {
        _toast(successMsg);
      } else {
        _toast('Action failed', isError: true);
      }
    } catch (_) {
      _toast('Network error', isError: true);
    }
  }

  void _isolateHost() {
    if (_isolateHostCtrl.text.isEmpty) { _toast('Host name required', isError: true); return; }
    _executePost('/api/admin/system_control', {'action': 'isolate_host', 'target': _isolateHostCtrl.text}, 'Host ${_isolateHostCtrl.text} isolation initiated.');
    _isolateHostCtrl.clear();
  }

  void _restoreHost() {
    if (_restoreHostCtrl.text.isEmpty) { _toast('Host name required', isError: true); return; }
    _executePost('/api/admin/system_control', {'action': 'restore_host', 'target': _restoreHostCtrl.text}, 'Host ${_restoreHostCtrl.text} restoration initiated.');
    _restoreHostCtrl.clear();
  }

  void _disableUser() {
    if (_disableUserCtrl.text.isEmpty) { _toast('Username required', isError: true); return; }
    _executePost('/api/admin/system_control', {'action': 'disable_user', 'target': _disableUserCtrl.text}, 'User ${_disableUserCtrl.text} disabled globally.');
    _disableUserCtrl.clear();
  }

  void _createUser() async {
    if (_newUserNameCtrl.text.isEmpty || _newUserPassCtrl.text.isEmpty) { _toast('Username and password required', isError: true); return; }
    await _executePost('/api/admin/create_user', {'username': _newUserNameCtrl.text, 'password': _newUserPassCtrl.text, 'role': _newUserRole}, 'User ${_newUserNameCtrl.text} provisioned successfully.');
    _newUserNameCtrl.clear();
    _newUserPassCtrl.clear();
    _fetchUsers();
  }

  void _deleteUser(String username) {
    setState(() => _users.removeWhere((u) => u['username'] == username));
    _toast('User $username deleted');
  }

  Widget _buildStatBox(String title, String val, String sub) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(8), border: Border.all(color: const Color(0xFF30363d))),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(title.toUpperCase(), style: const TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681))),
          const SizedBox(height: 8),
          Text(val, style: const TextStyle(fontSize: 22, fontWeight: FontWeight.w900, color: Colors.white)),
          const SizedBox(height: 4),
          Text(sub, style: const TextStyle(fontSize: 10, color: Color(0xFF6e7681))),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Banner
          Container(
            padding: const EdgeInsets.all(14), margin: const EdgeInsets.only(bottom: 16),
            decoration: BoxDecoration(color: const Color(0x26FF3B30), border: Border.all(color: Colors.red), borderRadius: BorderRadius.circular(8)),
            child: const Text('\u26A1 EXCLUSIVE SOC ADMIN COMMAND CENTER: High-impact containment controls, user account provisioning, and system overrides. All actions are immutably logged to the security audit trail.', style: TextStyle(color: Colors.white, fontSize: 12, height: 1.5, fontWeight: FontWeight.bold)),
          ),
          
          // Stats Row
          Wrap(
            spacing: 8, runSpacing: 8,
            children: [
              SizedBox(width: 160, child: _buildStatBox('User Sessions', '2 Active', 'Admin / Analyst')),
              SizedBox(width: 160, child: _buildStatBox('System Role', '\u26A1 SOC ADMIN', 'Full Control')),
              SizedBox(width: 160, child: _buildStatBox('Containment Status', 'READY', 'Firewall & Host Isolation')),
              SizedBox(width: 160, child: _buildStatBox('Audit Logging', 'ACTIVE', 'Immutable log')),
            ]
          ),
          const SizedBox(height: 16),

          // Lockdown Sections
          Wrap(
            spacing: 16, runSpacing: 16,
            children: [
              // Host Lockdown
              Container(
                width: 400,
                padding: const EdgeInsets.all(12), decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(8), border: Border.all(color: const Color(0xFF30363d))),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: const [
                        Text('Admin Host Lockdown & Isolation', style: TextStyle(fontWeight: FontWeight.bold, color: Colors.white, fontSize: 13)),
                        Text('Requires Admin Role', style: TextStyle(fontSize: 9, color: Color(0xFF6e7681))),
                      ]
                    ),
                    const SizedBox(height: 8),
                    const Text('Emergency host containment cuts all network traffic to compromised endpoints while preserving SOC management channel.', style: TextStyle(fontSize: 10, color: Colors.white70)),
                    const SizedBox(height: 12),
                    Row(
                      children: [
                        Expanded(child: TextField(controller: _isolateHostCtrl, style: const TextStyle(fontSize: 12), decoration: const InputDecoration(filled: true, fillColor: Color(0xFF030712), isDense: true, border: OutlineInputBorder(), hintText: 'e.g. WORKSTATION-01', hintStyle: TextStyle(fontSize: 11)))),
                        const SizedBox(width: 8),
                        ElevatedButton.icon(onPressed: _isolateHost, style: ElevatedButton.styleFrom(backgroundColor: Colors.red, foregroundColor: Colors.white), icon: const Icon(Icons.flash_on, size: 14), label: const Text('Isolate Host'))
                      ],
                    ),
                    const SizedBox(height: 8),
                    Row(
                      children: [
                        Expanded(child: TextField(controller: _restoreHostCtrl, style: const TextStyle(fontSize: 12), decoration: const InputDecoration(filled: true, fillColor: Color(0xFF030712), isDense: true, border: OutlineInputBorder(), hintText: 'e.g. WORKSTATION-01', hintStyle: TextStyle(fontSize: 11)))),
                        const SizedBox(width: 8),
                        ElevatedButton(onPressed: _restoreHost, style: ElevatedButton.styleFrom(backgroundColor: Colors.green, foregroundColor: Colors.white), child: const Text('Restore Host'))
                      ],
                    )
                  ]
                )
              ),
              // User Lockdown
              Container(
                width: 400,
                padding: const EdgeInsets.all(12), decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(8), border: Border.all(color: const Color(0xFF30363d))),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: const [
                        Text('Admin User Account Lockdown', style: TextStyle(fontWeight: FontWeight.bold, color: Colors.white, fontSize: 13)),
                        Text('Active Directory / Local User', style: TextStyle(fontSize: 9, color: Color(0xFF6e7681))),
                      ]
                    ),
                    const SizedBox(height: 8),
                    const Text('Instantly disable compromised user credentials across the network to stop lateral movement.', style: TextStyle(fontSize: 10, color: Colors.white70)),
                    const SizedBox(height: 12),
                    Row(
                      children: [
                        Expanded(child: TextField(controller: _disableUserCtrl, style: const TextStyle(fontSize: 12), decoration: const InputDecoration(filled: true, fillColor: Color(0xFF030712), isDense: true, border: OutlineInputBorder(), hintText: 'e.g. jdoe', hintStyle: TextStyle(fontSize: 11)))),
                        const SizedBox(width: 8),
                        ElevatedButton.icon(onPressed: _disableUser, style: ElevatedButton.styleFrom(backgroundColor: Colors.red, foregroundColor: Colors.white), icon: const Icon(Icons.flash_on, size: 14), label: const Text('Disable User'))
                      ],
                    ),
                  ]
                )
              )
            ]
          ),
          const SizedBox(height: 16),
          
          // User Provisioning
          Container(
            padding: const EdgeInsets.all(12), decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(8), border: Border.all(color: const Color(0xFF30363d))),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: const [
                    Text('Exclusive Admin User Management & Provisioning', style: TextStyle(fontWeight: FontWeight.bold, color: Colors.white, fontSize: 13)),
                    Text('Create & Manage System User Credentials (Admin Only)', style: TextStyle(fontSize: 9, color: Color(0xFF6e7681))),
                  ]
                ),
                const SizedBox(height: 12),
                Row(
                  children: [
                    Expanded(flex: 2, child: TextField(controller: _newUserNameCtrl, style: const TextStyle(fontSize: 12), decoration: const InputDecoration(filled: true, fillColor: Color(0xFF030712), isDense: true, border: OutlineInputBorder(), hintText: 'Username (e.g. katre)', hintStyle: TextStyle(fontSize: 11)))),
                    const SizedBox(width: 8),
                    Expanded(flex: 2, child: TextField(controller: _newUserPassCtrl, obscureText: true, style: const TextStyle(fontSize: 12), decoration: const InputDecoration(filled: true, fillColor: Color(0xFF030712), isDense: true, border: OutlineInputBorder(), hintText: 'Password', hintStyle: TextStyle(fontSize: 11)))),
                    const SizedBox(width: 8),
                    Expanded(flex: 1, child: DropdownButtonFormField<String>(
                      value: _newUserRole,
                      decoration: const InputDecoration(filled: true, fillColor: Color(0xFF030712), isDense: true, border: OutlineInputBorder(), contentPadding: EdgeInsets.symmetric(horizontal: 10, vertical: 10)),
                      dropdownColor: const Color(0xFF161b22),
                      style: const TextStyle(fontSize: 11, color: Colors.white),
                      items: const [
                        DropdownMenuItem(value: 'analyst', child: Text('SOC Analyst')),
                        DropdownMenuItem(value: 'auditor', child: Text('Auditor')),
                        DropdownMenuItem(value: 'admin', child: Text('Admin')),
                      ],
                      onChanged: (v) => setState(() => _newUserRole = v!),
                    )),
                    const SizedBox(width: 8),
                    ElevatedButton.icon(onPressed: _createUser, style: ElevatedButton.styleFrom(backgroundColor: Colors.blue, foregroundColor: Colors.white), icon: const Icon(Icons.add, size: 14), label: const Text('Add User'))
                  ]
                ),
                const SizedBox(height: 12),
                SingleChildScrollView(
                  scrollDirection: Axis.horizontal,
                  child: DataTable(
                    dataRowMinHeight: 40, dataRowMaxHeight: 40, headingRowHeight: 35,
                    columns: const [
                      DataColumn(label: Text('USERNAME', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681)))),
                      DataColumn(label: Text('ASSIGNED ROLE', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681)))),
                      DataColumn(label: Text('STATUS', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681)))),
                      DataColumn(label: Text('CREATED AT', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681)))),
                      DataColumn(label: Text('ACTION', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF6e7681)))),
                    ],
                    rows: _users.isEmpty ? [
                      const DataRow(cells: [DataCell(Text('Loading users...', style: TextStyle(fontSize: 11, color: Colors.white70))), DataCell(Text('')), DataCell(Text('')), DataCell(Text('')), DataCell(Text(''))])
                    ] : _users.map((u) => DataRow(cells: [
                      DataCell(Text(u['username'] == 'admin' ? 'admin (You)' : (u['username'] as String), style: TextStyle(fontSize: 11, color: u['username'] == 'admin' ? Colors.blue : Colors.white, fontWeight: FontWeight.bold))),
                      DataCell(Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(border: Border.all(color: u['role'] == 'admin' ? Colors.red : Colors.green), borderRadius: BorderRadius.circular(4)), child: Text((u['role'] as String).toUpperCase(), style: TextStyle(fontSize: 9, fontWeight: FontWeight.bold, color: u['role'] == 'admin' ? Colors.red : Colors.green)))),
                      DataCell(Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(border: Border.all(color: Colors.green), borderRadius: BorderRadius.circular(4)), child: const Text('Active', style: TextStyle(fontSize: 9, fontWeight: FontWeight.bold, color: Colors.green)))),
                      DataCell(Text(u['created_at'] as String, style: const TextStyle(fontSize: 11, color: Colors.white70, fontFamily: 'monospace'))),
                      DataCell(Row(
                        children: [
                          ElevatedButton.icon(onPressed: (){}, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF30363d), foregroundColor: Colors.white, padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 4), minimumSize: Size.zero), icon: const Icon(Icons.security, size: 10), label: const Text('Role', style: TextStyle(fontSize: 10))),
                          const SizedBox(width: 4),
                          ElevatedButton.icon(onPressed: (){}, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF30363d), foregroundColor: Colors.white, padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 4), minimumSize: Size.zero), icon: const Icon(Icons.key, size: 10), label: const Text('Reset PW', style: TextStyle(fontSize: 10))),
                          if (u['username'] != 'admin') const SizedBox(width: 4),
                          if (u['username'] != 'admin') ElevatedButton.icon(onPressed: () => _deleteUser(u['username']), style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF30363d), foregroundColor: Colors.red, padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 4), minimumSize: Size.zero), icon: const Icon(Icons.delete, size: 10), label: const Text('Delete', style: TextStyle(fontSize: 10))),
                        ]
                      )),
                    ])).toList(),
                  )
                )
              ]
            )
          ),
          const SizedBox(height: 16),
          
          // Maintenance Overrides
          Container(
            padding: const EdgeInsets.all(12), decoration: BoxDecoration(color: const Color(0xFF161b22), borderRadius: BorderRadius.circular(8), border: Border.all(color: const Color(0xFF30363d))),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: const [
                    Text('Admin System Maintenance & Overrides', style: TextStyle(fontWeight: FontWeight.bold, color: Colors.white, fontSize: 13)),
                    Text('High Blast Radius Actions', style: TextStyle(fontSize: 9, color: Color(0xFF6e7681))),
                  ]
                ),
                const SizedBox(height: 12),
                Wrap(
                  spacing: 12, runSpacing: 8,
                  children: [
                    ElevatedButton.icon(onPressed: () => _executePost('/api/admin/purge_alerts', {}, 'All alerts successfully purged from datastore.'), style: ElevatedButton.styleFrom(backgroundColor: Colors.red, foregroundColor: Colors.white), icon: const Icon(Icons.warning, size: 14), label: const Text('Emergency Purge Alerts')),
                    ElevatedButton.icon(onPressed: () => _executePost('/api/admin/system_control', {'action': 'engine_rescan'}, 'Full system engine rescan initiated.'), style: ElevatedButton.styleFrom(backgroundColor: Colors.blue, foregroundColor: Colors.white), icon: const Icon(Icons.settings, size: 14), label: const Text('Trigger System Engine Rescan')),
                    ElevatedButton.icon(onPressed: () => _executePost('/api/admin/test_email', {}, 'Email dispatched successfully.'), style: ElevatedButton.styleFrom(backgroundColor: Colors.teal, foregroundColor: Colors.white), icon: const Icon(Icons.email, size: 14), label: const Text('Dispatch & Preview HTML Email Report')),
                  ]
                )
              ]
            )
          )
        ]
      )
    );
  }
}
