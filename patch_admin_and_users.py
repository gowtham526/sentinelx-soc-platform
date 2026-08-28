import re

# 1. Fix admin_screens.dart \$ issue
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/admin_screens.dart', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace(r'\$', '$')

# Also fix the UserManagement table in Admin Command Center! It has a user table too.
# I will just replace the actions column there as well.
# It currently has `DataCell(TextButton(onPressed: () => _deleteUser(u['username']), child: const Text('Delete', style: TextStyle(fontSize: 10, color: Colors.red)))),`
# Let's replace the whole DataTable rows definition in admin_screens.dart:

new_admin_row = '''
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
'''

text = re.sub(r'rows: _users\.isEmpty \? \[.*?\]\)\)\.toList\(\),', new_admin_row.strip(), text, flags=re.DOTALL)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/admin_screens.dart', 'w', encoding='utf-8') as f:
    f.write(text)

# 2. Fix UserManagementScreen in settings_screens.dart
with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/settings_screens.dart', 'r', encoding='utf-8') as f:
    text2 = f.read()

new_user_row = '''
                    rows: _users.map((u) => DataRow(cells: [
                      DataCell(Text(u['username'] == 'admin' ? 'admin (You)' : (u['username'] as String), style: TextStyle(fontSize: 11, color: u['username'] == 'admin' ? Colors.blue : Colors.white, fontWeight: FontWeight.bold))),
                      DataCell(Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(border: Border.all(color: u['role'] == 'admin' ? Colors.red : (u['role'] == 'auditor' ? Colors.orange : Colors.green)), borderRadius: BorderRadius.circular(4)), child: Text((u['role'] as String).toUpperCase(), style: TextStyle(fontSize: 9, fontWeight: FontWeight.bold, color: u['role'] == 'admin' ? Colors.red : (u['role'] == 'auditor' ? Colors.orange : Colors.green))))),
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
'''

text2 = re.sub(r'rows: _users\.map\(\(u\) => DataRow\(cells: \[.*?\]\)\)\.toList\(\),', new_user_row.strip(), text2, flags=re.DOTALL)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/settings_screens.dart', 'w', encoding='utf-8') as f:
    f.write(text2)

print("UI rows and backslashes patched successfully!")
