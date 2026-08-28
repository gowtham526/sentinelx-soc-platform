import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/settings_screens.dart', 'r', encoding='utf-8') as f:
    text = f.read()

replacement = '''
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
'''

# Find the block from _createUserDialog to the end of _deleteUser
old_pattern = r'void _createUserDialog\(\) \{[\s\S]*?void _deleteUser\(String username\) \{[\s\S]*?\}'
text = re.sub(old_pattern, replacement.strip(), text)

# Now we need to update the buttons in the build method
# Search for: ElevatedButton.icon(onPressed: (){}, ... label: const Text('Role'
# Replace with: ElevatedButton.icon(onPressed: () => _changeRoleDialog(u['username'], u['role']), ...
text = text.replace(
    "ElevatedButton.icon(onPressed: (){}, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF30363d), foregroundColor: Colors.white, padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 4), minimumSize: Size.zero), icon: const Icon(Icons.security, size: 10), label: const Text('Role', style: TextStyle(fontSize: 10)))",
    "ElevatedButton.icon(onPressed: () => _changeRoleDialog(u['username'], u['role']), style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF30363d), foregroundColor: Colors.white, padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 4), minimumSize: Size.zero), icon: const Icon(Icons.security, size: 10), label: const Text('Role', style: TextStyle(fontSize: 10)))"
)

# Search for: ElevatedButton.icon(onPressed: (){}, ... label: const Text('Reset PW'
# Replace with: ElevatedButton.icon(onPressed: () => _resetPasswordDialog(u['username']), ...
text = text.replace(
    "ElevatedButton.icon(onPressed: (){}, style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF30363d), foregroundColor: Colors.white, padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 4), minimumSize: Size.zero), icon: const Icon(Icons.key, size: 10), label: const Text('Reset PW', style: TextStyle(fontSize: 10)))",
    "ElevatedButton.icon(onPressed: () => _resetPasswordDialog(u['username']), style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF30363d), foregroundColor: Colors.white, padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 4), minimumSize: Size.zero), icon: const Icon(Icons.key, size: 10), label: const Text('Reset PW', style: TextStyle(fontSize: 10)))"
)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/settings_screens.dart', 'w', encoding='utf-8') as f:
    f.write(text)

print("Patched UserManagementScreen buttons in settings_screens.dart")
