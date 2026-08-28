with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    d_content = f.read()

old_dash_helper = """
  Future<void> _updateAlert(String id, String status, String label) async {
    bool success = await ApiService.updateAlertStatus(id, status);
    if (success) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Marked as $label'), backgroundColor: const Color(0xFF10B981)));
      _loadDashboardData();
    } else {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Failed to update alert'), backgroundColor: Color(0xFFF43F5E)));
    }
  }
"""

new_dash_helper = """
  Future<void> _updateAlert(String id, String status, String label) async {
    String? error = await ApiService.updateAlertStatus(id, status);
    if (error == null) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Marked as $label'), backgroundColor: const Color(0xFF10B981)));
      _loadDashboardData();
    } else {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Failed: $error\\nID: $id'), backgroundColor: const Color(0xFFF43F5E), duration: const Duration(seconds: 4)));
    }
  }
"""

d_content = d_content.replace(old_dash_helper.strip(), new_dash_helper.strip())

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(d_content)


with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/alert_detail_screen.dart', 'r', encoding='utf-8') as f:
    a_content = f.read()

old_a_helper = """
  Future<void> _changeStatus(String newStatus) async {
    setState(() {
      _isUpdating = true;
    });

    final alertId = widget.alert['id'] ?? '';
    final success = await ApiService.updateAlertStatus(alertId, newStatus);

    setState(() {
      _isUpdating = false;
      if (success) {
        _status = newStatus;
      }
    });

    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(success ? 'Status updated to $newStatus' : 'Failed to update status'),
          backgroundColor: success ? const Color(0xFF10B981) : const Color(0xFFF43F5E),
        ),
      );
    }
  }
"""

new_a_helper = """
  Future<void> _changeStatus(String newStatus) async {
    setState(() {
      _isUpdating = true;
    });

    final alertId = (widget.alert['id'] ?? widget.alert['alert_id'] ?? '').toString();
    final error = await ApiService.updateAlertStatus(alertId, newStatus);

    setState(() {
      _isUpdating = false;
      if (error == null) {
        _status = newStatus;
      }
    });

    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(error == null ? 'Status updated to $newStatus' : 'Failed: $error\\nID: $alertId'),
          backgroundColor: error == null ? const Color(0xFF10B981) : const Color(0xFFF43F5E),
          duration: const Duration(seconds: 4),
        ),
      );
    }
  }
"""

a_content = a_content.replace(old_a_helper.strip(), new_a_helper.strip())

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/alert_detail_screen.dart', 'w', encoding='utf-8') as f:
    f.write(a_content)
