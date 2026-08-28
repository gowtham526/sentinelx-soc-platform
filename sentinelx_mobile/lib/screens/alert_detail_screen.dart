import 'package:flutter/material.dart';
import '../services/api_service.dart';

class AlertDetailScreen extends StatefulWidget {
  final dynamic alert;
  const AlertDetailScreen({super.key, required this.alert});

  @override
  State<AlertDetailScreen> createState() => _AlertDetailScreenState();
}

class _AlertDetailScreenState extends State<AlertDetailScreen> {
  late String _status;
  bool _isUpdating = false;

  @override
  void initState() {
    super.initState();
    _status = widget.alert['status'] ?? 'NEW';
  }

  Future<void> _changeStatus(String newStatus) async {
    setState(() => _isUpdating = true);
    final alertId = (widget.alert['id'] ?? widget.alert['alert_id'] ?? '').toString();
    final error = await ApiService.updateAlertStatus(alertId, newStatus);
    if (mounted) {
      setState(() {
        _isUpdating = false;
        if (error == null) _status = newStatus;
      });
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(error == null ? 'Status updated to $newStatus' : 'Failed: $error\\nID: $alertId'),
          backgroundColor: error == null ? const Color(0xFF10B981) : const Color(0xFFF43F5E),
          duration: const Duration(seconds: 4),
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final alert = widget.alert;
    final sev = (alert['severity'] ?? 'LOW').toString().toUpperCase();

    return Scaffold(
      backgroundColor: const Color(0xFF04090F),
      appBar: AppBar(
        backgroundColor: const Color(0xFF0D1B2E),
        title: Text(alert['id'] ?? 'Alert Detail', style: const TextStyle(color: Colors.white, fontSize: 16)),
        elevation: 0,
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: const Color(0xFF0D1B2E),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: const Color(0xFF1A3050)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Text(sev, style: const TextStyle(color: Color(0xFFF43F5E), fontSize: 12, fontWeight: FontWeight.bold)),
                    Text(_status, style: const TextStyle(color: Color(0xFF00C896), fontSize: 12, fontWeight: FontWeight.bold)),
                  ],
                ),
                const SizedBox(height: 8),
                Text(
                  alert['event'] ?? alert['title'] ?? 'Security Incident Alert',
                  style: const TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 12),
                _buildField('Timestamp', alert['timestamp'] ?? '-'),
                _buildField('Host / Computer', alert['host'] ?? '-'),
                _buildField('Target IP', alert['ip'] ?? '-'),
                _buildField('Process Path', alert['process'] ?? alert['path'] ?? '-'),
                _buildField('MITRE Tactic', alert['mitre_tactic'] ?? alert['tactic'] ?? '-'),
                _buildField('MITRE Technique', alert['mitre'] ?? alert['mitre_id'] ?? '-'),
                _buildField('Details', alert['detail'] ?? alert['details'] ?? alert['description'] ?? '-'),
              ],
            ),
          ),
          const SizedBox(height: 20),
          const Text('RESPONSE ACTIONS', style: TextStyle(color: Colors.white, fontSize: 12, fontWeight: FontWeight.bold, letterSpacing: 1)),
          const SizedBox(height: 10),
          Row(
            children: [
              Expanded(
                child: ElevatedButton(
                  style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFFF59E0B)),
                  onPressed: _isUpdating ? null : () => _changeStatus('INVESTIGATING'),
                  child: const Text('Investigate', style: TextStyle(color: Colors.black, fontSize: 12, fontWeight: FontWeight.bold)),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: ElevatedButton(
                  style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF10B981)),
                  onPressed: _isUpdating ? null : () => _changeStatus('RESOLVED'),
                  child: const Text('Resolve', style: TextStyle(color: Colors.black, fontSize: 12, fontWeight: FontWeight.bold)),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildField(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label.toUpperCase(), style: const TextStyle(color: Color(0xFF7B98B8), fontSize: 10, fontWeight: FontWeight.bold)),
          const SizedBox(height: 2),
          Text(value, style: const TextStyle(color: Colors.white, fontSize: 12)),
        ],
      ),
    );
  }
}
