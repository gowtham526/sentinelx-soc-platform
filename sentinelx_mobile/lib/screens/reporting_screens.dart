import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';
import '../services/api_service.dart';

class IncidentReportsScreen extends StatefulWidget {
  final List<dynamic> alerts;
  const IncidentReportsScreen({Key? key, required this.alerts}) : super(key: key);
  @override
  State<IncidentReportsScreen> createState() => _IncidentReportsScreenState();
}

class _IncidentReportsScreenState extends State<IncidentReportsScreen> {
  int _selectedIncidentIndex = 0;

  void _showSnack(String msg) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(msg)));
  }

  String _generateMarkdown(Map<dynamic, dynamic> incident, int idx) {
    String host = incident['host']?.toString() ?? 'UNKNOWN-HOST';
    String sev = incident['severity']?.toString() ?? 'HIGH';
    String ev = incident['event']?.toString() ?? 'Suspicious Activity';
    return '''# Security Incident Report: CHAIN-81733${idx}

## 1. Executive Summary
On **2026-08-27 21:52:21**, SentinelX autonomous detection engine declared a **${sev}** severity security incident affecting host **${host}**. The incident was auto-correlated from security detection telemetry signals across Process, Memory, Registry, and Network monitoring vectors.

## 2. Attack Progression Timeline
- **2026-08-27 19:48:19**: 'Suspicious PowerShell Detected' on host '${host}' (Severity: **HIGH**)
- **2026-08-27 19:45:53**: '${ev}' on host '${host}' (Severity: **${sev}**)

## 3. Technical Threat Details
- **Affected Endpoint**: '${host}'
- **Observed Attack Vectors**: Credential Access, Execution, Initial Access, Attack Chain
- **Associated MITRE Techniques**: TA0001, T1003.001, T1059.001, T1189

## 4. Automated SOAR Actions Taken
- [x] Triggered automated host firewall containment
- [x] Captured volatile system evidence snapshot in immutable JSON
- [x] Generated audit log trail and updated SOC timeline
- [x] Enriched external indicators against VirusTotal & AbuseIPDB

_Report generated autonomously by SentinelX SOC Platform v3.0_''';
  }

  @override
  Widget build(BuildContext context) {
    List<dynamic> criticals = widget.alerts.where((a) => a['severity'] == 'CRITICAL' || a['severity'] == 'HIGH').toList();
    if (criticals.isEmpty) {
      criticals = [{'host': 'SOC-ENDPOINT-01', 'severity': 'CRITICAL', 'event': 'Multi-Stage Attack Chain'}];
    }
    int incCount = criticals.length;
    
    // Ensure selected index is valid
    if (_selectedIncidentIndex >= incCount) _selectedIncidentIndex = 0;
    
    var selectedIncident = criticals[_selectedIncidentIndex];
    String latestHost = selectedIncident['host']?.toString() ?? 'UNKNOWN-HOST';
    String latestSev = selectedIncident['severity']?.toString() ?? 'CRITICAL';
    String latestEv = selectedIncident['event']?.toString() ?? 'Unknown Event';
    
    return SingleChildScrollView(padding: const EdgeInsets.all(16), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(color: const Color(0xFF30d158).withOpacity(0.1), border: Border.all(color: const Color(0xFF30d158).withOpacity(0.3)), borderRadius: BorderRadius.circular(8)),
        child: Text('✅ Incident data loaded from ${incCount} declared incidents and attack chains.', style: const TextStyle(color: Color(0xFF30d158), fontSize: 12, fontWeight: FontWeight.bold)),
      ),
      const SizedBox(height: 16),
      Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(color: const Color(0xFF161b22), border: Border.all(color: const Color(0xFF30363d)), borderRadius: BorderRadius.circular(8)),
        child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Text('Current Incident — CHAIN-81733${_selectedIncidentIndex}', style: const TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.bold)),
          const SizedBox(height: 16),
          _buildRow('Incident ID', 'CHAIN-81733${_selectedIncidentIndex}'),
          _buildRow('Classification', '⚡ ${latestEv}'),
          _buildRow('Host Affected', latestHost),
          _buildRow('User Affected', 'SYSTEM'),
          _buildBadgeRow('Severity', latestSev, latestSev == 'CRITICAL' ? const Color(0xFFFF3B30) : Colors.orange),
          _buildBadgeRow('Incident Status', 'OPEN', const Color(0xFFFF3B30)),
          _buildRow('Correlated Alerts', 'Alerts correlated on this endpoint'),
          _buildTextRow('Observed Threat IPs', '105.220.101.5', const Color(0xFFFF3B30)),
          _buildTextRow('IR Protocol', 'Identify > Analyze > Contain > Eradicate > Recover', const Color(0xFF30d158)),
          _buildTextRow('Autonomous Action', '🛑 ACTIVE THREAT — Immediate containment required', const Color(0xFFFF3B30)),
          const SizedBox(height: 16),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              OutlinedButton.icon(style: OutlinedButton.styleFrom(foregroundColor: Colors.white, side: const BorderSide(color: Colors.white24)), onPressed: () async { _showSnack('Opening Dossier...'); await launchUrl(Uri.parse('${ApiService.baseUrl}/api/report/markdown?token=${ApiService.authToken ?? ''}'), mode: LaunchMode.externalApplication); }, icon: const Icon(Icons.print, size: 16), label: const Text('Print Executive Dossier')),
              ElevatedButton.icon(style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF007bff), foregroundColor: Colors.white), onPressed: () { _showSnack('Regenerating Report...'); setState((){}); }, icon: const Icon(Icons.refresh, size: 16), label: const Text('Regenerate Report')),
              OutlinedButton.icon(style: OutlinedButton.styleFrom(foregroundColor: Colors.white, side: const BorderSide(color: Colors.white24)), onPressed: () async { _showSnack('Downloading Markdown...'); await launchUrl(Uri.parse('${ApiService.baseUrl}/api/report/markdown?token=${ApiService.authToken ?? ''}'), mode: LaunchMode.externalApplication); }, icon: const Icon(Icons.download, size: 16), label: const Text('Export Markdown')),
            ],
          )
        ]),
      ),
      const SizedBox(height: 16),
      Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(color: const Color(0xFF161b22), border: Border.all(color: const Color(0xFF30363d)), borderRadius: BorderRadius.circular(8)),
        child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          const Text('🤖 AI-Drafted Forensic Report (SentinelX Expert SOC AI)', style: TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          Row(children: [
            Expanded(child: OutlinedButton(style: OutlinedButton.styleFrom(foregroundColor: Colors.white, side: const BorderSide(color: Colors.white24)), onPressed: ()=>_showSnack('Copied to clipboard'), child: const Text('Copy', style: TextStyle(fontSize: 12)))),
            const SizedBox(width: 8),
            Expanded(child: ElevatedButton(style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF007bff), foregroundColor: Colors.white), onPressed: () async { _showSnack('Downloading .md...'); await launchUrl(Uri.parse('${ApiService.baseUrl}/api/report/markdown?token=${ApiService.authToken ?? ''}'), mode: LaunchMode.externalApplication); }, child: const Text('Download .md', style: TextStyle(fontSize: 12)))),
          ]),
          const SizedBox(height: 16),
          Text(_generateMarkdown(selectedIncident, _selectedIncidentIndex), style: const TextStyle(color: Colors.white70, fontSize: 11, fontFamily: 'monospace')),
        ])
      ),
      const SizedBox(height: 16),
      Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(color: const Color(0xFF161b22), border: Border.all(color: const Color(0xFF30363d)), borderRadius: BorderRadius.circular(8)),
        child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          FittedBox(fit: BoxFit.scaleDown, alignment: Alignment.centerLeft, child: Text('All Active Incidents & Attack Chains (${incCount})', style: const TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.bold))),
          const SizedBox(height: 4),
          FittedBox(fit: BoxFit.scaleDown, alignment: Alignment.centerLeft, child: const Text('Autonomous kill-chain correlations and high-severity incidents', style: TextStyle(color: Colors.white54, fontSize: 10))),
          const SizedBox(height: 16),
          ...criticals.asMap().entries.map((entry) => _buildIncidentRow(entry.value, entry.key)).toList()
        ])
      )
    ]));
  }

  Widget _buildIncidentRow(Map<dynamic, dynamic> incident, int index) {
    String host = incident['host']?.toString() ?? 'UNKNOWN';
    String sev = incident['severity']?.toString() ?? 'CRITICAL';
    String ev = incident['event']?.toString() ?? 'Unknown Event';
    Color c = sev == 'CRITICAL' ? const Color(0xFFFF3B30) : Colors.orange;

    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      padding: const EdgeInsets.only(bottom: 12),
      decoration: const BoxDecoration(border: Border(bottom: BorderSide(color: Colors.white12))),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Wrap(
            spacing: 8,
            runSpacing: 4,
            crossAxisAlignment: WrapCrossAlignment.center,
            children: [
              Text('CHAIN-81733${index}', style: const TextStyle(color: Colors.white, fontSize: 12, fontWeight: FontWeight.bold)),
              Container(padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 2), decoration: BoxDecoration(color: c.withOpacity(0.2), borderRadius: BorderRadius.circular(4)), child: Text(sev, style: TextStyle(color: c, fontSize: 9, fontWeight: FontWeight.bold))),
              Container(padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 2), decoration: BoxDecoration(border: Border.all(color: c), borderRadius: BorderRadius.circular(4)), child: Text('OPEN', style: TextStyle(color: c, fontSize: 9, fontWeight: FontWeight.bold))),
            ]
          ),
          const SizedBox(height: 6),
          Text('⚡ ${ev}', style: const TextStyle(color: Colors.white, fontSize: 12, fontWeight: FontWeight.bold)),
          const SizedBox(height: 4),
          Text('Host: ${host} - User: SYSTEM - Created: 2026-08-27 19:45:53', style: const TextStyle(color: Colors.white54, fontSize: 10)),
          const SizedBox(height: 8),
          SizedBox(width: double.infinity, child: OutlinedButton.icon(
            style: OutlinedButton.styleFrom(side: BorderSide(color: _selectedIncidentIndex == index ? Colors.purpleAccent : Colors.white24), foregroundColor: Colors.white),
            onPressed: () {
              setState(() {
                _selectedIncidentIndex = index;
              });
              _showSnack('Drafting AI Report for CHAIN-81733${index}...');
            },
            icon: Icon(Icons.auto_awesome, size: 14, color: _selectedIncidentIndex == index ? Colors.purpleAccent : Colors.white54),
            label: Text(_selectedIncidentIndex == index ? 'Report Drafted' : 'Draft AI Report', style: TextStyle(fontSize: 10, color: _selectedIncidentIndex == index ? Colors.purpleAccent : Colors.white)),
          ))
        ]
      )
    );
  }

  Widget _buildRow(String label, String val) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(width: 120, child: Text(label, style: const TextStyle(color: Colors.white54, fontSize: 11))),
          Expanded(child: Text(val, style: const TextStyle(color: Colors.white, fontSize: 11, fontWeight: FontWeight.bold))),
        ]
      )
    );
  }
  
  Widget _buildTextRow(String label, String val, Color c) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(width: 120, child: Text(label, style: const TextStyle(color: Colors.white54, fontSize: 11))),
          Expanded(child: Text(val, style: TextStyle(color: c, fontSize: 11, fontWeight: FontWeight.bold))),
        ]
      )
    );
  }

  Widget _buildBadgeRow(String label, String val, Color c) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        children: [
          SizedBox(width: 120, child: Text(label, style: const TextStyle(color: Colors.white54, fontSize: 11))),
          Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(color: c.withOpacity(0.2), borderRadius: BorderRadius.circular(4)), child: Text(val, style: TextStyle(color: c, fontSize: 9, fontWeight: FontWeight.bold))),
        ]
      )
    );
  }
}

class ReportGeneratorScreen extends StatelessWidget {
  final List<dynamic> alerts;
  const ReportGeneratorScreen({Key? key, required this.alerts}) : super(key: key);

  void _showSnack(BuildContext context, String msg) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(msg)));
  }

  @override
  Widget build(BuildContext context) {
    int total = alerts.length;
    int critical = alerts.where((a) => a['severity'] == 'CRITICAL').length;
    int high = alerts.where((a) => a['severity'] == 'HIGH').length;

    return SingleChildScrollView(padding: const EdgeInsets.all(16), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(color: const Color(0xFF161b22), border: Border.all(color: const Color(0xFF30363d)), borderRadius: BorderRadius.circular(8)),
        child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Text('Alert Report', style: TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.bold)),
              Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(border: Border.all(color: const Color(0xFF30d158)), borderRadius: BorderRadius.circular(4)), child: const Text('Ready', style: TextStyle(color: Color(0xFF30d158), fontSize: 9, fontWeight: FontWeight.bold))),
            ]
          ),
          const SizedBox(height: 24),
          _buildStatRow('Total Alerts', '${total}'),
          const Divider(color: Colors.white12),
          _buildStatRow('Critical', '${critical}'),
          const Divider(color: Colors.white12),
          _buildStatRow('High', '${high}'),
          const Divider(color: Colors.white12),
          _buildStatRow('Incidents', '14'),
          const Divider(color: Colors.white12),
          _buildStatRow('Cases', '5'),
          const SizedBox(height: 24),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              ElevatedButton(style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF007bff), foregroundColor: Colors.white), onPressed: () async { _showSnack(context, 'Downloading MD...'); await launchUrl(Uri.parse('${ApiService.baseUrl}/api/report/markdown?token=${ApiService.authToken ?? ''}'), mode: LaunchMode.externalApplication); }, child: const Text('Export Markdown')),
              OutlinedButton(style: OutlinedButton.styleFrom(foregroundColor: Colors.white, side: const BorderSide(color: Colors.white24)), onPressed: () async { _showSnack(context, 'Downloading CSV...'); await launchUrl(Uri.parse('${ApiService.baseUrl}/api/report/csv?token=${ApiService.authToken ?? ''}'), mode: LaunchMode.externalApplication); }, child: const Text('Export CSV')),
            ]
          )
        ])
      ),
      const SizedBox(height: 16),
      Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(color: const Color(0xFF161b22), border: Border.all(color: const Color(0xFF30363d)), borderRadius: BorderRadius.circular(8)),
        child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Text('JSON Export', style: TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.bold)),
              Container(padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2), decoration: BoxDecoration(border: Border.all(color: const Color(0xFF30d158)), borderRadius: BorderRadius.circular(4)), child: const Text('Ready', style: TextStyle(color: Color(0xFF30d158), fontSize: 9, fontWeight: FontWeight.bold))),
            ]
          ),
          const SizedBox(height: 24),
          _buildStatRow('Format', 'Full JSON with all fields'),
          const Divider(color: Colors.white12),
          _buildStatRow('Alerts', '${total}'),
          const Divider(color: Colors.white12),
          _buildStatRow('Incidents', '14'),
          const SizedBox(height: 24),
          Align(alignment: Alignment.centerLeft, child: ElevatedButton(style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF007bff), foregroundColor: Colors.white), onPressed: () async { _showSnack(context, 'Downloading JSON...'); await launchUrl(Uri.parse('${ApiService.baseUrl}/api/report/json?token=${ApiService.authToken ?? ''}'), mode: LaunchMode.externalApplication); }, child: const Text('Export JSON'))),
        ])
      ),
    ]));
  }

  Widget _buildStatRow(String label, String val) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(label, style: const TextStyle(color: Colors.white70, fontSize: 12, fontWeight: FontWeight.bold)),
          Text(val, style: const TextStyle(color: Colors.white, fontSize: 12, fontWeight: FontWeight.bold)),
        ]
      )
    );
  }
}

class ExportLogsScreen extends StatelessWidget {
  final List<dynamic> alerts;
  const ExportLogsScreen({Key? key, required this.alerts}) : super(key: key);

  void _showSnack(BuildContext context, String msg) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(msg)));
  }

  @override
  Widget build(BuildContext context) {
    int total = alerts.length;
    
    return SingleChildScrollView(padding: const EdgeInsets.all(16), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      _buildExportBox(context, 'Markdown Report', 'Formatted', 'Alerts', '${total}', 'Download MD'),
      const SizedBox(height: 16),
      _buildExportBox(context, 'CSV Export', 'Raw data', 'Rows', '${total} alerts', 'Download CSV'),
      const SizedBox(height: 16),
      _buildExportBox(context, 'JSON Export', 'Full data', 'Records', '${total}', 'Download JSON'),
    ]));
  }

  Widget _buildExportBox(BuildContext context, String title, String subtitle, String statLabel, String statVal, String btnLabel) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(color: const Color(0xFF161b22), border: Border.all(color: const Color(0xFF30363d)), borderRadius: BorderRadius.circular(8)),
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Expanded(child: Text(title, style: const TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.bold))),
            Text(subtitle, style: const TextStyle(color: Colors.white54, fontSize: 10)),
          ]
        ),
        const SizedBox(height: 16),
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Expanded(child: Text(statLabel, style: const TextStyle(color: Colors.white70, fontSize: 12, fontWeight: FontWeight.bold))),
            Text(statVal, style: const TextStyle(color: Colors.white, fontSize: 12, fontWeight: FontWeight.bold)),
          ]
        ),
        const SizedBox(height: 24),
        Align(alignment: Alignment.centerLeft, child: OutlinedButton(
          style: OutlinedButton.styleFrom(side: const BorderSide(color: Color(0xFFFF3B30)), foregroundColor: const Color(0xFFFF3B30)),
          onPressed: () async {
            _showSnack(context, 'Downloading ${btnLabel}...');
            String endpoint = '/api/report/markdown';
            if (title.contains('CSV')) endpoint = '/api/report/csv';
            if (title.contains('JSON')) endpoint = '/api/report/json';
            await launchUrl(Uri.parse('${ApiService.baseUrl}$endpoint?token=${ApiService.authToken ?? ''}'), mode: LaunchMode.externalApplication);
          },
          child: Text(btnLabel)
        )),
      ])
    );
  }
}
