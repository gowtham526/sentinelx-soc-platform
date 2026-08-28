import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/reporting_screens.dart', 'r', encoding='utf-8') as f:
    text = f.read()

# Add imports
if 'import \'../services/api_service.dart\';' not in text:
    text = text.replace("import 'package:flutter/material.dart';", "import 'package:flutter/material.dart';\nimport 'package:url_launcher/url_launcher.dart';\nimport '../services/api_service.dart';")

# 1. Update IncidentReportsScreen
old_print = "onPressed: ()=>_showSnack('Printing Dossier...')"
new_print = "onPressed: () async { _showSnack('Opening Dossier...'); await launchUrl(Uri.parse('${ApiService.baseUrl}/api/report/markdown?token=${ApiService.authToken ?? ''}'), mode: LaunchMode.externalApplication); }"

old_regen = "onPressed: ()=>_showSnack('Regenerating Report...')"
new_regen = "onPressed: () { _showSnack('Regenerating Report...'); setState((){}); }"

old_md33 = "onPressed: ()=>_showSnack('Exporting MD...')"
new_md33 = "onPressed: () async { _showSnack('Downloading Markdown...'); await launchUrl(Uri.parse('${ApiService.baseUrl}/api/report/markdown?token=${ApiService.authToken ?? ''}'), mode: LaunchMode.externalApplication); }"

old_dl33 = "onPressed: ()=>_showSnack('Downloading .md')"
new_dl33 = "onPressed: () async { _showSnack('Downloading .md...'); await launchUrl(Uri.parse('${ApiService.baseUrl}/api/report/markdown?token=${ApiService.authToken ?? ''}'), mode: LaunchMode.externalApplication); }"

text = text.replace(old_print, new_print)
text = text.replace(old_regen, new_regen)
text = text.replace(old_md33, new_md33)
text = text.replace(old_dl33, new_dl33)

# 2. Update ReportGeneratorScreen
old_md34 = "onPressed: ()=>_showSnack(context, 'Exporting MD to downloads...')"
new_md34 = "onPressed: () async { _showSnack(context, 'Downloading MD...'); await launchUrl(Uri.parse('${ApiService.baseUrl}/api/report/markdown?token=${ApiService.authToken ?? ''}'), mode: LaunchMode.externalApplication); }"

old_csv34 = "onPressed: ()=>_showSnack(context, 'Exporting CSV to downloads...')"
new_csv34 = "onPressed: () async { _showSnack(context, 'Downloading CSV...'); await launchUrl(Uri.parse('${ApiService.baseUrl}/api/report/csv?token=${ApiService.authToken ?? ''}'), mode: LaunchMode.externalApplication); }"

old_json34 = "onPressed: ()=>_showSnack(context, 'Exporting JSON to downloads...')"
new_json34 = "onPressed: () async { _showSnack(context, 'Downloading JSON...'); await launchUrl(Uri.parse('${ApiService.baseUrl}/api/report/json?token=${ApiService.authToken ?? ''}'), mode: LaunchMode.externalApplication); }"

text = text.replace(old_md34, new_md34)
text = text.replace(old_csv34, new_csv34)
text = text.replace(old_json34, new_json34)

# 3. Update ExportLogsScreen
old_export_box = "onPressed: ()=>_showSnack(context, 'Downloading ${btnLabel}...')"
new_export_box = """onPressed: () async {
            _showSnack(context, 'Downloading ${btnLabel}...');
            String endpoint = '/api/report/markdown';
            if (title.contains('CSV')) endpoint = '/api/report/csv';
            if (title.contains('JSON')) endpoint = '/api/report/json';
            await launchUrl(Uri.parse('${ApiService.baseUrl}$endpoint?token=${ApiService.authToken ?? ''}'), mode: LaunchMode.externalApplication);
          }"""

text = text.replace(old_export_box, new_export_box)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/reporting_screens.dart', 'w', encoding='utf-8') as f:
    f.write(text)
