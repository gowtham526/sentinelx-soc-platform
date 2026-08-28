import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

# Make the fetcher also grab events
old_code = '''final alerts = await ApiService.fetchAlerts();
      if (mounted) setState(() { _alerts = alerts; _isLoading = false; });'''

new_code = '''final alerts = await ApiService.fetchAlerts();
      final events = await ApiService.fetchEventsStream();
      if (mounted) setState(() { 
          _alerts = alerts; 
          _events = events;
          _isLoading = false; 
      });'''

if 'final events = await ApiService.fetchEventsStream()' not in text:
    text = text.replace(old_code, new_code)
    with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
        f.write(text)
    print("Injected events fetch successfully")
else:
    print("Already injected")
