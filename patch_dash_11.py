import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'r', encoding='utf-8') as f:
    text = f.read()

# 1. Add Timer import if not there
if "import 'dart:async';" not in text:
    text = "import 'dart:async';\n" + text

# 2. Add Timer variable to _DashboardScreenState
if "Timer? _refreshTimer;" not in text:
    text = text.replace(
        "class _DashboardScreenState extends State<DashboardScreen> {",
        "class _DashboardScreenState extends State<DashboardScreen> {\n  Timer? _refreshTimer;"
    )

# 3. Start Timer in initState
if "_refreshTimer = Timer.periodic" not in text:
    text = text.replace(
        "void initState() {\n    super.initState();\n    _loadDashboardData();\n  }",
        "void initState() {\n    super.initState();\n    _loadDashboardData();\n    _refreshTimer = Timer.periodic(const Duration(seconds: 3), (_) => _loadDashboardData(silent: true));\n  }"
    )

# 4. Cancel Timer in dispose
if "void dispose() {" not in text:
    # We need to insert a dispose method before the closing brace of the state class or before a known method like `void _handleLogout()`
    idx = text.find("void _handleLogout()")
    dispose_code = "  @override\n  void dispose() {\n    _refreshTimer?.cancel();\n    super.dispose();\n  }\n\n  "
    text = text[:idx] + dispose_code + text[idx:]
else:
    # If dispose exists, add the cancel
    if "_refreshTimer?.cancel();" not in text:
        text = text.replace("void dispose() {\n", "void dispose() {\n    _refreshTimer?.cancel();\n")

# 5. Modify _loadDashboardData to support silent refresh so the loading spinner doesn't flash every 3 seconds
text = text.replace(
    "Future<void> _loadDashboardData() async {\n    setState(() => _isLoading = true);",
    "Future<void> _loadDashboardData({bool silent = false}) async {\n    if (!silent) setState(() => _isLoading = true);"
)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile/lib/screens/dashboard_screen.dart', 'w', encoding='utf-8') as f:
    f.write(text)
print("Patch applied for auto-refresh.")
