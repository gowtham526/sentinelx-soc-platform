import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'r', encoding='utf-8') as f:
    text = f.read()

# Replace the previous patch with a more robust one
patch_regex = r'<script>\s*// Periodically check and hide admin-only sidebar items[\s\S]*?</script>'
text = re.sub(patch_regex, '', text)

new_patch = '''
<script>
// robust role enforcement for sidebar
setInterval(function() {
    var role = (window._authUser && window._authUser.role) || sessionStorage.getItem('sx_role');
    if (role && role !== 'admin') {
        var items = document.querySelectorAll('.nav-item');
        items.forEach(function(el) {
            var txt = el.innerText || el.textContent;
            if (txt.includes('User Management') || txt.includes('Admin Command')) {
                el.style.display = 'none';
            }
        });
        
        // Also ensure they cannot navigate there manually
        if (window.currentView === 'USER_MGMT' || window.currentView === 'ADMIN_COMMAND') {
            if (typeof go === 'function') go('MAIN_DASHBOARD');
        }
    }
}, 500);
</script>
</body>
'''

text = text.replace('</body>', new_patch)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'w', encoding='utf-8') as f:
    f.write(text)

print("Applied robust SPA patch")
