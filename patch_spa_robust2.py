import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'r', encoding='utf-8') as f:
    text = f.read()

# Replace the previous patch
patch_regex = r'<script>\s*// robust role enforcement for sidebar[\s\S]*?</script>'
text = re.sub(patch_regex, '', text)

new_patch = '''
<script>
// robust role enforcement for sidebar
setInterval(function() {
    var role = (window._authUser && window._authUser.role) || sessionStorage.getItem('sx_role');
    if (role && role !== 'admin') {
        var items = document.querySelectorAll('.nav-item, .sidebar-item, .menu-item, li');
        items.forEach(function(el) {
            var txt = el.innerText || el.textContent;
            if ((txt.includes('User Management') || txt.includes('Admin Command')) && txt.length < 50) {
                el.style.display = 'none';
            }
        });
        
        // Also ensure they cannot navigate there manually
        var cv = typeof currentView !== 'undefined' ? currentView : (window.currentView || '');
        if (cv === 'USER_MGMT' || cv === 'ADMIN_COMMAND') {
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

print("Applied robust SPA patch 2")
