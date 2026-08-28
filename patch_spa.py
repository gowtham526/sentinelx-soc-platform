import re

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'r', encoding='utf-8') as f:
    text = f.read()

# Inject a patch at the end of body or right after _authUser logic
patch = '''
<script>
// Periodically check and hide admin-only sidebar items for non-admins
setInterval(function() {
    var role = (window._authUser && window._authUser.role) || sessionStorage.getItem('sx_role');
    if (role && role !== 'admin') {
        var items = document.querySelectorAll('.sidebar-item, .nav-item, li, div');
        items.forEach(function(el) {
            if (el.innerHTML && (el.innerHTML.includes('User Management') || el.innerHTML.includes('Admin Command Center'))) {
                // To avoid hiding the main content, only hide if it's small (like a sidebar button)
                if (el.innerText.length < 50 && el.onclick) {
                    el.style.display = 'none';
                }
            }
        });
        
        // Also remove from slides array if it exists
        if (typeof slides !== 'undefined') {
            for (var i=0; i<slides.length; i++) {
                if ((slides[i].id === 'USER_MGMT' || slides[i].id === 'ADMIN_COMMAND') && !slides[i]._hidden) {
                    slides[i]._hidden = true;
                }
            }
        }
    }
}, 1000);
</script>
</body>
'''

text = text.replace('</body>', patch)

with open('C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_spa.html', 'w', encoding='utf-8') as f:
    f.write(text)

print("Patched SPA")
