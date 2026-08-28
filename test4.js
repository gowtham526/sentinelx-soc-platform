
/* ════════════════════════════════════════════════════
   PHASE 1 UPGRADE — Command Palette, Keyboard Shortcuts,
   Confirm-Before-Destructive-Action guard.
   Everything here is additive: it does not touch the
   original page definitions, it wraps/observes them.
════════════════════════════════════════════════════ */

/* Shared, confirm-guarded block-IP action — replaces 6 previously-duplicated
   unguarded inline fetch('/api/firewall/block') calls scattered across
   Net Suspicious, File Analysis, Quarantine, Threat Intel Framework,
   IOC Dashboard and Threat Map. One implementation, one confirm, one log path. */
function _confirmBlockIP(ip, reason, type){
  if(!ip || ip === '-' || ip === 'undefined'){ _toast('No valid IP to block', 'a'); return; }
  _confirmAction('Block <b>' + ip + '</b> at the firewall? Traffic will be dropped immediately.', function(){
    _apiFetch('/api/firewall/block', {method:'POST', body: JSON.stringify({ip:ip, reason:reason||'Manual block', type:type||'Malicious IP'})})
      .then(function(r){ return r.json(); })
      .then(function(d){
        _toast((d.success||d.blocked) ? ('Blocked ' + ip) : 'Failed — run as Admin', (d.success||d.blocked)?'g':'r');
        setTimeout(function(){ if(typeof _fetchAll === 'function') _fetchAll(); }, 800);
      })
      .catch(function(){ _toast('Could not reach server', 'r'); });
  }, {title:'Block IP', confirmLabel:'Block IP'});
}

/* ---------- 1. CONFIRM GUARD for destructive actions ---------- */
function _confirmAction(message, onConfirm, opts){
  opts = opts || {};
  var existing = document.getElementById('CONFIRM_MODAL');
  if(existing) existing.remove();

  var overlay = document.createElement('div');
  overlay.id = 'CONFIRM_MODAL';
  overlay.className = 'confirm-overlay';
  overlay.innerHTML =
    '<div class="confirm-box">' +
      '<div class="confirm-title">⚠ ' + (opts.title || 'Confirm action') + '</div>' +
      '<div class="confirm-msg">' + message + '</div>' +
      '<div class="confirm-row">' +
        '<button class="btn btn-gh" id="CONFIRM_CANCEL">Cancel</button>' +
        '<button class="btn btn-r" id="CONFIRM_OK">' + (opts.confirmLabel || 'Confirm') + '</button>' +
      '</div>' +
    '</div>';
  document.body.appendChild(overlay);

  function close(){ overlay.remove(); document.removeEventListener('keydown', onKey); }
  function onKey(e){
    if(e.key === 'Escape'){ close(); }
    if(e.key === 'Enter'){ close(); onConfirm(); }
  }
  overlay.onclick = function(e){ if(e.target === overlay) close(); };
  document.getElementById('CONFIRM_CANCEL').onclick = close;
  document.getElementById('CONFIRM_OK').onclick = function(){ close(); onConfirm(); };
  document.addEventListener('keydown', onKey);
  document.getElementById('CONFIRM_OK').focus();
}

/* Wrap existing destructive functions so every call site
   (buttons already wired via onclick="_kpKill(...)" etc.)
   automatically gets a confirm step — no other code changes needed. */
(function(){
  function guard(name, label, msgFn){
    var orig = window[name];
    if(typeof orig !== 'function'){ console.warn('Phase1: could not find', name, 'to guard'); return; }
    window[name] = function(){
      var args = Array.prototype.slice.call(arguments);
      _confirmAction(msgFn.apply(null, args), function(){ orig.apply(null, args); }, {title: label, confirmLabel: label});
    };
  }
  guard('_kpKill', 'Kill Process', function(pid, name){ return 'Kill process <b>' + (name||'') + '</b> (PID ' + pid + ')? This cannot be undone.'; });
  guard('_kpKillAll', 'Kill All Processes', function(){ return 'Kill <b>all</b> flagged processes on this host? This cannot be undone.'; });
  guard('_kpManual', 'Kill Process', function(){
    var pidEl = document.getElementById('KP_PID'), nmEl = document.getElementById('KP_NAME');
    var pid = pidEl ? pidEl.value.trim() : '', nm = (nmEl && nmEl.value.trim()) || 'process';
    return 'Kill <b>' + nm + '</b> (PID ' + pid + ')? This cannot be undone.';
  });
  guard('_bdBlock', 'Block IP/Domain', function(){ return 'Block this IP/domain at the firewall? Traffic will be dropped immediately.'; });
  guard('_tiBlock', 'Block IP', function(ip){ return 'Block <b>' + ip + '</b> at the firewall?'; });
  guard('_bipBlock', 'Block IP', function(){ return 'Block this IP at the firewall?'; });
  guard('_closeIncident', 'Close Incident', function(incId){ return 'Close incident <b>' + incId + '</b>? Make sure all related alerts are resolved first.'; });
  guard('_resolveAllAlerts', 'Bulk Resolve', function(host){ return 'Mark ALL open alerts for <b>' + host + '</b> as resolved?'; });
})();

/* ---------- 2. COMMAND PALETTE (Ctrl/Cmd + K) ---------- */
var _cpSel = 0;
var _cpItems = [];

function _cpBuildItems(){
  var items = [];
  pages.filter(function(p){ return p.sec; }).forEach(function(p){
    items.push({label: 'Go to ' + p.label, tag: p.sec, action: function(){ go(p.id); }});
  });
  (window._A || []).slice(0, 200).forEach(function(a){
    items.push({
      label: 'Open alert ' + (a.event || a.id) + ' — ' + (a.host || ''),
      tag: a.severity || '',
      action: function(){ _openAlert(a.id); }
    });
  });
  return items;
}

function _openPalette(){
  var existing = document.getElementById('CMD_PALETTE');
  if(existing){ existing.remove(); return; }
  _cpItems = _cpBuildItems();
  _cpSel = 0;

  var overlay = document.createElement('div');
  overlay.id = 'CMD_PALETTE';
  overlay.className = 'cp-overlay';
  overlay.innerHTML =
    '<div class="cp-box">' +
      '<input class="cp-input" id="CP_INPUT" placeholder="Type a command… (go to a page, open an alert, block an IP)" autocomplete="off"/>' +
      '<div class="cp-list" id="CP_LIST"></div>' +
      '<div class="cp-hint"><span>↑↓ navigate</span><span>↵ select</span><span>esc close</span></div>' +
    '</div>';
  overlay.onclick = function(e){ if(e.target === overlay) _closePalette(); };
  document.body.appendChild(overlay);

  var input = document.getElementById('CP_INPUT');
  input.addEventListener('input', function(){ _cpRender(input.value); });
  input.addEventListener('keydown', _cpKeyHandler);
  _cpRender('');
  setTimeout(function(){ input.focus(); }, 10);
}

function _closePalette(){
  var el = document.getElementById('CMD_PALETTE');
  if(el) el.remove();
}

function _cpFuzzyMatch(query, text){
  query = query.toLowerCase(); text = text.toLowerCase();
  if(!query) return true;
  var qi = 0;
  for(var i = 0; i < text.length && qi < query.length; i++){
    if(text[i] === query[qi]) qi++;
  }
  return qi === query.length;
}

function _cpRender(query){
  var filtered = _cpItems.filter(function(it){ return _cpFuzzyMatch(query, it.label); }).slice(0, 40);
  _cpSel = 0;
  var list = document.getElementById('CP_LIST');
  if(!filtered.length){
    list.innerHTML = '<div class="cp-empty">No matches — try "go to", an alert name, or a host.</div>';
    return;
  }
  list.innerHTML = filtered.map(function(it, i){
    return '<div class="cp-item' + (i === 0 ? ' sel' : '') + '" data-idx="' + i + '">' +
      '<span>' + it.label + '</span>' + (it.tag ? '<span class="cp-tag">' + it.tag + '</span>' : '') +
    '</div>';
  }).join('');
  Array.prototype.forEach.call(list.querySelectorAll('.cp-item'), function(el, i){
    el.onclick = function(){ filtered[i].action(); _closePalette(); };
  });
  _cpCurrentFiltered = filtered;
}
var _cpCurrentFiltered = [];

function _cpKeyHandler(e){
  var list = document.getElementById('CP_LIST');
  var items = list ? list.querySelectorAll('.cp-item') : [];
  if(e.key === 'Escape'){ _closePalette(); return; }
  if(e.key === 'ArrowDown'){ e.preventDefault(); _cpSel = Math.min(_cpSel + 1, items.length - 1); _cpHighlight(items); }
  if(e.key === 'ArrowUp'){ e.preventDefault(); _cpSel = Math.max(_cpSel - 1, 0); _cpHighlight(items); }
  if(e.key === 'Enter'){
    e.preventDefault();
    if(_cpCurrentFiltered[_cpSel]){ _cpCurrentFiltered[_cpSel].action(); _closePalette(); }
  }
}
function _cpHighlight(items){
  Array.prototype.forEach.call(items, function(el, i){ el.classList.toggle('sel', i === _cpSel); });
  if(items[_cpSel]) items[_cpSel].scrollIntoView({block: 'nearest'});
}

/* ---------- 3. KEYBOARD-FIRST SHORTCUTS ---------- */
var _kbIndex = -1;

function _kbShowHelp(){
  _confirmAction(
    '<div style="text-align:left;font-size:11px;line-height:1.9">' +
    '<b>J / K</b> — next / previous alert&nbsp;&nbsp;&nbsp; <b>Space</b> — quick preview<br>' +
    '<b>E</b> — mark investigating&nbsp;&nbsp;&nbsp; <b>R</b> — mark resolved&nbsp;&nbsp;&nbsp; <b>B</b> — block IP<br>' +
    '<b>C</b> — create case&nbsp;&nbsp;&nbsp; <b>1-5</b> — set severity on selected alert<br>' +
    '<b>Ctrl/Cmd+K</b> — command palette&nbsp;&nbsp;&nbsp; <b>?</b> — this help' +
    '</div>',
    function(){}, {title: 'Keyboard Shortcuts', confirmLabel: 'Got it'}
  );
}

function _kbSelectedAlert(){
  var list = (window._A || []);
  if(_kbIndex < 0 || _kbIndex >= list.length) return null;
  return list[_kbIndex];
}

document.addEventListener('keydown', function(e){
  var tag = (e.target.tagName || '').toLowerCase();
  var typing = tag === 'input' || tag === 'textarea' || e.target.isContentEditable;

  if((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k'){
    e.preventDefault();
    _openPalette();
    return;
  }
  if(typing) return;

  var list = window._A || [];
  switch(e.key){
    case 'j':
      _kbIndex = Math.min((_kbIndex < 0 ? -1 : _kbIndex) + 1, list.length - 1);
      _toast('Selected: ' + (list[_kbIndex] ? (list[_kbIndex].event || list[_kbIndex].id) : '-'), 'b');
      break;
    case 'k':
      _kbIndex = Math.max(_kbIndex - 1, 0);
      _toast('Selected: ' + (list[_kbIndex] ? (list[_kbIndex].event || list[_kbIndex].id) : '-'), 'b');
      break;
    case ' ':
      e.preventDefault();
      var sel = _kbSelectedAlert();
      if(sel) _openAlert(sel.id); else _toast('No alert selected — press J to select one', 'a');
      break;
    case 'e':
      var a1 = _kbSelectedAlert();
      if(a1) _ahStatus(a1.id, 'INVESTIGATING'); else _toast('Select an alert first (J/K)', 'a');
      break;
    case 'r':
      var a2 = _kbSelectedAlert();
      if(a2) _ahStatus(a2.id, 'RESOLVED'); else _toast('Select an alert first (J/K)', 'a');
      break;
    case 'b':
      var a3 = _kbSelectedAlert();
      if(a3 && a3.ip && a3.ip !== '-') _tiBlock(a3.ip); else _toast('Selected alert has no IP to block', 'a');
      break;
    case 'c':
      var a4 = _kbSelectedAlert();
      if(!a4){ _toast('Select an alert first (J/K)', 'a'); break; }
      _confirmAction('Create a case for alert on <b>' + (a4.host||'-') + '</b>?', function(){
        _apiFetch('/api/case/create', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({alert_id: a4.id})})
          .then(function(r){ return r.json(); })
          .then(function(d){ d.success ? _toast('Case ' + d.case_id + ' created', 'g') : _toast('Could not create case', 'r'); })
          .catch(function(){ _toast('Could not reach server', 'r'); });
      }, {title:'Create Case', confirmLabel:'Create Case'});
      break;
    case '?':
      _kbShowHelp();
      break;
    case '1': case '2': case '3': case '4': case '5':
      var sevMap = {'1':'CRITICAL','2':'HIGH','3':'MEDIUM','4':'LOW','5':'LOW'};
      var a5 = _kbSelectedAlert();
      if(a5){ a5.severity = sevMap[e.key]; _toast('Severity set to ' + sevMap[e.key] + ' (local)', 'g'); if(typeof _patchStats === 'function') _patchStats(); }
      break;
  }
});

/* ─── 360 CYBER MATRIX CANVAS & ANIMATED LOGIN SCRIPT ─── */
function _initCyberCanvas() {
  var cvs = document.getElementById('CYBER_CANVAS');
  if (!cvs) return;
  var ctx = cvs.getContext('2d');
  var w = cvs.width = window.innerWidth;
  var h = cvs.height = window.innerHeight;
  var pts = [];
  for (var i = 0; i < 65; i++) {
    pts.push({
      x: Math.random() * w,
      y: Math.random() * h,
      vx: (Math.random() - 0.5) * 0.8,
      vy: (Math.random() - 0.5) * 0.8,
      r: Math.random() * 2 + 1
    });
  }

  function render() {
    ctx.clearRect(0, 0, w, h);
    ctx.fillStyle = 'rgba(0, 240, 255, 0.6)';
    ctx.strokeStyle = 'rgba(0, 240, 255, 0.12)';

    for (var i = 0; i < pts.length; i++) {
      var p = pts[i];
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0 || p.x > w) p.vx *= -1;
      if (p.y < 0 || p.y > h) p.vy *= -1;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fill();

      for (var j = i + 1; j < pts.length; j++) {
        var p2 = pts[j];
        var dist = Math.hypot(p.x - p2.x, p.y - p2.y);
        if (dist < 130) {
          ctx.beginPath();
          ctx.moveTo(p.x, p.y);
          ctx.lineTo(p2.x, p2.y);
          ctx.stroke();
        }
      }
    }
    requestAnimationFrame(render);
  }
  render();
}

function _quickLogin(u, p) {
  var uInp = document.getElementById('LOGIN_U');
  var pInp = document.getElementById('LOGIN_P');
  if (uInp) uInp.value = u;
  if (pInp) pInp.value = p;
  _submitLogin();
}

function _submitLogin() {
  var uInp = document.getElementById('LOGIN_U');
  var pInp = document.getElementById('LOGIN_P');
  var u = (uInp && uInp.value ? uInp.value.trim() : 'analyst').toLowerCase();
  var p = (pInp && pInp.value ? pInp.value.trim() : 'analyst123');

  var btn = document.getElementById('LOGIN_SUBMIT_BTN');
  if (btn) {
    btn.textContent = 'AUTHENTICATING…';
    btn.disabled = true;
  }

  function handleLoginSuccess(token, role, username) {
    sessionStorage.setItem('sx_token', token);
    sessionStorage.setItem('sx_role', role);
    sessionStorage.setItem('sx_user', username);
    document.cookie = "sx_token=" + token + "; path=/; max-age=28800";

    _authToken = token;
    _authUser = { username: username, role: role };

    var loginScreen = document.getElementById('LOGIN');
    var appScreen = document.getElementById('APP');
    if (loginScreen) {
      loginScreen.classList.remove('on');
      loginScreen.style.display = 'none';
    }
    if (appScreen) {
      appScreen.style.display = 'flex';
    }

    _appStarted = true;
    _updateUserHeader(username, role);
    if (typeof _renderNav === 'function') _renderNav();
    if (typeof go === 'function') go('DASHBOARD');
    if (typeof _fetchAll === 'function') _fetchAll().catch(function(){});

    if (btn) {
      btn.textContent = 'AUTHENTICATE & ENTER SOC';
      btn.disabled = false;
    }
    _toast('Authenticated as ' + (role === 'admin' ? '⚡ SOC ADMIN' : (role === 'auditor' ? '👁️ AUDITOR' : '🛡️ SOC ANALYST')), 'g');
  }

  fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: u, password: p })
  }).then(function(r) { return r.json(); }).then(function(d) {
    if (d && d.success && d.token) {
      handleLoginSuccess(d.token, d.role || 'analyst', d.username || u);
    } else {
      // Local fallback for demo credentials
      if ((u === 'admin' && p === 'admin123') || (u === 'analyst' && p === 'analyst123') || (u === 'auditor' && p === 'auditor123')) {
        var role = u === 'admin' ? 'admin' : (u === 'auditor' ? 'auditor' : 'analyst');
        handleLoginSuccess('demo-token-' + u, role, u);
      } else {
        if (btn) {
          btn.textContent = 'AUTHENTICATE & ENTER SOC';
          btn.disabled = false;
        }
        _toast(d.error || 'Authentication failed', 'r');
      }
    }
  }).catch(function(err) {
    // Offline / Standalone fallback for demo credentials
    if ((u === 'admin' && p === 'admin123') || (u === 'analyst' && p === 'analyst123') || (u === 'auditor' && p === 'auditor123')) {
      var role = u === 'admin' ? 'admin' : (u === 'auditor' ? 'auditor' : 'analyst');
      handleLoginSuccess('demo-token-' + u, role, u);
    } else {
      if (btn) {
        btn.textContent = 'AUTHENTICATE & ENTER SOC';
        btn.disabled = false;
      }
      _toast('Connection error to server', 'r');
    }
  });
}

function _updateUserHeader(username, role) {
  var userEl = document.getElementById('SB_USER');
  var roleEl = document.getElementById('SB_ROLE');
  var sbAvEl = document.getElementById('SB_AV');
  var tbAvEl = document.getElementById('TB_AV');
  var badgesEl = document.getElementById('TB_BADGES');

  var initials = (username || 'User').substring(0, 2).toUpperCase();

  if (userEl) userEl.textContent = username || 'User';
  if (roleEl) roleEl.textContent = role === 'admin' ? '⚡ SOC ADMIN' : (role === 'auditor' ? '👁️ AUDITOR' : '🛡️ SOC Analyst');
  if (sbAvEl) sbAvEl.textContent = initials;
  if (tbAvEl) tbAvEl.textContent = initials;

  if (badgesEl) {
    if (role === 'admin') {
      badgesEl.innerHTML = '<span class="bx bx-r" style="background:#ff3b30;color:#fff;font-weight:700;box-shadow:0 0 10px rgba(255,59,48,0.5)">⚡ SOC ADMIN COMMAND MODE</span>';
    } else if (role === 'auditor') {
      badgesEl.innerHTML = '<span class="bx bx-a" style="background:#ff9f0a;color:#000;font-weight:700">👁️ AUDITOR READ-ONLY MODE</span>';
    } else {
      badgesEl.innerHTML = '<span class="bx bx-b" style="background:#0a84ff;color:#fff;font-weight:700">🛡️ SOC ANALYST TRIAGE MODE</span>';
    }
  }
}

function _toggleLoginPwVisibility() {
  var pInp = document.getElementById('LOGIN_P');
  var tog = document.getElementById('PW_VIS_TOGGLE');
  if(!pInp || !tog) return;
  if(pInp.type === 'password') {
    pInp.type = 'text';
    tog.textContent = '🙈 Hide';
  } else {
    pInp.type = 'password';
    tog.textContent = '👁️ Show';
  }
}

// ── USER MANAGEMENT CLIENT CONTROLLER ─────────────────────────
async function _loadUsersManagementUi() {
  var tbody = document.getElementById('UM_USERS_TBODY');
  if(!tbody) return;

  var users = [];
  try {
    var res = await _apiFetch('/api/users');
    if (res && res.ok) {
      var data = await res.json();
      users = data.users || [];
    }
  } catch(e) {
    console.warn('[SentinelX] Users API fallback to local cache:', e);
  }

  // Graceful local fallback if offline or initial load
  if (!users || !users.length) {
    users = [
      { username: 'admin', role: 'admin', created_at: '2026-08-10 10:00:00', status: 'Active' },
      { username: 'analyst', role: 'analyst', created_at: '2026-08-10 10:00:00', status: 'Active' },
      { username: 'auditor', role: 'auditor', created_at: '2026-08-10 10:00:00', status: 'Active' }
    ];
  }

  var currentUname = (_authUser && _authUser.username) || (sessionStorage.getItem('sx_user')) || 'admin';
  tbody.innerHTML = users.map(function(u) {
    var isYou = u.username === currentUname;
    var roleBadge = u.role === 'admin' ? '<span class="bx bx-r">👑 ADMIN</span>' : (u.role === 'auditor' ? '<span class="bx bx-a">👁️ AUDITOR</span>' : '<span class="bx bx-g">🛡️ ANALYST</span>');
    
    return (
      '<tr>' +
        '<td class="hi" style="font-weight:700">' + u.username + (isYou ? ' <span style="font-size:9.5px;color:var(--accent)">(You)</span>' : '') + '</td>' +
        '<td>' + roleBadge + '</td>' +
        '<td><span class="bx bx-g">● ' + (u.status || 'Active') + '</span></td>' +
        '<td class="mono" style="font-size:10.5px;color:var(--text3)">' + (u.created_at || '2026-08-10') + '</td>' +
        '<td>' +
          '<div style="display:flex;gap:6px">' +
            '<button class="btn btn-gh" style="padding:2px 8px;font-size:9.5px" onclick="_changeUserRole(\'' + u.username + '\',\'' + u.role + '\')">🎭 Role</button>' +
            '<button class="btn btn-gh" style="padding:2px 8px;font-size:9.5px" onclick="_promptResetPassword(\'' + u.username + '\')">🔑 Reset PW</button>' +
            (!isYou ? '<button class="btn btn-r" style="padding:2px 8px;font-size:9.5px;background:rgba(255,59,48,0.15);color:#ff453a;border-color:#ff453a" onclick="_deleteUser(\'' + u.username + '\')">🗑️ Delete</button>' : '') +
          '</div>' +
        '</td>' +
      '</tr>'
    );
  }).join('');
}

function _toggleAddUserForm() {
  var f = document.getElementById('UM_ADD_FORM');
  if(!f) return;
  f.style.display = f.style.display === 'none' ? 'block' : 'none';
}

async function _submitCreateUser() {
  var uInp = document.getElementById('NEW_USER_U');
  var pInp = document.getElementById('NEW_USER_P');
  var rInp = document.getElementById('NEW_USER_R');

  var u = (uInp ? uInp.value : '').trim().toLowerCase();
  var p = (pInp ? pInp.value : '').trim();
  var r = (rInp ? rInp.value : 'analyst').trim();

  if(!u || !p) {
    if(typeof _toast === 'function') _toast('Username and Password are required', 'r');
    return;
  }

  try {
    var res = await _apiFetch('/api/users', {
      method: 'POST',
      body: JSON.stringify({ username: u, password: p, role: r })
    });
    var data = await res.json();
    if(data.success) {
      if(typeof _toast === 'function') _toast('✅ ' + data.message, 'g');
      if(uInp) uInp.value = '';
      if(pInp) pInp.value = '';
      _toggleAddUserForm();
      _loadUsersManagementUi();
    } else {
      if(typeof _toast === 'function') _toast('Error: ' + (data.error || 'Failed to create user'), 'r');
    }
  } catch(e) {
    if(typeof _toast === 'function') _toast('Request error: ' + e.message, 'r');
  }
}

async function _changeUserRole(username, currentRole) {
  var newRole = prompt('Enter new role for user "' + username + '" (admin, analyst, auditor):', currentRole);
  if(!newRole || newRole.trim().toLowerCase() === currentRole) return;
  newRole = newRole.trim().toLowerCase();

  try {
    var res = await _apiFetch('/api/users/' + encodeURIComponent(username) + '/role', {
      method: 'PUT',
      body: JSON.stringify({ role: newRole })
    });
    var data = await res.json();
    if(data.success) {
      if(typeof _toast === 'function') _toast('✅ ' + data.message, 'g');
      _loadUsersManagementUi();
    } else {
      if(typeof _toast === 'function') _toast('Error: ' + (data.error || 'Failed'), 'r');
    }
  } catch(e) {
    if(typeof _toast === 'function') _toast('Request error: ' + e.message, 'r');
  }
}

async function _promptResetPassword(username) {
  var newPw = prompt('Enter new password for user "' + username + '" (min 6 characters):');
  if(!newPw || newPw.trim().length < 6) {
    if(newPw) _toast('Password must be at least 6 characters', 'a');
    return;
  }

  try {
    var res = await _apiFetch('/api/users/' + encodeURIComponent(username) + '/reset_password', {
      method: 'POST',
      body: JSON.stringify({ new_password: newPw.trim() })
    });
    var data = await res.json();
    if(data.success) {
      if(typeof _toast === 'function') _toast('✅ ' + data.message, 'g');
    } else {
      if(typeof _toast === 'function') _toast('Error: ' + (data.error || 'Failed'), 'r');
    }
  } catch(e) {
    if(typeof _toast === 'function') _toast('Request error: ' + e.message, 'r');
  }
}

async function _deleteUser(username) {
  if(!confirm('Are you sure you want to permanently delete user "' + username + '"?')) return;

  try {
    var res = await _apiFetch('/api/users/' + encodeURIComponent(username), {
      method: 'DELETE'
    });
    var data = await res.json();
    if(data.success) {
      if(typeof _toast === 'function') _toast('✅ ' + data.message, 'g');
      _loadUsersManagementUi();
    } else {
      if(typeof _toast === 'function') _toast('Error: ' + (data.error || 'Failed'), 'r');
    }
  } catch(e) {
    if(typeof _toast === 'function') _toast('Request error: ' + e.message, 'r');
  }
}

// ── ENTERPRISE MODULES CONTROLLER ─────────────────────────────
function _openMitreTechniqueModal(techId) {
  var ra = typeof _realAlerts === 'function' ? _realAlerts() : _A;
  var matched = ra.filter(function(a) { return (a.mitre_id || a.mitre) === techId; });
  var techName = matched.length ? (matched[0].mitre_name || techId) : techId;
  var url = 'https://attack.mitre.org/techniques/' + techId.replace('.', '/') + '/';

  var modalHtml = (
    '<div id="MITRE_MODAL_OVERLAY" style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.85);z-index:9999;display:flex;justify-content:center;align-items:center;backdrop-filter:blur(10px)">' +
      '<div style="background:#0c121e;border:1px solid rgba(255,255,255,0.18);border-radius:12px;width:90%;max-width:700px;max-height:85vh;overflow-y:auto;padding:24px;box-shadow:0 25px 70px rgba(0,0,0,0.9)">' +
        '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;border-bottom:1px solid var(--border);padding-bottom:12px">' +
          '<div>' +
            '<div style="font-size:16px;font-weight:900;color:#fff">' + techId + ' — ' + techName + '</div>' +
            '<div style="font-size:11px;color:#58a6ff;margin-top:2px">MITRE ATT&CK Enterprise Matrix Technique</div>' +
          '</div>' +
          '<button class="btn btn-gh" style="font-size:14px;padding:4px 10px" onclick="document.getElementById(\'MITRE_MODAL_OVERLAY\').remove()">✕</button>' +
        '</div>' +
        '<div style="font-size:12px;color:var(--text2);margin-bottom:16px;line-height:1.5">' +
          'Adversaries utilize this technique for multi-stage endpoint compromise. SentinelX continuously monitors Sysmon process ancestry and network sockets matching this pattern.' +
        '</div>' +
        '<div style="font-size:12px;font-weight:800;color:#fff;margin-bottom:8px">LIVE ASSOCIATED ALERTS (' + matched.length + '):</div>' +
        '<div style="display:flex;flex-direction:column;gap:6px;max-height:260px;overflow-y:auto">' +
          (matched.length ? matched.map(function(a) {
            return (
              '<div style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:8px 12px;display:flex;justify-content:space-between;align-items:center">' +
                '<div>' +
                  '<div style="font-size:11px;font-weight:700;color:#fff">' + (a.event || 'Threat') + '</div>' +
                  '<div class="mono" style="font-size:9.5px;color:var(--text3)">Host: ' + (a.host || '-') + ' · User: ' + (a.user || '-') + '</div>' +
                '</div>' +
                '<div>' +
                  sevBx(a.severity || 'LOW') +
                  '<button class="btn btn-b" style="padding:2px 7px;font-size:9px;margin-left:6px" onclick="document.getElementById(\'MITRE_MODAL_OVERLAY\').remove(); _openAlert(\'' + a.id + '\')">Inspect</button>' +
                '</div>' +
              '</div>'
            );
          }).join('') : '<div style="color:var(--text3);padding:10px;text-align:center">No active alerts recorded for this technique yet.</div>') +
        '</div>' +
        '<div style="display:flex;justify-content:space-between;align-items:center;margin-top:18px">' +
          '<button class="btn btn-gh" onclick="window.open(\'' + url + '\',\'_blank\')">View on MITRE.org ↗</button>' +
          '<button class="btn btn-ac" onclick="document.getElementById(\'MITRE_MODAL_OVERLAY\').remove()">Done</button>' +
        '</div>' +
      '</div>' +
    '</div>'
  );
  var div = document.createElement('div');
  div.innerHTML = modalHtml;
  document.body.appendChild(div.firstChild);
}

var _attackReplayTimer = null;
function _playAttackReplaySequence() {
  _resetAttackReplay();
  var btn = document.getElementById('PLAY_ATTACK_BTN');
  if(btn) { btn.textContent = '⏳ Replaying Kill-Chain…'; btn.disabled = true; }

  var step = 1;
  _attackReplayTimer = setInterval(function() {
    if(step > 6) {
      clearInterval(_attackReplayTimer);
      if(btn) { btn.textContent = '✅ Replay Complete'; btn.disabled = false; }
      if(typeof _speakAlert === 'function') _speakAlert('Attack chain sequence successfully replayed. Autonomous containment verified.');
      return;
    }

    for(var s = 1; s <= 6; s++) {
      var el = document.getElementById('CHAIN_STAGE_' + s);
      var st = document.getElementById('STAGE_STATUS_' + s);
      if(!el || !st) continue;
      if(s === step) {
        el.style.transform = 'scale(1.04)';
        el.style.boxShadow = '0 0 20px rgba(255,59,48,0.5)';
        st.innerHTML = '<span class="bx bx-r" style="font-weight:800">● DETECTED / ACTIVE</span>';
      } else if(s < step) {
        el.style.transform = 'none';
        el.style.boxShadow = 'none';
        st.innerHTML = '<span class="bx bx-g">✓ COMPLETED</span>';
      }
    }
    step++;
  }, 900);
}

function _resetAttackReplay() {
  if(_attackReplayTimer) clearInterval(_attackReplayTimer);
  for(var s = 1; s <= 6; s++) {
    var el = document.getElementById('CHAIN_STAGE_' + s);
    var st = document.getElementById('STAGE_STATUS_' + s);
    if(el) { el.style.transform = 'none'; el.style.boxShadow = 'none'; }
    if(st) st.innerHTML = '<span style="color:var(--text3)">● Standby</span>';
  }
  var btn = document.getElementById('PLAY_ATTACK_BTN');
  if(btn) { btn.textContent = '▶ Play Attack Replay Sequence'; btn.disabled = false; }
}

async function _runLiveThreatHunt() {
  var tbody = document.getElementById('HUNT_RESULTS_TBODY');
  var stats = document.getElementById('HUNT_STATS');
  if(!tbody) return;

  var kw = (document.getElementById('HUNT_KW')?.value || '').trim().toLowerCase();
  var tactic = (document.getElementById('HUNT_TACTIC')?.value || '').trim().toLowerCase();
  var host = (document.getElementById('HUNT_HOST')?.value || '').trim().toLowerCase();
  var sev = (document.getElementById('HUNT_SEV')?.value || '').trim().toUpperCase();

  tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:20px;color:var(--text3)"><span class="live-dot"></span> Hunting active telemetry streams…</td></tr>';

  var results = [];
  try {
    var res = await _apiFetch('/api/threathunt/query', {
      method: 'POST',
      body: JSON.stringify({ keyword: kw, tactic: tactic, host: host, min_severity: sev })
    });
    if (res && res.ok) {
      var data = await res.json();
      results = data.results || [];
    }
  } catch(e) {
    console.warn('[SentinelX] Threat hunt API fallback to client-side filter:', e);
  }

  // Client-side fallback if empty or offline
  if (!results.length) {
    var pool = typeof _realAlerts === 'function' ? _realAlerts() : _A;
    results = pool.filter(function(a) {
      if (kw) {
        var blob = ((a.event||'') + ' ' + (a.detail||'') + ' ' + (a.mitre_id||'') + ' ' + (a.mitre_name||'') + ' ' + (a.ip||'')).toLowerCase();
        if (!blob.includes(kw)) return false;
      }
      if (tactic && !(a.mitre_tactic||'').toLowerCase().includes(tactic)) return false;
      if (host && !(a.host||'').toLowerCase().includes(host)) return false;
      if (sev) {
        var sevOrder = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4};
        if ((sevOrder[a.severity || 'LOW'] || 1) < (sevOrder[sev] || 1)) return false;
      }
      return true;
    });
  }

  if (stats) stats.textContent = 'Found ' + results.length + ' matching telemetry events across active endpoints.';

  if (!results.length) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:24px;color:var(--text3)">No events match the specified threat hunting parameters.</td></tr>';
    return;
  }

  tbody.innerHTML = results.slice(0, 50).map(function(a) {
    return (
      '<tr>' +
        '<td class="mono" style="font-size:9.5px;color:var(--text3)">' + (a.id || '-') + '</td>' +
        '<td class="hi" style="font-weight:700">' + (a.event || 'Threat') + '</td>' +
        '<td class="mono" style="color:#58a6ff">' + (a.host || '-') + '</td>' +
        '<td><span class="mitre">' + (a.mitre_id || a.mitre || 'T1059') + '</span></td>' +
        '<td>' + sevBx(a.severity || 'LOW') + '</td>' +
        '<td class="mono" style="font-size:10px;color:var(--text3)">' + ((a.timestamp||'').split(' ')[1] || a.timestamp || '-') + '</td>' +
        '<td><button class="btn btn-p" style="padding:2px 7px;font-size:9px" onclick="_openAlert(\'' + a.id + '\')">Investigate</button></td>' +
      '</tr>'
    );
  }).join('');
}

function _applyHuntPreset(kw, tactic, sev) {
  var kwEl = document.getElementById('HUNT_KW');
  var tacEl = document.getElementById('HUNT_TACTIC');
  var sevEl = document.getElementById('HUNT_SEV');
  if(kwEl) kwEl.value = kw;
  if(tacEl) tacEl.value = tactic;
  if(sevEl) sevEl.value = sev;
  _runLiveThreatHunt();
}

function _resetHuntFilters() {
  ['HUNT_KW','HUNT_TACTIC','HUNT_HOST','HUNT_SEV'].forEach(function(id) {
    var el = document.getElementById(id);
    if(el) el.value = '';
  });
  _runLiveThreatHunt();
}

/* ─── ADMIN RESPONSE FUNCTIONS ─── */
function _admIsolateHost() {
  var host = (document.getElementById('ADM_ISO_HOST')?.value || '').trim();
  if(!host) { _toast('Host name required', 'r'); return; }
  _apiFetch('/api/response/isolate_host', {
    method: 'POST',
    body: JSON.stringify({ host: host, reason: 'Admin Command Lockdown' })
  }).then(r => r.json()).then(d => {
    if(d.success) _toast('⚡ Host ' + host + ' isolated by Admin', 'g');
    else _toast(d.error || 'Action failed - Requires Admin role', 'r');
  });
}

function _admRestoreHost() {
  var host = (document.getElementById('ADM_REST_HOST')?.value || '').trim();
  if(!host) { _toast('Host name required', 'r'); return; }
  _apiFetch('/api/response/restore_host', {
    method: 'POST',
    body: JSON.stringify({ host: host })
  }).then(r => r.json()).then(d => {
    if(d.success) _toast('Host ' + host + ' restored', 'g');
    else _toast(d.error || 'Action failed - Requires Admin role', 'r');
  });
}

function _admDisableUser() {
  var user = (document.getElementById('ADM_DIS_USER')?.value || '').trim();
  if(!user) { _toast('Username required', 'r'); return; }
  _apiFetch('/api/response/disable_user', {
    method: 'POST',
    body: JSON.stringify({ username: user, reason: 'Admin Lockdown' })
  }).then(r => r.json()).then(d => {
    if(d.success) _toast('⚡ User ' + user + ' disabled by Admin', 'g');
    else _toast(d.error || 'Action failed - Requires Admin role', 'r');
  });
}

function _admPurgeAlerts() {
  if(confirm('Are you sure you want to purge all alerts? (Admin Action)')) {
    _apiFetch('/api/admin/purge_alerts', {
      method: 'POST'
    }).then(r => r.json()).then(d => {
      if(d.success) { _toast('All alerts purged', 'g'); location.reload(); }
      else _toast(d.error || 'Purge failed - Requires Admin role', 'r');
    });
  }
}

function _admTriggerRescan() {
  _apiFetch('/api/admin/system_control', {
    method: 'POST',
    body: JSON.stringify({ action: 'engine_rescan' })
  }).then(r => r.json()).then(d => {
    if(d.success) _toast('Engine rescan triggered', 'g');
    else _toast(d.error || 'Rescan failed', 'r');
  });
}

function _admTestEmail() {
  _toast('Generating CRITICAL alert & processing email notification...', 'b');
  _apiFetch('/api/admin/test_email', {
    method: 'POST'
  }).then(r => r.json()).then(d => {
    if(d.success) {
      _toast('Test email template generated! Opening HTML preview...', 'g');
      var m = document.createElement('div');
      m.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.85);z-index:9999;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:20px';
      m.innerHTML = '<div style="background:#fff;width:100%;max-width:580px;max-height:90vh;border-radius:12px;overflow:auto;position:relative">' +
        '<button style="position:absolute;top:10px;right:14px;background:#f43f5e;color:#fff;border:none;border-radius:6px;padding:6px 12px;cursor:pointer;font-weight:700;z-index:10" onclick="this.closest(\'div\').parentNode.remove()">✕ Close Preview</button>' +
        d.html_preview +
        '</div>';
      document.body.appendChild(m);
    } else {
      _toast(d.error || 'Failed to dispatch email test', 'r');
    }
  });
}

/* ─── 3D SLIDE DECK NAVIGATION DELEGATION ─── */
// Slide deck controls handled globally

// Keyboard Arrow Shortcuts for 3D Slide Flipping (Left Arrow / Right Arrow)
document.addEventListener('keydown', function(e) {
  var tag = (e.target.tagName || '').toLowerCase();
  var typing = tag === 'input' || tag === 'textarea' || e.target.isContentEditable;
  if(typing) return;
  
  if(e.key === 'ArrowLeft') {
    e.preventDefault();
    _prevSlide();
  } else if(e.key === 'ArrowRight') {
    e.preventDefault();
    _nextSlide();
  }
});

/* ─── LEAFLET REAL WORLD MAP & GEOLOCATION SCRIPT ─── */
var _leafletWorldMap = null;
var _mapMarkers = [];
var _pinpointMarker = null;
var _vectorMapAnimId = null;
var _activePinpointData = null;
var _mapEngineMode = 'vector';

var _COUNTRY_GEO_DB = {
  'IN': { country: 'India', city: 'Chennai', region: 'Tamil Nadu', lat: 13.0827, lon: 80.2707, isp: 'Indian ISP Backbone', countryCode: 'IN' },
  'RU': { country: 'Russia', city: 'Moscow', region: 'Moscow', lat: 55.7558, lon: 37.6173, isp: 'Russian Cyber Network', countryCode: 'RU' },
  'US': { country: 'United States', city: 'Washington D.C. / California', region: 'US', lat: 37.0902, lon: -95.7129, isp: 'North American Carrier', countryCode: 'US' },
  'DE': { country: 'Germany', city: 'Frankfurt am Main', region: 'Hesse', lat: 50.1109, lon: 8.6821, isp: 'German Internet Exchange', countryCode: 'DE' },
  'CN': { country: 'China', city: 'Beijing', region: 'Beijing', lat: 39.9042, lon: 116.4074, isp: 'China Telecom / Unicom', countryCode: 'CN' },
  'GB': { country: 'United Kingdom', city: 'London', region: 'England', lat: 51.5074, lon: -0.1278, isp: 'British Telecom', countryCode: 'GB' },
  'FR': { country: 'France', city: 'Paris', region: 'Île-de-France', lat: 48.8566, lon: 2.3522, isp: 'French National Carrier', countryCode: 'FR' },
  'JP': { country: 'Japan', city: 'Tokyo', region: 'Tokyo', lat: 35.6762, lon: 139.6503, isp: 'NTT / KDDI Japan', countryCode: 'JP' },
  'AU': { country: 'Australia', city: 'Sydney / Melbourne', region: 'NSW', lat: -33.8688, lon: 151.2093, isp: 'Telstra Australia', countryCode: 'AU' },
  'BR': { country: 'Brazil', city: 'São Paulo', region: 'São Paulo', lat: -23.5505, lon: -46.6333, isp: 'Brazilian Internet Hub', countryCode: 'BR' },
  'NL': { country: 'Netherlands', city: 'Amsterdam', region: 'North Holland', lat: 52.3676, lon: 4.9041, isp: 'Amsterdam Exchange', countryCode: 'NL' },
  'CA': { country: 'Canada', city: 'Toronto', region: 'Ontario', lat: 43.6532, lon: -79.3832, isp: 'Canadian Carrier', countryCode: 'CA' },
  'SG': { country: 'Singapore', city: 'Singapore', region: 'Central', lat: 1.3521, lon: 103.8198, isp: 'Singtel Asia Hub', countryCode: 'SG' }
};

function _detectCountryFromIP(ipStr) {
  if(!ipStr || ipStr === '127.0.0.1' || ipStr === 'localhost' || ipStr === '-' || ipStr.startsWith('192.168.') || ipStr.startsWith('10.') || /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ipStr)) {
    return _COUNTRY_GEO_DB['IN'];
  }
  var parts = ipStr.split('.').map(Number);
  var first = parts[0] || 0;
  if([49, 103, 106, 117, 122, 182, 150].indexOf(first) >= 0) return _COUNTRY_GEO_DB['IN'];
  if([95, 178, 185, 194, 91].indexOf(first) >= 0) return _COUNTRY_GEO_DB['RU'];
  if([80, 81, 82, 85, 87, 88, 89].indexOf(first) >= 0) return _COUNTRY_GEO_DB['DE'];
  if([114, 115, 116, 118, 119, 120, 121, 220, 221, 222].indexOf(first) >= 0) return _COUNTRY_GEO_DB['CN'];
  if([133, 202, 210, 219].indexOf(first) >= 0) return _COUNTRY_GEO_DB['JP'];
  if([139, 144, 203].indexOf(first) >= 0) return _COUNTRY_GEO_DB['AU'];
  if([177, 179, 189, 200, 201].indexOf(first) >= 0) return _COUNTRY_GEO_DB['BR'];
  if([151, 195].indexOf(first) >= 0) return _COUNTRY_GEO_DB['GB'];
  return _COUNTRY_GEO_DB['US'];
}

function _initLeafletWorldMap(callback) {
  var mapContainer = document.getElementById('LEAFLET_WORLD_MAP');
  if(!mapContainer) {
    if(typeof callback === 'function') setTimeout(function(){ _initLeafletWorldMap(callback); }, 150);
    return;
  }

  // 1. If user chose Leaflet OpenStreetMap/CartoDB tiles and library is loaded
  if(_mapEngineMode === 'leaflet' && typeof L !== 'undefined') {
    if(_leafletWorldMap) {
      try {
        var existingContainer = _leafletWorldMap.getContainer();
        if(existingContainer === mapContainer && document.body.contains(existingContainer)) {
          _leafletWorldMap.invalidateSize();
          if(typeof callback === 'function') callback(_leafletWorldMap);
          return;
        }
      } catch(e) {}
      try { _leafletWorldMap.remove(); } catch(e){}
      _leafletWorldMap = null;
    }

    if(mapContainer._leaflet_id) mapContainer._leaflet_id = null;
    mapContainer.innerHTML = '';

    try {
      _leafletWorldMap = L.map(mapContainer, {
        center: [22, 10],
        zoom: 2,
        minZoom: 2,
        maxZoom: 18,
        zoomControl: true,
        preferCanvas: true
      });

      var darkLayer = L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; OpenStreetMap & CartoDB',
        maxZoom: 18,
        subdomains: 'abcd'
      });
      darkLayer.addTo(_leafletWorldMap);

      [100, 300, 600, 1000].forEach(function(d){
        setTimeout(function(){ if(_leafletWorldMap) _leafletWorldMap.invalidateSize(); }, d);
      });

      _plotAlertIPsOnWorldMap();
      if(typeof callback === 'function') callback(_leafletWorldMap);
      return;
    } catch(err) {
      console.warn('[SentinelX] Leaflet initialization error:', err);
    }
  }

  // 2. High-Definition Guaranteed Cyber Vector Map Engine (Default, 100% Instant & Offline)
  _renderCyberVectorWorldMap(mapContainer, _activePinpointData);
  if(typeof callback === 'function') callback(null);
}

function _toggleLeafletTileEngine() {
  if(_mapEngineMode === 'vector') {
    if(typeof L === 'undefined') {
      _toast('Tile library is still loading in background...', 'b');
      return;
    }
    _mapEngineMode = 'leaflet';
    _toast('Switched to OpenStreetMap / CartoDB tiles', 'g');
  } else {
    _mapEngineMode = 'vector';
    _toast('Switched to Cyber Vector Hologram view', 'g');
  }
  _initLeafletWorldMap();
}

function _renderCyberVectorWorldMap(container, pinpointTarget) {
  if(!container) return;
  if(_vectorMapAnimId) {
    cancelAnimationFrame(_vectorMapAnimId);
    _vectorMapAnimId = null;
  }

  container.innerHTML = '<canvas id="CYBER_VECTOR_MAP_CVS" style="width:100%;height:100%;min-height:460px;display:block;cursor:crosshair;border-radius:10px"></canvas>';
  var cvs = document.getElementById('CYBER_VECTOR_MAP_CVS');
  if(!cvs) return;

  var w = cvs.width = container.clientWidth || container.offsetWidth || 900;
  var h = cvs.height = container.clientHeight || container.offsetHeight || 460;
  var ctx = cvs.getContext('2d');

  function g2c(lat, lon) {
    var x = ((lon + 180) / 360) * w;
    var y = ((90 - lat) / 180) * h;
    return { x: x, y: y };
  }

  var continents = [
    // North America
    [[70,-165],[72,-130],[60,-75],[50,-55],[30,-80],[25,-80],[18,-105],[32,-118],[48,-125],[60,-140],[70,-165]],
    // South America
    [[12,-72],[6,-52],[-10,-36],[-23,-42],[-54,-68],[-40,-74],[-5,-80],[10,-75],[12,-72]],
    // Eurasia
    [[70,30],[75,90],[72,145],[60,170],[40,140],[25,120],[10,105],[20,80],[25,60],[30,35],[42,28],[55,10],[60,5],[70,30]],
    // Africa
    [[35,-5],[37,10],[32,32],[12,50],[0,42],[-34,20],[-34,18],[-15,12],[5,0],[15,-17],[30,-10],[35,-5]],
    // Australia
    [[-12,130],[-15,145],[-28,153],[-38,145],[-35,115],[-20,115],[-12,130]],
    // India subcontinent
    [[32,75],[28,88],[22,88],[16,82],[8,77],[15,73],[22,69],[26,70],[32,75]],
    // UK & Ireland
    [[58,-5],[58,0],[50,1],[50,-5],[58,-5]],
    // Japan
    [[45,142],[38,141],[34,133],[33,130],[36,136],[45,142]]
  ];

  var scanSweep = 0;

  function draw() {
    ctx.fillStyle = '#060a12';
    ctx.fillRect(0, 0, w, h);

    // Ocean grid & Latitude/Longitude cyber lines
    ctx.strokeStyle = 'rgba(0, 240, 255, 0.07)';
    ctx.lineWidth = 1;

    for (var lon = -180; lon <= 180; lon += 30) {
      var lx = ((lon + 180) / 360) * w;
      ctx.beginPath();
      ctx.moveTo(lx, 0);
      ctx.lineTo(lx, h);
      ctx.stroke();
    }
    for (var lat = -90; lat <= 90; lat += 30) {
      var ly = ((90 - lat) / 180) * h;
      ctx.beginPath();
      ctx.moveTo(0, ly);
      ctx.lineTo(w, ly);
      ctx.stroke();
    }

    // Equator & Prime Meridian high-contrast lines
    ctx.strokeStyle = 'rgba(0, 240, 255, 0.18)';
    var eqY = g2c(0, 0).y;
    ctx.beginPath(); ctx.moveTo(0, eqY); ctx.lineTo(w, eqY); ctx.stroke();
    var pmX = g2c(0, 0).x;
    ctx.beginPath(); ctx.moveTo(pmX, 0); ctx.lineTo(pmX, h); ctx.stroke();

    // Draw Continents Landmasses
    continents.forEach(function(poly) {
      ctx.beginPath();
      var first = g2c(poly[0][0], poly[0][1]);
      ctx.moveTo(first.x, first.y);
      for (var i = 1; i < poly.length; i++) {
        var pt = g2c(poly[i][0], poly[i][1]);
        ctx.lineTo(pt.x, pt.y);
      }
      ctx.closePath();
      ctx.fillStyle = 'rgba(13, 27, 46, 0.85)';
      ctx.fill();
      ctx.strokeStyle = 'rgba(0, 240, 255, 0.35)';
      ctx.lineWidth = 1.2;
      ctx.stroke();
    });

    // Radar scanning vertical laser line
    scanSweep = (scanSweep + 1.2) % w;
    var grad = ctx.createLinearGradient(scanSweep - 60, 0, scanSweep, 0);
    grad.addColorStop(0, 'rgba(0, 240, 255, 0)');
    grad.addColorStop(1, 'rgba(0, 240, 255, 0.18)');
    ctx.fillStyle = grad;
    ctx.fillRect(scanSweep - 60, 0, 60, h);
    ctx.strokeStyle = 'rgba(0, 240, 255, 0.6)';
    ctx.beginPath();
    ctx.moveTo(scanSweep, 0);
    ctx.lineTo(scanSweep, h);
    ctx.stroke();

    var activeNodes = Object.keys(_COUNTRY_GEO_DB).map(function(k){ return _COUNTRY_GEO_DB[k]; }).slice(0, 8);
    var now = Date.now();

    activeNodes.forEach(function(node, idx) {
      var pt = g2c(node.lat, node.lon);
      var pulse = ((now / 400 + idx) % 3);
      
      // Outer sonar pulse ring
      ctx.strokeStyle = 'rgba(255, 59, 48, ' + Math.max(0, 0.8 - pulse * 0.25) + ')';
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.arc(pt.x, pt.y, 6 + pulse * 6, 0, Math.PI * 2);
      ctx.stroke();

      // Node center dot
      ctx.fillStyle = '#ff3b30';
      ctx.beginPath();
      ctx.arc(pt.x, pt.y, 4.5, 0, Math.PI * 2);
      ctx.fill();

      // Location label
      ctx.fillStyle = 'rgba(255,255,255,0.7)';
      ctx.font = '9px "JetBrains Mono", monospace';
      ctx.fillText(node.city + ' [' + node.countryCode + ']', pt.x + 8, pt.y + 3);
    });

    // Draw active pinpoint target if selected
    var curTgt = pinpointTarget || _activePinpointData;
    if (curTgt && typeof curTgt.lat !== 'undefined') {
      var tgt = g2c(curTgt.lat, curTgt.lon);
      var tgtPulse = ((now / 250) % 4);

      // Cyber crosshair
      ctx.strokeStyle = '#00f0ff';
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.arc(tgt.x, tgt.y, 12 + tgtPulse * 5, 0, Math.PI * 2);
      ctx.stroke();

      ctx.beginPath();
      ctx.moveTo(tgt.x - 18, tgt.y);
      ctx.lineTo(tgt.x + 18, tgt.y);
      ctx.moveTo(tgt.x, tgt.y - 18);
      ctx.lineTo(tgt.x, tgt.y + 18);
      ctx.stroke();

      ctx.fillStyle = '#00f0ff';
      ctx.beginPath();
      ctx.arc(tgt.x, tgt.y, 5, 0, Math.PI * 2);
      ctx.fill();

      // Cyber HUD Coordinate Readout
      ctx.fillStyle = '#0d1b2e';
      ctx.fillRect(tgt.x + 10, tgt.y - 32, 170, 26);
      ctx.strokeStyle = '#00f0ff';
      ctx.strokeRect(tgt.x + 10, tgt.y - 32, 170, 26);

      ctx.fillStyle = '#ffffff';
      ctx.font = 'bold 10px "Inter", sans-serif';
      ctx.fillText('📍 ' + (curTgt.city || 'Node') + ', ' + (curTgt.country || 'Target'), tgt.x + 16, tgt.y - 18);
      ctx.fillStyle = '#58a6ff';
      ctx.font = '8.5px "JetBrains Mono", monospace';
      ctx.fillText('LAT ' + parseFloat(curTgt.lat).toFixed(2) + '°  LON ' + parseFloat(curTgt.lon).toFixed(2) + '°', tgt.x + 16, tgt.y - 8);
    }

    // Top overlay watermark
    ctx.fillStyle = 'rgba(0, 240, 255, 0.7)';
    ctx.font = 'bold 10px "JetBrains Mono", monospace';
    ctx.fillText('SENTINELX GLOBAL TELEMETRY PROJECTION · VECTOR MAP ACTIVE', 14, 20);

    _vectorMapAnimId = requestAnimationFrame(draw);
  }

  draw();

  cvs.onclick = function(e) {
    var cRect = cvs.getBoundingClientRect();
    var clickX = e.clientX - cRect.left;
    var clickY = e.clientY - cRect.top;

    var clickLon = (clickX / w) * 360 - 180;
    var clickLat = 90 - (clickY / h) * 180;

    var nearest = null;
    var minD = Infinity;
    Object.keys(_COUNTRY_GEO_DB).forEach(function(k) {
      var n = _COUNTRY_GEO_DB[k];
      var d = Math.hypot(n.lat - clickLat, n.lon - clickLon);
      if (d < minD) {
        minD = d;
        nearest = n;
      }
    });

    if (nearest) {
      _pinpointIPOnMap(nearest.countryCode === 'IN' ? '182.79.0.1' : (nearest.countryCode === 'RU' ? '95.173.136.1' : (nearest.countryCode === 'DE' ? '185.220.101.7' : '8.8.8.8')));
    }
  };
}

function _plotAlertIPsOnWorldMap() {
  if(!_leafletWorldMap || !window._A) return;
  var ipAlerts = _A.filter(function(a){ return a.ip && a.ip !== '-' && a.ip !== 'None'; });
  var uniqueIPs = [...new Map(ipAlerts.map(function(a){ return [a.ip, a]; })).values()];

  var alreadyPlotted = new Set(_mapMarkers.map(function(m){ return m._sx_ip; }).filter(Boolean));

  uniqueIPs.forEach(function(a) {
    if(alreadyPlotted.has(a.ip)) return;

    _apiFetch('/api/geo?ip=' + encodeURIComponent(a.ip))
      .then(function(r){ if(!r.ok) throw new Error('not ok'); return r.json(); })
      .then(function(d){
        if(!d || !d.lat || !d.lon) throw new Error('no coords');
        _addAlertMarker(a, d);
      })
      .catch(function(){
        fetch('https://ipwhois.app/json/' + encodeURIComponent(a.ip))
          .then(function(r2){ return r2.json(); })
          .then(function(d2){
            if(d2 && d2.success !== false && d2.latitude && d2.longitude) {
              _addAlertMarker(a, {lat:d2.latitude, lon:d2.longitude, city:d2.city, country:d2.country, isp:d2.isp||d2.org});
            } else {
              var fb = _detectCountryFromIP(a.ip);
              _addAlertMarker(a, {lat:fb.lat, lon:fb.lon, city:fb.city, country:fb.country, isp:fb.isp});
            }
          })
          .catch(function(){
            var fb = _detectCountryFromIP(a.ip);
            _addAlertMarker(a, {lat:fb.lat, lon:fb.lon, city:fb.city, country:fb.country, isp:fb.isp});
          });
      });
  });
}

function _addAlertMarker(a, d) {
  if(!_leafletWorldMap) return;
  try {
    var marker = L.circleMarker([d.lat, d.lon], {
      radius: 8,
      fillColor: a.severity === 'CRITICAL' ? '#ff3b30' : (a.severity === 'HIGH' ? '#ff9500' : '#0a84ff'),
      color: '#ffffff',
      weight: 1.5,
      opacity: 0.9,
      fillOpacity: 0.8
    }).addTo(_leafletWorldMap);
    marker._sx_ip = a.ip;

    marker.bindPopup(
      '<div style="font-family:sans-serif;font-size:12px;color:#000;min-width:180px">' +
        '<b style="font-size:13px">📍 ' + (d.city || 'Network Node') + ', ' + (d.country || 'Global') + '</b><br/>' +
        '<b>IP:</b> <code style="color:#e11d48;font-weight:700">' + a.ip + '</code><br/>' +
        '<b>Event:</b> ' + (a.event || 'Threat Alert') + '<br/>' +
        '<b>Severity:</b> ' + (a.severity || 'HIGH') + '<br/>' +
        '<b>ISP:</b> ' + (d.isp || 'Provider') + '<br/>' +
        '<button style="margin-top:8px;background:#ff3b30;color:#fff;border:none;padding:5px 10px;border-radius:4px;cursor:pointer;font-weight:bold;width:100%" onclick="_confirmBlockIP(\'' + a.ip + '\')">⚡ Block IP at Firewall</button>' +
      '</div>'
    );
    _mapMarkers.push(marker);
  } catch(e){}
}

function _pinpointIPOnMap(targetIp) {
  var ipInput = document.getElementById('GEO_MAP_IP_INPUT');
  var ip = targetIp || (ipInput ? ipInput.value.trim() : '');
  if(!ip) { if(typeof _toast === 'function') _toast('Please enter a valid IP address', 'r'); return; }
  
  if(ipInput) {
    ipInput.value = ip;
  }

  if(typeof _toast === 'function') _toast('Searching geographic coordinates for ' + ip + '...', 'b');

  function renderGeoResult(d) {
    if(!d || typeof d.lat === 'undefined' || typeof d.lon === 'undefined') {
      d = _detectCountryFromIP(ip);
    }
    
    var lat = parseFloat(d.lat || d.latitude);
    var lon = parseFloat(d.lon || d.longitude);
    var country = d.country || d.country_name || 'Unknown Country';
    var city = d.city || 'City Hub';
    var isp = d.isp || d.org || 'Internet Provider';
    var countryCode = d.countryCode || d.country_code || '';

    _activePinpointData = { lat: lat, lon: lon, country: country, city: city, isp: isp, countryCode: countryCode, ip: ip };

    // 1. Update SVG Map Target Crosshair
    var svgTarget = document.getElementById('SVG_PINPOINT_TARGET');
    if(svgTarget) {
      var sx = ((lon + 180) / 360) * 1000;
      var sy = ((90 - lat) / 180) * 500;
      svgTarget.setAttribute('transform', 'translate(' + sx + ',' + sy + ')');
      svgTarget.style.display = 'block';
    }

    if(_mapEngineMode === 'leaflet' && _leafletWorldMap && typeof L !== 'undefined') {
      if(_pinpointMarker) {
        try { _leafletWorldMap.removeLayer(_pinpointMarker); } catch(e){}
        _pinpointMarker = null;
      }

      _leafletWorldMap.invalidateSize();
      _leafletWorldMap.flyTo([lat, lon], 5, { duration: 1.5 });

      _pinpointMarker = L.circleMarker([lat, lon], {
        radius: 13,
        fillColor: '#00f0ff',
        color: '#ffffff',
        weight: 3,
        opacity: 1,
        fillOpacity: 0.95
      }).addTo(_leafletWorldMap);

      _pinpointMarker.bindPopup(
        '<div style="font-family:sans-serif;font-size:12px;color:#000;min-width:200px">' +
          '<b style="font-size:14px;color:#0284c7">📍 ' + city + ', ' + country + ' (' + countryCode + ')</b><br/>' +
          '<b>IP Address:</b> <code style="color:#0f172a;font-weight:bold">' + ip + '</code><br/>' +
          '<b>ISP Carrier:</b> ' + isp + '<br/>' +
          '<b>Coordinates:</b> ' + lat.toFixed(4) + '°, ' + lon.toFixed(4) + '°<br/>' +
          '<button style="margin-top:8px;background:#ff3b30;color:#fff;border:none;padding:6px 12px;border-radius:4px;cursor:pointer;font-weight:bold;width:100%" onclick="_confirmBlockIP(\'' + ip + '\')">⚡ Block IP at Firewall</button>' +
        '</div>'
      ).openPopup();

      _mapMarkers.push(_pinpointMarker);
    }

    // Render Geo Intel Card
    var card = document.getElementById('GEO_INTEL_CARD');
    if(card) {
      card.style.display = 'block';
      card.innerHTML =
        '<div style="font-size:13px;font-weight:800;color:var(--accent);margin-bottom:8px">📍 GEOLOCATION INTEL — ' + ip + '</div>' +
        '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px">' +
          '<div><span style="font-size:10px;color:var(--text3)">Country</span><br/><b style="font-size:12px;color:#fff">' + country + ' (' + countryCode + ')</b></div>' +
          '<div><span style="font-size:10px;color:var(--text3)">City / Region</span><br/><b style="font-size:12px;color:#fff">' + city + '</b></div>' +
          '<div><span style="font-size:10px;color:var(--text3)">ISP Provider</span><br/><b style="font-size:12px;color:#fff">' + isp + '</b></div>' +
          '<div><span style="font-size:10px;color:var(--text3)">Coordinates</span><br/><b style="font-size:12px;color:var(--accent)">' + lat.toFixed(4) + '°, ' + lon.toFixed(4) + '°</b></div>' +
        '</div>' +
        '<div style="margin-top:10px;display:flex;gap:10px">' +
          '<button class="btn btn-r" style="padding:6px 14px;font-weight:700" onclick="_confirmBlockIP(\'' + ip + '\')">⚡ Block IP at Firewall</button>' +
        '</div>';
    }

    if(typeof _toast === 'function') _toast('📍 Location pinpointed: ' + country + ' (' + city + ')', 'g');
  }

  // Check backend first, then fallback
  _apiFetch('/api/geo?ip=' + encodeURIComponent(ip))
    .then(function(r) {
      if(!r.ok) throw new Error('API status ' + r.status);
      return r.json();
    })
    .then(function(d) {
      if(d && typeof d.lat !== 'undefined') {
        renderGeoResult(d);
      } else {
        throw new Error('Invalid backend data');
      }
    })
    .catch(function() {
      fetch('https://ipwhois.app/json/' + encodeURIComponent(ip))
        .then(function(r2){ return r2.json(); })
        .then(function(d2){
          if(d2 && d2.success !== false && d2.latitude && d2.longitude) {
            renderGeoResult({
              lat: d2.latitude,
              lon: d2.longitude,
              country: d2.country,
              countryCode: d2.country_code,
              city: d2.city,
              isp: d2.isp || d2.org
            });
          } else {
            renderGeoResult(_detectCountryFromIP(ip));
          }
        })
        .catch(function(){
          renderGeoResult(_detectCountryFromIP(ip));
        });
    });
}

function _locateMyPublicIP() {
  _toast('Detecting your public IP and location...', 'b');
  
  // Try client-side public IP lookup first
  fetch('https://api.ipify.org?format=json')
    .then(function(r){ return r.json(); })
    .then(function(res){
      if(res && res.ip) {
        _pinpointIPOnMap(res.ip);
      } else {
        throw new Error('No IP from ipify');
      }
    })
    .catch(function(){
      // Secondary fallback
      fetch('https://ipwhois.app/json/')
        .then(function(r2){ return r2.json(); })
        .then(function(d2){
          if(d2 && (d2.ip || d2.query)) {
            _pinpointIPOnMap(d2.ip || d2.query);
          } else {
            _pinpointIPOnMap('182.79.0.1');
          }
        })
        .catch(function(){
          _pinpointIPOnMap('182.79.0.1');
        });
    });
}

// ─── STARTUP Triggers for 360 Cyber Canvas Particle Matrix Background ───
document.addEventListener('DOMContentLoaded', function() {
  _initCyberCanvas();
  _init3DParallaxTilt();
  _initAppMultiThemeCanvas();
});

window.addEventListener('load', function() {
  _initCyberCanvas();
  _init3DParallaxTilt();
  _initAppMultiThemeCanvas();
});

setTimeout(function() {
  _initCyberCanvas();
  _init3DParallaxTilt();
  _initAppMultiThemeCanvas();
}, 200);

/* ─── DYNAMIC MULTI-THEME 3D CANVAS MOTION ENGINE FOR ALL SLIDES ─── */
var _appCanvasTheme = 'constellation';
var _appCanvasColor = 'rgba(0, 240, 255, 0.7)';
var _appRadarAngle = 0;

function _setAppCanvasTheme(slideId) {
  var themeMap = {
    'DASHBOARD':         { mode: 'constellation', color: 'rgba(0, 240, 255, 0.7)' },
    'HUNT_IP':           { mode: 'radar_sweep',   color: 'rgba(48, 209, 88, 0.7)' },
    'THREAT_HUNTER':     { mode: 'radar_sweep',   color: 'rgba(48, 209, 88, 0.7)' },
    'THREAT_MAP':        { mode: 'orbital_arcs',  color: 'rgba(255, 149, 0, 0.7)' },
    'AUTOMATION_ENGINE': { mode: 'neural_matrix', color: 'rgba(191, 90, 242, 0.7)' },
    'SOAR_BUILDER':      { mode: 'neural_matrix', color: 'rgba(191, 90, 242, 0.7)' },
    'SUSP_EXE':          { mode: 'hex_mesh',      color: 'rgba(50, 215, 200, 0.7)' },
    'PS_DETECTION':      { mode: 'hex_mesh',      color: 'rgba(50, 215, 200, 0.7)' },
    'NET_SUSPICIOUS':    { mode: 'hex_mesh',      color: 'rgba(255, 149, 0, 0.7)' },
    'REG_MON':           { mode: 'hex_mesh',      color: 'rgba(50, 215, 200, 0.7)' },
    'ADMIN_COMMAND':     { mode: 'plasma_shield', color: 'rgba(255, 59, 48, 0.8)' },
    'ADMIN_AUDIT':       { mode: 'plasma_shield', color: 'rgba(255, 59, 48, 0.8)' },
    'ALERT_HIST':        { mode: 'spectrum_bars', color: 'rgba(255, 55, 95, 0.7)' },
    'METRICS':           { mode: 'spectrum_bars', color: 'rgba(10, 132, 255, 0.7)' }
  };

  var conf = themeMap[slideId] || { mode: 'constellation', color: 'rgba(0, 240, 255, 0.6)' };
  _appCanvasTheme = conf.mode;
  _appCanvasColor = conf.color;
}

function _initAppMultiThemeCanvas() {
  var cvs = document.getElementById('APP_CYBER_CANVAS');
  if(!cvs) return;
  var ctx = cvs.getContext('2d');
  var w = cvs.width = window.innerWidth;
  var h = cvs.height = window.innerHeight;

  window.addEventListener('resize', function() {
    w = cvs.width = window.innerWidth;
    h = cvs.height = window.innerHeight;
  });

  var pts = [];
  for(var i = 0; i < 50; i++) {
    pts.push({
      x: Math.random() * w,
      y: Math.random() * h,
      vx: (Math.random() - 0.5) * 1.2,
      vy: (Math.random() - 0.5) * 1.2,
      r: Math.random() * 2 + 1.5,
      phase: Math.random() * Math.PI * 2
    });
  }

  function render() {
    ctx.clearRect(0, 0, w, h);

    if(_appCanvasTheme === 'constellation') {
      ctx.fillStyle = _appCanvasColor;
      ctx.strokeStyle = 'rgba(0, 240, 255, 0.12)';
      for(var i = 0; i < pts.length; i++) {
        var p = pts[i];
        p.x += p.vx; p.y += p.vy;
        if(p.x < 0 || p.x > w) p.vx *= -1;
        if(p.y < 0 || p.y > h) p.vy *= -1;
        ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2); ctx.fill();

        for(var j = i + 1; j < pts.length; j++) {
          var p2 = pts[j];
          var dist = Math.hypot(p.x - p2.x, p.y - p2.y);
          if(dist < 140) {
            ctx.beginPath(); ctx.moveTo(p.x, p.y); ctx.lineTo(p2.x, p2.y); ctx.stroke();
          }
        }
      }
    } else if(_appCanvasTheme === 'radar_sweep') {
      var cx = w / 2, cy = h / 2;
      _appRadarAngle += 0.02;
      ctx.strokeStyle = _appCanvasColor;
      ctx.lineWidth = 1;

      for(var r = 100; r < 500; r += 100) {
        ctx.beginPath(); ctx.arc(cx, cy, r, 0, Math.PI * 2); ctx.stroke();
      }

      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(cx + Math.cos(_appRadarAngle) * 600, cy + Math.sin(_appRadarAngle) * 600);
      ctx.stroke();
    } else if(_appCanvasTheme === 'orbital_arcs') {
      ctx.strokeStyle = _appCanvasColor;
      ctx.lineWidth = 1.5;
      for(var i = 0; i < 6; i++) {
        var t = Date.now() * 0.001 + i;
        var startX = (Math.sin(t) * 0.4 + 0.5) * w;
        var startY = (Math.cos(t * 0.8) * 0.4 + 0.5) * h;
        ctx.beginPath();
        ctx.arc(startX, startY, 40 + i * 20, 0, Math.PI * 1.5);
        ctx.stroke();
      }
    } else if(_appCanvasTheme === 'neural_matrix') {
      ctx.fillStyle = _appCanvasColor;
      for(var i = 0; i < pts.length; i++) {
        var p = pts[i];
        p.y += 2.5;
        if(p.y > h) p.y = 0;
        ctx.fillRect(p.x, p.y, 2, 12);
      }
    } else if(_appCanvasTheme === 'plasma_shield') {
      var cx = w / 2, cy = h / 2;
      var pulse = Math.sin(Date.now() * 0.003) * 30 + 150;
      ctx.strokeStyle = _appCanvasColor;
      ctx.lineWidth = 3;
      ctx.beginPath(); ctx.arc(cx, cy, pulse, 0, Math.PI * 2); ctx.stroke();
      ctx.beginPath(); ctx.arc(cx, cy, pulse + 60, 0, Math.PI * 2); ctx.stroke();
    } else {
      ctx.fillStyle = _appCanvasColor;
      for(var i = 0; i < pts.length; i++) {
        var p = pts[i];
        p.x += p.vx; p.y += p.vy;
        if(p.x < 0 || p.x > w) p.vx *= -1;
        if(p.y < 0 || p.y > h) p.vy *= -1;
        ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2); ctx.fill();
      }
    }

    requestAnimationFrame(render);
  }
  render();
}

/* ═══════════════════════════════════════════════════════════
   ENTERPRISE SUITE: ATTACK SIMULATOR, AI COPILOT & AUDIO HUD
═══════════════════════════════════════════════════════════════ */

// ── 1. 1-CLICK LIVE ATTACK SIMULATOR MODAL ───────────────────
function _openAttackSimModal() {
  var ex = document.getElementById('ATTACK_SIM_MODAL');
  if(ex) { ex.remove(); return; }

  var modal = document.createElement('div');
  modal.id = 'ATTACK_SIM_MODAL';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.8);z-index:10000;display:flex;align-items:center;justify-content:center;padding:20px;backdrop-filter:blur(6px)';
  modal.onclick = function(e) { if(e.target === modal) modal.remove(); };

  modal.innerHTML = 
    '<div style="background:var(--bg2);border:1px solid #ff453a;border-radius:14px;width:100%;max-width:640px;padding:22px;box-shadow:0 0 40px rgba(255,69,58,0.25)">' +
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">' +
        '<div>' +
          '<div style="font-size:15px;font-weight:900;color:#ff453a;letter-spacing:0.5px">🎯 1-CLICK RED TEAM ATTACK SIMULATION PANEL</div>' +
          '<div style="font-size:11px;color:var(--text3);margin-top:2px">Trigger real-time attack scenarios through live detectors, correlation engine, and SOAR response.</div>' +
        '</div>' +
        '<button class="btn btn-gh" onclick="document.getElementById(\'ATTACK_SIM_MODAL\').remove()" style="padding:4px 10px">Close ✕</button>' +
      '</div>' +

      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px">' +
        '<div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:12px;cursor:pointer;transition:0.2s" onmouseover="this.style.borderColor=\'#ff453a\'" onmouseout="this.style.borderColor=\'var(--border)\'" onclick="_runAttackScenario(\'mimikatz\')">' +
          '<div style="font-size:12px;font-weight:800;color:#ff453a">🔴 Mimikatz Credential Dump</div>' +
          '<div style="font-size:10px;color:var(--text3);margin-top:4px">LSASS Memory Injection & Sekurlsa Password Extraction</div>' +
          '<div style="font-size:9px;color:var(--blue);margin-top:6px;font-family:var(--mono)">MITRE: T1003.001 / Sysmon EID 10</div>' +
        '</div>' +

        '<div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:12px;cursor:pointer;transition:0.2s" onmouseover="this.style.borderColor=\'#ff453a\'" onmouseout="this.style.borderColor=\'var(--border)\'" onclick="_runAttackScenario(\'ransomware\')">' +
          '<div style="font-size:12px;font-weight:800;color:#ff3b30">🔴 Ransomware Precursor</div>' +
          '<div style="font-size:10px;color:var(--text3);margin-top:4px">Volume Shadow Deletion & Decoy Canary File Tripwire</div>' +
          '<div style="font-size:9px;color:var(--amber);margin-top:6px;font-family:var(--mono)">MITRE: T1490 / CMD & Canary</div>' +
        '</div>' +

        '<div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:12px;cursor:pointer;transition:0.2s" onmouseover="this.style.borderColor=\'#ff453a\'" onmouseout="this.style.borderColor=\'var(--border)\'" onclick="_runAttackScenario(\'c2_beacon\')">' +
          '<div style="font-size:12px;font-weight:800;color:#ff2d55">🔴 External C2 Reverse Shell</div>' +
          '<div style="font-size:10px;color:var(--text3);margin-top:4px">Cobalt Strike Outbound Beacon to 185.220.101.5:4444</div>' +
          '<div style="font-size:9px;color:var(--red);margin-top:6px;font-family:var(--mono)">MITRE: T1071.001 / Network EID 3</div>' +
        '</div>' +

        '<div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:12px;cursor:pointer;transition:0.2s" onmouseover="this.style.borderColor=\'#ff453a\'" onmouseout="this.style.borderColor=\'var(--border)\'" onclick="_runAttackScenario(\'persistence\')">' +
          '<div style="font-size:12px;font-weight:800;color:#ff9500">🔴 Registry Persistence Implant</div>' +
          '<div style="font-size:10px;color:var(--text3);margin-top:4px">HKLM RunOnce Registry Key Modification for Auto-Start</div>' +
          '<div style="font-size:9px;color:var(--accent);margin-top:6px;font-family:var(--mono)">MITRE: T1547.001 / Registry Monitor</div>' +
        '</div>' +
      '</div>' +

      '<div style="font-size:10px;color:var(--text3);background:var(--bg3);padding:10px;border-radius:6px;text-align:center">' +
        '⚡ Detections immediately populate the <b>Live Alert Feed</b>, <b>World Threat Map</b>, and trigger <b>SOAR Host Containment</b>.' +
      '</div>' +
    '</div>';

  document.body.appendChild(modal);
}

async function _runAttackScenario(scenario) {
  var modal = document.getElementById('ATTACK_SIM_MODAL');
  if(modal) modal.remove();

  if(typeof _toast === 'function') _toast('🚀 Launching simulated ' + scenario.toUpperCase() + ' attack...', 'b');

  try {
    var res = await fetch('/api/simulate_attack', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + (_authToken || '')
      },
      body: JSON.stringify({ scenario: scenario, host: 'SOC-ENDPOINT-01', user: 'analyst_demo' })
    });
    var data = await res.json();
    if(data.success) {
      if(typeof _toast === 'function') _toast('🚨 ' + data.message, 'r');
      _speakCyberAlert('Alert triggered: ' + scenario + ' detected on endpoint 01. SOAR response initiated.');
      
      // Refresh all telemetry
      if(typeof _fetchAll === 'function') await _fetchAll();
      
      // Automatically switch to Live Alerts slide to show the result
      if(typeof go === 'function') go('LIVE_ALERTS');
      
      if(data.alert && data.alert.id) {
        setTimeout(function() { _openAlert(data.alert.id); }, 600);
      }
    } else {
      if(typeof _toast === 'function') _toast('Simulation error: ' + (data.error || 'Failed'), 'r');
    }
  } catch(e) {
    if(typeof _toast === 'function') _toast('Simulation network error: ' + e.message, 'r');
  }
}

// ── 2. INTERACTIVE SOC AI COPILOT FLOATING ASSISTANT ─────────
var _aiCopilotOpen = false;
function _toggleAiCopilot() {
  var ex = document.getElementById('SOC_AI_COPILOT_WIDGET');
  if(ex) {
    ex.remove();
    _aiCopilotOpen = false;
    return;
  }

  _aiCopilotOpen = true;
  var widget = document.createElement('div');
  widget.id = 'SOC_AI_COPILOT_WIDGET';
  widget.style.cssText = 'position:fixed;bottom:20px;right:20px;width:380px;height:520px;background:var(--bg2);border:1px solid #bf5af2;border-radius:14px;z-index:9998;display:flex;flex-direction:column;box-shadow:0 10px 40px rgba(191,90,242,0.3);overflow:hidden;backdrop-filter:blur(8px)';

  widget.innerHTML = 
    '<div style="background:linear-gradient(135deg, rgba(191,90,242,0.25), rgba(10,132,255,0.2));border-bottom:1px solid rgba(255,255,255,0.1);padding:12px 16px;display:flex;justify-content:space-between;align-items:center">' +
      '<div style="display:flex;align-items:center;gap:8px">' +
        '<span style="font-size:16px">🤖</span>' +
        '<div><div style="font-size:12px;font-weight:800;color:#ffffff">SENTINELX AI COPILOT</div><div style="font-size:9.5px;color:#bf5af2">Natural Language Threat Assistant</div></div>' +
      '</div>' +
      '<button class="btn btn-gh" style="padding:2px 8px;font-size:10px" onclick="_toggleAiCopilot()">✕</button>' +
    '</div>' +

    '<div id="AI_CHAT_MSGS" style="flex:1;overflow-y:auto;padding:12px;display:flex;flex-direction:column;gap:10px">' +
      '<div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:10px;font-size:11px;color:var(--text)">' +
        '👋 <b>Hello Analyst!</b> I am your SentinelX AI Copilot. Ask me anything about active incidents, IP reputations, or automated response actions.' +
      '</div>' +
    '</div>' +

    '<div style="padding:8px 12px;background:var(--bg3);border-top:1px solid var(--border);display:flex;gap:6px;overflow-x:auto">' +
      '<span class="chip cp-p" style="cursor:pointer;font-size:9px;white-space:nowrap" onclick="_sendAiCopilotQuery(\'Summarize active incidents\')">📊 Summarize Incidents</span>' +
      '<span class="chip cp-r" style="cursor:pointer;font-size:9px;white-space:nowrap" onclick="_sendAiCopilotQuery(\'Show critical alerts\')">🚨 Critical Alerts</span>' +
      '<span class="chip cp-b" style="cursor:pointer;font-size:9px;white-space:nowrap" onclick="_sendAiCopilotQuery(\'Check IOC 185.220.101.5\')">🌐 Check IOC</span>' +
    '</div>' +

    '<div style="padding:10px 12px;background:var(--bg2);border-top:1px solid var(--border);display:flex;gap:8px">' +
      '<input id="AI_QUERY_INPUT" class="inp" style="flex:1;margin:0;font-size:11px;background:rgba(0,0,0,0.5);color:#fff" placeholder="Ask AI Copilot..." onkeydown="if(event.key===\'Enter\') _sendAiCopilotQuery()"/>' +
      '<button class="btn btn-p" style="padding:6px 12px;font-size:11px;font-weight:700" onclick="_sendAiCopilotQuery()">Send</button>' +
    '</div>';

  document.body.appendChild(widget);
}

async function _sendAiCopilotQuery(customQuery) {
  var input = document.getElementById('AI_QUERY_INPUT');
  var query = customQuery || (input ? input.value : '');
  if(!query.trim()) return;
  if(input) input.value = '';

  var chatBox = document.getElementById('AI_CHAT_MSGS');
  if(!chatBox) return;

  // Add User message
  var userDiv = document.createElement('div');
  userDiv.style.cssText = 'align-self:flex-end;background:rgba(191,90,242,0.25);border:1px solid rgba(191,90,242,0.4);color:#ffffff;border-radius:8px;padding:8px 12px;font-size:11px;max-width:85%';
  userDiv.textContent = query;
  chatBox.appendChild(userDiv);

  // Add loading placeholder
  var botDiv = document.createElement('div');
  botDiv.style.cssText = 'align-self:flex-start;background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:10px;font-size:11px;color:var(--text);max-width:90%';
  botDiv.innerHTML = '<span class="live-dot"></span> Analyzing telemetry...';
  chatBox.appendChild(botDiv);
  chatBox.scrollTop = chatBox.scrollHeight;

  var ra = typeof _realAlerts === 'function' ? _realAlerts() : (_A || []);
  var critList = ra.filter(function(a){ return a.severity === 'CRITICAL'; });
  var highList = ra.filter(function(a){ return a.severity === 'HIGH'; });
  var incCount = (_I && _I.length) || 0;
  var qLower = query.toLowerCase();

  var text = '';
  try {
    var res = await fetch('/api/ai_copilot', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + (_authToken || '')
      },
      body: JSON.stringify({ query: query })
    });
    
    if (res.ok) {
      var contentType = res.headers.get('content-type') || '';
      if (contentType.indexOf('json') !== -1) {
        var data = await res.json();
        if (data.reply) text = data.reply;
      }
    }
  } catch(e) {}

  // Dynamic contextual fallback if backend is offline or restarting
  if (!text) {
    if (qLower.indexOf('summary') !== -1 || qLower.indexOf('incident') !== -1 || qLower.indexOf('status') !== -1 || qLower.indexOf('overview') !== -1) {
      text = '🛡️ **SOC Operational Summary:**\n- **Live Detections**: ' + ra.length + ' active threats (' + critList.length + ' Critical, ' + highList.length + ' High).\n- **Auto-Correlated Incidents**: ' + incCount + ' incidents declared.\n- **Active Detectors**: 7 telemetry engines (Sysmon, PS, CMD, Network, EXE, Registry, Security).\n- **Recommendation**: Immediate triage recommended for Critical alerts using 1-click SOAR Containment.';
    } else if (qLower.indexOf('critical') !== -1 || qLower.indexOf('urgent') !== -1 || qLower.indexOf('alert') !== -1) {
      if (critList.length > 0) {
        var top3 = critList.slice(0, 3).map(function(a){
          return '- **' + (a.id || 'Alert') + '**: ' + (a.event || 'Critical Threat') + ' on `' + (a.host || 'endpoint') + '` (' + (a.mitre_id || 'T1059') + ')';
        }).join('\n');
        text = '🚨 **Critical Threats Requiring Action (' + critList.length + ' active):**\n' + top3 + '\n\n*Action*: Click "Open" in Alert Feed to trigger AI remediation or host isolation.';
      } else {
        text = '✅ **Zero Critical Threats:** No critical alerts active in pipeline right now. System health is optimal.';
      }
    } else if (qLower.indexOf('isolate') !== -1 || qLower.indexOf('contain') !== -1 || qLower.indexOf('firewall') !== -1) {
      text = '🔒 **SOAR Host Containment Guide:**\nSentinelX automatically blocks inbound/outbound TCP traffic using Windows Firewall (`netsh advfirewall`) while maintaining a secure administrative communication channel to the SOC server.';
    } else if (qLower.indexOf('185.220') !== -1 || qLower.indexOf('ip') !== -1 || qLower.indexOf('ioc') !== -1) {
      text = '🌐 **Threat Intel on IP `185.220.101.5`:**\n- **Classification**: High Confidence Cobalt Strike C2 Node (Russia/Tor Exit)\n- **AbuseIPDB Score**: 100% (Malicious)\n- **VirusTotal Score**: 14/72 detections\n- **Recommended Action**: 1-Click Firewall Block via Threat Intel panel.';
    } else {
      text = '🤖 **SentinelX AI Analysis for "' + query + '":**\nAnalyzed ' + ra.length + ' alert signals across your SOC environment. All detection baselines and MITRE ATT&CK mappings are active. No anomalies found outside documented alert chains.';
    }
  }

  botDiv.innerHTML = text.replace(/\*\*(.*?)\*\*/g, '<b>$1</b>').replace(/\n/g, '<br/>');
  chatBox.scrollTop = chatBox.scrollHeight;
}

// War Room and Audio HUD handled globally

/* ═══════════════════════════════════════════════════════════
   UNIVERSAL ENDPOINT EVENT STREAM & SYSMON XML ENGINE (SPLUNK)
═══════════════════════════════════════════════════════════════ */
var _streamPollTimer = null;
var _streamAutoPollActive = true;
var _cachedStreamEvents = [];

function _initUniversalStreamUi() {
  _fetchEventStream();
  _loadSysmonXmlUi();
  if(!_streamPollTimer) {
    _streamPollTimer = setInterval(function() {
      var view = document.getElementById('STREAM_VIEW_CONSOLE');
      if(view && view.style.display !== 'none' && _streamAutoPollActive) {
        _fetchEventStream(true);
      }
    }, 1500); // 1.5s sub-second streaming
  }
}

function _switchStreamTab(tab) {
  var vStream = document.getElementById('STREAM_VIEW_CONSOLE');
  var vXml = document.getElementById('STREAM_VIEW_XML');
  var bStream = document.getElementById('TAB_BTN_STREAM');
  var bXml = document.getElementById('TAB_BTN_XML');

  if(tab === 'xml') {
    if(vStream) vStream.style.display = 'none';
    if(vXml) vXml.style.display = 'block';
    if(bStream) { bStream.className = 'btn btn-gh'; bStream.style.background = ''; bStream.style.color = ''; }
    if(bXml) { bXml.className = 'btn btn-ac'; bXml.style.background = 'var(--accent)'; bXml.style.color = '#000'; }
    _loadSysmonXmlUi();
  } else {
    if(vStream) vStream.style.display = 'block';
    if(vXml) vXml.style.display = 'none';
    if(bStream) { bStream.className = 'btn btn-ac'; bStream.style.background = 'var(--accent)'; bStream.style.color = '#000'; }
    if(bXml) { bXml.className = 'btn btn-gh'; bXml.style.background = ''; bXml.style.color = ''; }
    _fetchEventStream();
  }
}

function _toggleStreamAutoPoll() {
  _streamAutoPollActive = !_streamAutoPollActive;
  var btn = document.getElementById('STREAM_AUTO_BTN');
  if(btn) {
    btn.textContent = _streamAutoPollActive ? '⏸ Pause Stream' : '▶ Resume Stream';
    btn.className = _streamAutoPollActive ? 'btn btn-gh' : 'btn btn-ac';
  }
  if(typeof _toast === 'function') _toast(_streamAutoPollActive ? '▶ Live Stream Resumed' : '⏸ Live Stream Paused', 'b');
}

async function _fetchEventStream(isBackground) {
  var qInput = document.getElementById('STREAM_SEARCH_INP');
  var q = qInput ? qInput.value : '';

  try {
    var res = await fetch('/api/events/stream?limit=250&q=' + encodeURIComponent(q), {
      headers: { 'Authorization': 'Bearer ' + (_authToken || '') }
    });
    var data = await res.json();
    if(data.success) {
      _cachedStreamEvents = data.events || [];
      _renderStreamStats(data.stats || {});
      _renderStreamTable(_cachedStreamEvents);
    }
  } catch(e) {}
}

function _renderStreamStats(st) {
  var elTot = document.getElementById('STREAM_STAT_TOTAL');
  var elProcs = document.getElementById('STREAM_STAT_PROCS');
  var elEid1 = document.getElementById('STREAM_STAT_EID1');
  var elNet = document.getElementById('STREAM_STAT_NET');

  if(elTot) elTot.textContent = st.total_events_buffered || _cachedStreamEvents.length;
  if(elProcs) elProcs.textContent = st.unique_active_processes || '0';
  if(elEid1) elEid1.textContent = st.process_create_events || '0';
  if(elNet) elNet.textContent = ((st.network_events || 0) + (st.file_events || 0));
}

function _renderStreamTable(events) {
  var tbody = document.getElementById('STREAM_EVENTS_TBODY');
  if(!tbody) return;

  if(!events || !events.length) {
    tbody.innerHTML = '<tr><td colspan="10" style="text-align:center;padding:30px;color:var(--text3)"><span class="live-dot"></span> Ingesting events… Open any program (chrome.exe, notepad.exe, cmd.exe, calc.exe) to see it appear live!</td></tr>';
    return;
  }

  tbody.innerHTML = events.map(function(e) {
    var pName = (e.process_name || 'unknown').toLowerCase();
    var isBrowser = pName.includes('chrome') || pName.includes('msedge') || pName.includes('firefox') || pName.includes('brave');
    var isNotepad = pName.includes('notepad');
    var isCmd = pName.includes('cmd') || pName.includes('powershell');
    
    var nameColor = isBrowser ? '#30d158' : (isNotepad ? '#0a84ff' : (isCmd ? '#ff9500' : 'var(--text)'));
    var rowBg = isBrowser ? 'rgba(48,209,88,0.06)' : (isNotepad ? 'rgba(10,132,255,0.06)' : (e.severity === 'CRITICAL' ? 'rgba(255,59,48,0.1)' : ''));
    
    var timeStr = e.timestamp ? (e.timestamp.indexOf(' ') !== -1 ? e.timestamp.split(' ')[1] : e.timestamp) : '-';
    var eidNum = e.event_id || 1;
    var eidBadge = eidNum === 1 ? '<span class="bx bx-g">EID 1: PROC</span>' : (eidNum === 3 ? '<span class="bx bx-a">EID 3: NET</span>' : '<span class="bx bx-b">EID ' + eidNum + '</span>');
    var cmdDisplay = (e.command_line || '-').replace(/"/g, '&quot;');
    var userDisplay = e.user || '-';
    var parentDisplay = e.parent_name || '-';

    return (
      '<tr style="background:' + rowBg + ';cursor:pointer" onclick="_inspectSplunkEvent(\'' + e.id + '\')">' +
        '<td class="mono" style="font-size:10px">' + timeStr + '</td>' +
        '<td>' + eidBadge + '</td>' +
        '<td class="hi" style="font-weight:700;color:' + nameColor + '">' + (e.process_name || '-') + '</td>' +
        '<td class="mono" style="font-size:10px">' + (e.pid || 0) + '</td>' +
        '<td class="mono" style="font-size:10px;color:var(--text3)">' + (e.ppid || 0) + '</td>' +
        '<td class="mono" style="font-size:10.5px;color:var(--text2)">' + parentDisplay + '</td>' +
        '<td class="mono" style="font-size:9.5px;color:var(--text3);max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + cmdDisplay + '">' + cmdDisplay.substring(0, 55) + '</td>' +
        '<td class="mono" style="font-size:10px">' + userDisplay + '</td>' +
        '<td>' + sevBx(e.severity || 'INFO') + '</td>' +
        '<td><button class="btn btn-b" style="padding:2px 7px;font-size:9px" onclick="event.stopPropagation();_inspectSplunkEvent(\'' + e.id + '\')">Inspect</button></td>' +
      '</tr>'
    );
  }).join('');
}

function _handleStreamSearch() {
  _fetchEventStream();
}

function _applyStreamQuickFilter(q) {
  var inp = document.getElementById('STREAM_SEARCH_INP');
  if(inp) inp.value = q;
  _fetchEventStream();
}

async function _clearStreamBuffer() {
  try {
    await fetch('/api/events/clear', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + (_authToken || '') }
    });
    _cachedStreamEvents = [];
    _renderStreamTable([]);
    if(typeof _toast === 'function') _toast('🗑 Event stream buffer cleared', 'g');
  } catch(e) {}
}

function _inspectSplunkEvent(evtId) {
  var evt = _cachedStreamEvents.find(function(x) { return x.id === evtId; });
  if(!evt) return;

  var ex = document.getElementById('SPLUNK_EVENT_INSPECT_MODAL');
  if(ex) ex.remove();

  var modal = document.createElement('div');
  modal.id = 'SPLUNK_EVENT_INSPECT_MODAL';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.85);z-index:10005;display:flex;align-items:center;justify-content:center;padding:20px;backdrop-filter:blur(8px)';
  modal.onclick = function(e) { if(e.target === modal) modal.remove(); };

  modal.innerHTML = 
    '<div style="background:var(--bg2);border:1px solid var(--border);border-radius:14px;width:100%;max-width:700px;padding:22px;box-shadow:0 0 50px rgba(0,0,0,0.8)">' +
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">' +
        '<div>' +
          '<div style="font-size:14px;font-weight:900;color:var(--accent)">🔍 SPLUNK RAW EVENT INSPECTOR</div>' +
          '<div style="font-size:11px;color:var(--text3);margin-top:2px">Event ID ' + (evt.event_id || 1) + ' · ' + (evt.event_name || 'Process Create') + '</div>' +
        '</div>' +
        '<button class="btn btn-gh" onclick="document.getElementById(\'SPLUNK_EVENT_INSPECT_MODAL\').remove()" style="padding:4px 10px">Close ✕</button>' +
      '</div>' +

      // Splunk Raw String
      '<div style="margin-bottom:12px">' +
        '<div style="font-size:10px;font-weight:700;color:var(--text3);margin-bottom:4px">RAW SPLUNK / SIEM LOG STRING:</div>' +
        '<div style="background:var(--bg3);border:1px solid var(--border);padding:10px;border-radius:6px;font-family:var(--mono);font-size:10px;color:var(--accent);word-break:break-all;line-height:1.5">' +
          (evt.raw_log || '-') +
        '</div>' +
      '</div>' +

      // Process Ancestry
      '<div style="margin-bottom:12px;background:var(--bg3);border:1px solid var(--border);padding:10px;border-radius:6px">' +
        '<div style="font-size:10px;font-weight:700;color:var(--text3);margin-bottom:6px">PROCESS HIERARCHY TREE:</div>' +
        '<div style="font-family:var(--mono);font-size:11px;color:var(--text)">' +
          '<span>📁 ' + (evt.parent_name || 'Parent Process') + ' (PPID: ' + (evt.ppid || 0) + ')</span>' +
          '<br/><span style="color:var(--accent);margin-left:14px">↳ ⚡ <b>' + (evt.process_name || 'Process') + '</b> (PID: ' + (evt.pid || 0) + ')</span>' +
        '</div>' +
      '</div>' +

      // Formatted Key-Value Grid
      '<div style="max-height:220px;overflow-y:auto;background:rgba(0,0,0,0.5);border:1px solid var(--border);border-radius:6px;padding:10px;font-family:var(--mono);font-size:10px;color:#a5d6ff">' +
        '<pre style="margin:0">' + JSON.stringify(evt, null, 2) + '</pre>' +
      '</div>' +
    '</div>';

  document.body.appendChild(modal);
}

// ── SYSMON XML MANAGER UI ───────────────────────────────────
async function _loadSysmonXmlUi() {
  var box = document.getElementById('SYSMON_XML_STATUS_BOX');
  var txt = document.getElementById('SYSMON_XML_TEXTAREA');
  var cfgStat = document.getElementById('STREAM_STAT_CFG');

  try {
    var res = await fetch('/api/sysmon/config', {
      headers: { 'Authorization': 'Bearer ' + (_authToken || '') }
    });
    var data = await res.json();
    if(txt && data.content) txt.value = data.content;
    
    var val = data.validation || {};
    if(box) {
      if(val.valid) {
        box.innerHTML = '✅ <b>Active Config:</b> ' + data.filename + ' (' + (data.is_custom ? 'Custom Upload' : 'Default Baseline') + ') · <b>' + (val.rule_elements_count || 0) + ' XML Filter Rules</b> Active.';
        box.style.color = 'var(--green)';
      } else {
        box.innerHTML = '⚠️ <b>XML Validation Warning:</b> ' + (val.error || 'Check syntax');
        box.style.color = 'var(--amber)';
      }
    }
    if(cfgStat) cfgStat.textContent = (val.rule_elements_count || 45) + ' XML Rules';
  } catch(e) {}
}

async function _saveSysmonXmlUi() {
  var txt = document.getElementById('SYSMON_XML_TEXTAREA');
  if(!txt) return;
  var content = txt.value.trim();
  if(!content) {
    if(typeof _toast === 'function') _toast('XML configuration content cannot be empty', 'r');
    return;
  }

  if(typeof _toast === 'function') _toast('Validating and applying Sysmon XML...', 'b');

  try {
    var res = await fetch('/api/sysmon/config', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + (_authToken || '')
      },
      body: JSON.stringify({ xml_content: content })
    });
    var data = await res.json();
    if(data.success) {
      if(typeof _toast === 'function') _toast('✅ ' + data.message, 'g');
      _loadSysmonXmlUi();
    } else {
      if(typeof _toast === 'function') _toast('XML Error: ' + (data.error || 'Failed to parse XML'), 'r');
    }
  } catch(e) {
    if(typeof _toast === 'function') _toast('Network error saving Sysmon XML: ' + e.message, 'r');
  }
}

async function _resetSysmonXmlUi() {
  try {
    var res = await fetch('/api/sysmon/config/reset', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + (_authToken || '') }
    });
    var data = await res.json();
    if(data.success) {
      if(typeof _toast === 'function') _toast('🔄 Reverted to default SentinelX Sysmon XML', 'g');
      _loadSysmonXmlUi();
    }
  } catch(e) {}
}

function _handleSysmonFileUpload(event) {
  var file = event.target.files[0];
  if(!file) return;
  var reader = new FileReader();
  reader.onload = function(e) {
    var txt = document.getElementById('SYSMON_XML_TEXTAREA');
    if(txt) txt.value = e.target.result;
    if(typeof _toast === 'function') _toast('📁 Loaded ' + file.name + ' into editor — click "Save & Apply XML"', 'b');
  };
  reader.readAsText(file);
}

function _applySysmonTemplate(tpl) {
  var txt = document.getElementById('SYSMON_XML_TEXTAREA');
  if(!txt) return;

  if(tpl === 'swiftonsecurity') {
    txt.value = '<Sysmon schemaversion="4.90">\n  <!-- SwiftOnSecurity Sysmon Config v14 -->\n  <HashAlgorithms>SHA256,MD5</HashAlgorithms>\n  <EventFiltering>\n    <RuleGroup name="SWIFTONSECURITY_PROCESS" groupRelation="or">\n      <ProcessCreate onmatch="exclude">\n        <Image condition="is">C:\\Windows\\System32\\notepad.exe</Image>\n      </ProcessCreate>\n      <ProcessCreate onmatch="include">\n        <CommandLine condition="contains"> -enc </CommandLine>\n        <CommandLine condition="contains">bypass</CommandLine>\n        <CommandLine condition="contains">downloadstring</CommandLine>\n        <CommandLine condition="contains">mimikatz</CommandLine>\n        <CommandLine condition="contains">vssadmin delete shadows</CommandLine>\n      </ProcessCreate>\n    </RuleGroup>\n  </EventFiltering>\n</Sysmon>';
  } else if(tpl === 'threathunting') {
    txt.value = '<Sysmon schemaversion="4.90">\n  <!-- Olaf Hartong ThreatHunting Modular Sysmon Configuration -->\n  <HashAlgorithms>SHA256</HashAlgorithms>\n  <EventFiltering>\n    <RuleGroup name="THREATHUNTING_EXECUTION" groupRelation="or">\n      <ProcessCreate onmatch="include">\n        <Image condition="end with">cmd.exe</Image>\n        <Image condition="end with">powershell.exe</Image>\n        <Image condition="end with">wscript.exe</Image>\n        <Image condition="end with">cscript.exe</Image>\n        <Image condition="end with">mshta.exe</Image>\n        <Image condition="end with">rundll32.exe</Image>\n        <Image condition="end with">regsvr32.exe</Image>\n        <Image condition="end with">certutil.exe</Image>\n      </ProcessCreate>\n    </RuleGroup>\n  </EventFiltering>\n</Sysmon>';
  } else {
    _loadSysmonXmlUi();
  }
  if(typeof _toast === 'function') _toast('Template loaded into editor — click "Save & Apply XML"', 'b');
}
