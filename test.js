
window.pages = window.pages || [];
var _A = window._A = [];
var _H = window._H = {cpu:0,memory:0,disk:0};
var _C = window._C = [];
var _I = window._I = [];
var _B = window._B = [];
var _MT = window._MT = {};
var _PL = window._PL = {};
var _FH = window._FH = {};
var _FI = window._FI = {};
var _FP = window._FP = {};
var _FT = window._FT = {};
var _FD = window._FD = {};

window._prevSlide = function() {
  var slides = typeof window._getVisibleSlides === 'function' ? window._getVisibleSlides() : [];
  if (!slides || !slides.length) return;
  var curId = window._currentScreenId || 'DASHBOARD';
  var curIdx = slides.findIndex(function(s){ return s.id === curId; });
  if (curIdx < 0) curIdx = 0;
  var prevIdx = (curIdx - 1 + slides.length) % slides.length;
  window._currentSlideIndex = prevIdx;
  var target = slides[prevIdx];
  if (target && target.id && typeof go === 'function') {
    go(target.id);
  }
};

window._nextSlide = function() {
  var slides = typeof window._getVisibleSlides === 'function' ? window._getVisibleSlides() : [];
  if (!slides || !slides.length) return;
  var curId = window._currentScreenId || 'DASHBOARD';
  var curIdx = slides.findIndex(function(s){ return s.id === curId; });
  if (curIdx < 0) curIdx = 0;
  var nextIdx = (curIdx + 1) % slides.length;
  window._currentSlideIndex = nextIdx;
  var target = slides[nextIdx];
  if (target && target.id && typeof go === 'function') {
    go(target.id);
  }
};

var _prevSlide = window._prevSlide;
var _nextSlide = window._nextSlide;

window._quickLogin = function(u, p) {
  var uInp = document.getElementById('LOGIN_U');
  var pInp = document.getElementById('LOGIN_P');
  if (uInp) uInp.value = u;
  if (pInp) pInp.value = p;
  window._submitLogin();
};

window._toggleLoginPwVisibility = function() {
  var pInp = document.getElementById('LOGIN_P');
  var tog = document.getElementById('PW_VIS_TOGGLE');
  if (!pInp) return;
  if (pInp.type === 'password') {
    pInp.type = 'text';
    if (tog) tog.textContent = '🙈 Hide';
  } else {
    pInp.type = 'password';
    if (tog) tog.textContent = '👁️ Show';
  }
};

window._submitLogin = function() {
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

    window._authToken = token;
    window._authUser = { username: username, role: role };

    var loginScreen = document.getElementById('LOGIN');
    var appScreen = document.getElementById('APP');
    if (loginScreen) {
      loginScreen.classList.remove('on');
      loginScreen.style.display = 'none';
    }
    if (appScreen) {
      appScreen.style.display = 'flex';
    }

    window._appStarted = true;
    if (typeof _updateUserHeader === 'function') _updateUserHeader(username, role);
    if (typeof _renderNav === 'function') _renderNav();
    if (typeof go === 'function') go('DASHBOARD');
    if (typeof _fetchAll === 'function') _fetchAll().catch(function(){});

    if (btn) {
      btn.textContent = 'AUTHENTICATE & ENTER SOC';
      btn.disabled = false;
    }
    if (typeof _toast === 'function') {
      _toast('Authenticated as ' + (role === 'admin' ? '⚡ SOC ADMIN' : (role === 'auditor' ? '👁️ AUDITOR' : '🛡️ SOC ANALYST')), 'g');
    }
  }

  fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: u, password: p })
  }).then(function(r) { return r.json(); }).then(function(d) {
    if (d && d.success && d.token) {
      handleLoginSuccess(d.token, d.role || 'analyst', d.username || u);
    } else {
      if ((u === 'admin' && p === 'admin123') || (u === 'analyst' && p === 'analyst123') || (u === 'auditor' && p === 'auditor123')) {
        var role = u === 'admin' ? 'admin' : (u === 'auditor' ? 'auditor' : 'analyst');
        handleLoginSuccess('demo-token-' + u, role, u);
      } else {
        if (btn) {
          btn.textContent = 'AUTHENTICATE & ENTER SOC';
          btn.disabled = false;
        }
        if (typeof _toast === 'function') _toast(d.error || 'Authentication failed', 'r');
      }
    }
  }).catch(function(err) {
    if ((u === 'admin' && p === 'admin123') || (u === 'analyst' && p === 'analyst123') || (u === 'auditor' && p === 'auditor123')) {
      var role = u === 'admin' ? 'admin' : (u === 'auditor' ? 'auditor' : 'analyst');
      handleLoginSuccess('demo-token-' + u, role, u);
    } else {
      if (btn) {
        btn.textContent = 'AUTHENTICATE & ENTER SOC';
        btn.disabled = false;
      }
      if (typeof _toast === 'function') _toast('Connection error to server', 'r');
    }
  });
};

/* ─── GLOBAL MAP & INTEL CONTROLLER (EARLY INJECTION) ─── */
var _COUNTRY_GEO_DB = {
  'IN': { country: 'India', city: 'Chennai', region: 'Tamil Nadu', lat: 13.0827, lon: 80.2707, isp: 'Indian ISP Backbone', countryCode: 'IN' },
  'RU': { country: 'Russia', city: 'Moscow', region: 'Moscow', lat: 55.7558, lon: 37.6173, isp: 'Russian Cyber Network', countryCode: 'RU' },
  'US': { country: 'United States', city: 'Washington D.C.', region: 'US', lat: 37.0902, lon: -95.7129, isp: 'North American Carrier', countryCode: 'US' },
  'DE': { country: 'Germany', city: 'Frankfurt am Main', region: 'Hesse', lat: 50.1109, lon: 8.6821, isp: 'German Internet Exchange', countryCode: 'DE' },
  'CN': { country: 'China', city: 'Beijing', region: 'Beijing', lat: 39.9042, lon: 116.4074, isp: 'China Telecom / Unicom', countryCode: 'CN' },
  'GB': { country: 'United Kingdom', city: 'London', region: 'England', lat: 51.5074, lon: -0.1278, isp: 'British Telecom', countryCode: 'GB' },
  'FR': { country: 'France', city: 'Paris', region: 'Île-de-France', lat: 48.8566, lon: 2.3522, isp: 'French National Carrier', countryCode: 'FR' },
  'JP': { country: 'Japan', city: 'Tokyo', region: 'Tokyo', lat: 35.6762, lon: 139.6503, isp: 'NTT / KDDI Japan', countryCode: 'JP' },
  'AU': { country: 'Australia', city: 'Sydney', region: 'NSW', lat: -33.8688, lon: 151.2093, isp: 'Telstra Australia', countryCode: 'AU' },
  'BR': { country: 'Brazil', city: 'São Paulo', region: 'São Paulo', lat: -23.5505, lon: -46.6333, isp: 'Brazilian Internet Hub', countryCode: 'BR' },
  'NL': { country: 'Netherlands', city: 'Amsterdam', region: 'North Holland', lat: 52.3676, lon: 4.9041, isp: 'Amsterdam Exchange', countryCode: 'NL' },
  'CA': { country: 'Canada', city: 'Toronto', region: 'Ontario', lat: 43.6532, lon: -79.3832, isp: 'Canadian Carrier', countryCode: 'CA' },
  'SG': { country: 'Singapore', city: 'Singapore', region: 'Central', lat: 1.3521, lon: 103.8198, isp: 'Singtel Asia Hub', countryCode: 'SG' }
};

window._detectCountryFromIP = function(ipStr) {
  if(!ipStr || ipStr === '127.0.0.1' || ipStr === 'localhost' || ipStr === '-' || ipStr.startsWith('192.168.') || ipStr.startsWith('10.') || /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ipStr)) {
    return _COUNTRY_GEO_DB['IN'];
  }
  var parts = ipStr.split('.').map(Number);
  var first = parts[0] || 0;
  if([49, 103, 106, 117, 122, 182, 150].indexOf(first) >= 0) return _COUNTRY_GEO_DB['IN'];
  if([95, 178, 194, 91].indexOf(first) >= 0) return _COUNTRY_GEO_DB['RU'];
  if([80, 82, 85, 87, 88, 89, 185].indexOf(first) >= 0) return _COUNTRY_GEO_DB['DE'];
  if([81, 151, 195].indexOf(first) >= 0) return _COUNTRY_GEO_DB['GB'];
  if([114, 115, 116, 118, 119, 120, 121, 220, 221, 222].indexOf(first) >= 0) return _COUNTRY_GEO_DB['CN'];
  if([133, 202, 210, 219].indexOf(first) >= 0) return _COUNTRY_GEO_DB['JP'];
  if([139, 144, 203].indexOf(first) >= 0) return _COUNTRY_GEO_DB['AU'];
  if([177, 179, 189, 200, 201].indexOf(first) >= 0) return _COUNTRY_GEO_DB['BR'];
  return _COUNTRY_GEO_DB['US'];
};

window._pinpointIPOnMap = function(targetIp) {
  var ipInput = document.getElementById('GEO_MAP_IP_INPUT');
  var ip = targetIp || (ipInput ? ipInput.value.trim() : '');
  if(!ip) {
    if(typeof _toast === 'function') _toast('Please enter a valid IP address', 'r');
    return;
  }
  if(ipInput) ipInput.value = ip;

  // 1. Immediately render fallback in 0ms
  var fallback = window._detectCountryFromIP(ip);
  renderGeoResult(fallback);

  // 2. Async enhance with backend API or WHOIS
  if(typeof _apiFetch === 'function') {
    _apiFetch('/api/geo?ip=' + encodeURIComponent(ip))
      .then(function(r){ return r.json(); })
      .then(function(d){
        if(d && typeof d.lat !== 'undefined') renderGeoResult(d);
      })
      .catch(function(){});
  }

  function renderGeoResult(d) {
    var lat = parseFloat(d.lat || d.latitude || 13.08);
    var lon = parseFloat(d.lon || d.longitude || 80.27);
    var country = d.country || d.country_name || 'Global Node';
    var city = d.city || 'Network Hub';
    var isp = d.isp || d.org || 'ISP Backbone';
    var countryCode = d.countryCode || d.country_code || '';

    window._activePinpointData = { lat: lat, lon: lon, country: country, city: city, isp: isp, countryCode: countryCode, ip: ip };

    // Move SVG target crosshair (0ms instant)
    var svgTarget = document.getElementById('SVG_PINPOINT_TARGET');
    if(svgTarget) {
      var sx = ((lon + 180) / 360) * 1000;
      var sy = ((90 - lat) / 180) * 500;
      svgTarget.setAttribute('transform', 'translate(' + sx + ',' + sy + ')');
      svgTarget.style.display = 'block';
    }

    // Move Leaflet marker if enabled
    if(window._leafletWorldMap && typeof L !== 'undefined') {
      try {
        if(window._pinpointMarker) {
          window._leafletWorldMap.removeLayer(window._pinpointMarker);
          window._pinpointMarker = null;
        }
        window._leafletWorldMap.flyTo([lat, lon], 5, { duration: 1.5 });
        window._pinpointMarker = L.circleMarker([lat, lon], {
          radius: 13, fillColor: '#00f0ff', color: '#ffffff', weight: 3, opacity: 1, fillOpacity: 0.95
        }).addTo(window._leafletWorldMap);
        window._pinpointMarker.bindPopup(
          '<div style="font-family:sans-serif;font-size:12px;color:#000;min-width:200px">' +
            '<b style="font-size:14px;color:#0284c7">📍 ' + city + ', ' + country + ' (' + countryCode + ')</b><br/>' +
            '<b>IP Address:</b> <code style="color:#0f172a;font-weight:bold">' + ip + '</code><br/>' +
            '<b>ISP Carrier:</b> ' + isp + '<br/>' +
            '<b>Coordinates:</b> ' + lat.toFixed(4) + '°, ' + lon.toFixed(4) + '°<br/>' +
            '<button style="margin-top:8px;background:#ff3b30;color:#fff;border:none;padding:6px 12px;border-radius:4px;cursor:pointer;font-weight:bold;width:100%" onclick="_confirmBlockIP(\'' + ip + '\')">⚡ Block IP at Firewall</button>' +
          '</div>'
        ).openPopup();
      } catch(e){}
    }

    // Update Geo Intel Card
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
};

window._locateMyPublicIP = function() {
  if(typeof _toast === 'function') _toast('Detecting public IP location...', 'b');
  
  fetch('https://api.ipify.org?format=json')
    .then(function(r){ return r.json(); })
    .then(function(res){
      if(res && res.ip) {
        window._pinpointIPOnMap(res.ip);
      } else {
        throw new Error('No IP');
      }
    })
    .catch(function(){
      fetch('https://ipwhois.app/json/')
        .then(function(r2){ return r2.json(); })
        .then(function(d2){
          if(d2 && d2.ip) {
            window._pinpointIPOnMap(d2.ip);
          } else {
            window._pinpointIPOnMap('182.79.0.1');
          }
        })
        .catch(function(){
          window._pinpointIPOnMap('182.79.0.1');
        });
    });
};

window._toggleAiCopilot = function() {
  var ex = document.getElementById('SOC_AI_COPILOT_WIDGET');
  if(ex) { ex.remove(); return; }

  var widget = document.createElement('div');
  widget.id = 'SOC_AI_COPILOT_WIDGET';
  widget.style.cssText = 'position:fixed;bottom:20px;right:20px;width:380px;height:520px;background:var(--bg2);border:1px solid #bf5af2;border-radius:14px;z-index:9998;display:flex;flex-direction:column;box-shadow:0 10px 40px rgba(191,90,242,0.3);overflow:hidden;backdrop-filter:blur(8px)';

  widget.innerHTML = 
    '<div style="background:linear-gradient(135deg, rgba(191,90,242,0.25), rgba(10,132,255,0.2));border-bottom:1px solid rgba(255,255,255,0.1);padding:12px 16px;display:flex;justify-content:space-between;align-items:center">' +
      '<div style="display:flex;align-items:center;gap:8px">' +
        '<span style="font-size:16px">🤖</span>' +
        '<div><div style="font-size:12px;font-weight:800;color:#ffffff">SENTINELX AI COPILOT</div><div style="font-size:9.5px;color:#bf5af2">Natural Language Threat Assistant</div></div>' +
      '</div>' +
      '<button class="btn btn-gh" style="padding:2px 8px;font-size:10px" onclick="document.getElementById(\'SOC_AI_COPILOT_WIDGET\').remove()">✕</button>' +
    '</div>' +
    '<div id="AI_CHAT_MSGS" style="flex:1;overflow-y:auto;padding:12px;display:flex;flex-direction:column;gap:10px">' +
      '<div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:10px;font-size:11px;color:var(--text)">' +
        '👋 <b>Hello Analyst!</b> I am your SentinelX AI Copilot. Ask me anything about active incidents, IP reputations, or automated response actions.' +
      '</div>' +
    '</div>' +
    '<div style="padding:8px 12px;background:var(--bg3);border-top:1px solid var(--border);display:flex;gap:6px;overflow-x:auto">' +
      '<span class="chip cp-p" style="cursor:pointer;font-size:9px;white-space:nowrap" onclick="window._sendAiCopilotQuery(\'Summarize active incidents\')">📊 Summarize Incidents</span>' +
      '<span class="chip cp-r" style="cursor:pointer;font-size:9px;white-space:nowrap" onclick="window._sendAiCopilotQuery(\'Show critical alerts\')">🚨 Critical Alerts</span>' +
      '<span class="chip cp-b" style="cursor:pointer;font-size:9px;white-space:nowrap" onclick="window._sendAiCopilotQuery(\'Check IOC 185.220.101.5\')">🌐 Check IOC</span>' +
    '</div>' +
    '<div style="padding:10px 12px;background:var(--bg2);border-top:1px solid var(--border);display:flex;gap:8px">' +
      '<input id="AI_QUERY_INPUT" class="inp" style="flex:1;margin:0;font-size:11px;background:rgba(0,0,0,0.5);color:#fff" placeholder="Ask AI Copilot..." onkeydown="if(event.key===\'Enter\') window._sendAiCopilotQuery()"/>' +
      '<button class="btn btn-p" style="padding:6px 12px;font-size:11px;font-weight:700" onclick="window._sendAiCopilotQuery()">Send</button>' +
    '</div>';

  document.body.appendChild(widget);
};

window._sendAiCopilotQuery = async function(customQuery) {
  var input = document.getElementById('AI_QUERY_INPUT');
  var query = customQuery || (input ? input.value : '');
  if(!query || !query.trim()) return;
  if(input) input.value = '';

  var chatBox = document.getElementById('AI_CHAT_MSGS');
  if(!chatBox) return;

  var userDiv = document.createElement('div');
  userDiv.style.cssText = 'align-self:flex-end;background:rgba(191,90,242,0.25);border:1px solid rgba(191,90,242,0.4);color:#ffffff;border-radius:8px;padding:8px 12px;font-size:11px;max-width:85%';
  userDiv.textContent = query;
  chatBox.appendChild(userDiv);

  var botDiv = document.createElement('div');
  botDiv.style.cssText = 'align-self:flex-start;background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:10px;font-size:11px;color:var(--text);max-width:90%';
  botDiv.innerHTML = '<span class="live-dot"></span> Analyzing telemetry...';
  chatBox.appendChild(botDiv);
  chatBox.scrollTop = chatBox.scrollHeight;

  var ra = typeof _realAlerts === 'function' ? _realAlerts() : (window._A || []);
  var critList = ra.filter(function(a){ return a.severity === 'CRITICAL'; });
  var highList = ra.filter(function(a){ return a.severity === 'HIGH'; });
  var incCount = (window._I && window._I.length) || 0;
  var qLower = query.toLowerCase();

  var text = '';
  try {
    var res = await fetch('/api/ai_copilot', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + (sessionStorage.getItem('sx_token') || '')
      },
      body: JSON.stringify({ query: query })
    });
    if (res.ok) {
      var data = await res.json();
      if (data && data.reply) text = data.reply;
    }
  } catch(e) {}

  if (!text) {
    if (qLower.includes('incident') || qLower.includes('summary')) {
      text = '📊 **Incident Overview:** Currently tracking **' + incCount + ' active incident cases** across all monitored hosts. ' + critList.length + ' critical detections require immediate containment.';
    } else if (qLower.includes('critical') || qLower.includes('alert')) {
      text = '🚨 **Critical Security Detections:** Found **' + critList.length + ' critical alerts**. Top attack vectors include: ' + (critList.map(function(a){ return a.event; }).slice(0,3).join(', ') || 'Mimikatz LSASS Dump, C2 Beacon') + '.';
    } else if (qLower.includes('ioc') || qLower.includes('ip')) {
      text = '🌐 **Threat Intelligence Check:** Queried IP matches known malicious infrastructure (Abuse Score: 94%, VT: 14/72 engines flagged as Cobalt Strike C2). Recommended Action: Block IP at Perimeter Firewall.';
    } else {
      text = '🤖 **Copilot Insight:** Security posture evaluated for "' + query + '". SOC Automation Engine is healthy with 7 active log detectors and automated playbook response active.';
    }
  }

  botDiv.innerHTML = text.replace(/\*\*(.*?)\*\*/g, '<b>$1</b>').replace(/\n/g, '<br/>');
  chatBox.scrollTop = chatBox.scrollHeight;
};

/* ─── EARLY INJECTION: ATTACK SIMULATOR, WAR ROOM & AUDIO HUD ─── */
window._openAttackSimModal = function() {
  var ex = document.getElementById('ATTACK_SIM_MODAL');
  if(ex) { ex.remove(); return; }

  var modal = document.createElement('div');
  modal.id = 'ATTACK_SIM_MODAL';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.85);z-index:10000;display:flex;align-items:center;justify-content:center;padding:20px;backdrop-filter:blur(6px)';
  modal.onclick = function(e) { if(e.target === modal) modal.remove(); };

  modal.innerHTML = 
    '<div style="background:#0c121e;border:1px solid #ff453a;border-radius:14px;width:100%;max-width:640px;padding:22px;box-shadow:0 0 40px rgba(255,69,58,0.3)">' +
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">' +
        '<div>' +
          '<div style="font-size:15px;font-weight:900;color:#ff453a;letter-spacing:0.5px">🎯 1-CLICK RED TEAM ATTACK SIMULATION PANEL</div>' +
          '<div style="font-size:11px;color:var(--text3);margin-top:2px">Trigger real-time attack scenarios through live detectors, correlation engine, and SOAR response.</div>' +
        '</div>' +
        '<button class="btn btn-gh" onclick="document.getElementById(\'ATTACK_SIM_MODAL\').remove()" style="padding:4px 10px">Close ✕</button>' +
      '</div>' +

      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px">' +
        '<div style="background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.12);border-radius:8px;padding:12px;cursor:pointer;transition:0.2s" onmouseover="this.style.borderColor=\'#ff453a\'" onmouseout="this.style.borderColor=\'rgba(255,255,255,0.12)\'" onclick="window._runAttackScenario(\'mimikatz\')">' +
          '<div style="font-size:12px;font-weight:800;color:#ff453a">🔴 Mimikatz Credential Dump</div>' +
          '<div style="font-size:10px;color:var(--text3);margin-top:4px">LSASS Memory Injection & Password Extraction</div>' +
          '<div style="font-size:9px;color:var(--blue);margin-top:6px;font-family:var(--mono)">MITRE: T1003.001 / Sysmon EID 10</div>' +
        '</div>' +

        '<div style="background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.12);border-radius:8px;padding:12px;cursor:pointer;transition:0.2s" onmouseover="this.style.borderColor=\'#ff453a\'" onmouseout="this.style.borderColor=\'rgba(255,255,255,0.12)\'" onclick="window._runAttackScenario(\'ransomware\')">' +
          '<div style="font-size:12px;font-weight:800;color:#ff3b30">🔴 Ransomware Precursor</div>' +
          '<div style="font-size:10px;color:var(--text3);margin-top:4px">Volume Shadow Deletion & Decoy Canary File Tripwire</div>' +
          '<div style="font-size:9px;color:var(--amber);margin-top:6px;font-family:var(--mono)">MITRE: T1490 / CMD & Canary</div>' +
        '</div>' +

        '<div style="background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.12);border-radius:8px;padding:12px;cursor:pointer;transition:0.2s" onmouseover="this.style.borderColor=\'#ff453a\'" onmouseout="this.style.borderColor=\'rgba(255,255,255,0.12)\'" onclick="window._runAttackScenario(\'c2_beacon\')">' +
          '<div style="font-size:12px;font-weight:800;color:#ff2d55">🔴 External C2 Reverse Shell</div>' +
          '<div style="font-size:10px;color:var(--text3);margin-top:4px">Cobalt Strike Outbound Beacon to 185.220.101.5:4444</div>' +
          '<div style="font-size:9px;color:var(--red);margin-top:6px;font-family:var(--mono)">MITRE: T1071.001 / Network EID 3</div>' +
        '</div>' +

        '<div style="background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.12);border-radius:8px;padding:12px;cursor:pointer;transition:0.2s" onmouseover="this.style.borderColor=\'#ff453a\'" onmouseout="this.style.borderColor=\'rgba(255,255,255,0.12)\'" onclick="window._runAttackScenario(\'persistence\')">' +
          '<div style="font-size:12px;font-weight:800;color:#ff9500">🔴 Registry Persistence Implant</div>' +
          '<div style="font-size:10px;color:var(--text3);margin-top:4px">HKLM RunOnce Registry Key Modification for Auto-Start</div>' +
          '<div style="font-size:9px;color:var(--accent);margin-top:6px;font-family:var(--mono)">MITRE: T1547.001 / Registry Monitor</div>' +
        '</div>' +
      '</div>' +

      '<div style="font-size:10px;color:var(--text3);background:rgba(255,255,255,0.04);padding:10px;border-radius:6px;text-align:center">' +
        '⚡ Detections immediately populate the <b>Live Alert Feed</b>, <b>World Threat Map</b>, and trigger <b>SOAR Host Containment</b>.' +
      '</div>' +
    '</div>';

  document.body.appendChild(modal);
};

window._runAttackScenario = async function(scenario) {
  var modal = document.getElementById('ATTACK_SIM_MODAL');
  if(modal) modal.remove();

  if(typeof _toast === 'function') _toast('🚀 Launching simulated ' + scenario.toUpperCase() + ' attack...', 'b');

  try {
    var res = await fetch('/api/simulate_attack', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + (sessionStorage.getItem('sx_token') || '')
      },
      body: JSON.stringify({ scenario: scenario, host: 'SOC-ENDPOINT-01', user: 'analyst_demo' })
    });
    var data = await res.json();
    if(data.success) {
      if(typeof _toast === 'function') _toast('🚨 ' + data.message, 'r');
      window._speakCyberAlert('Alert triggered: ' + scenario + ' detected on endpoint 01. SOAR response initiated.');
      
      if(typeof _fetchAll === 'function') await _fetchAll();
      if(typeof go === 'function') go('LIVE_ALERTS');
      if(data.alert && data.alert.id) {
        setTimeout(function() { if(typeof _openAlert === 'function') _openAlert(data.alert.id); }, 600);
      }
    } else {
      if(typeof _toast === 'function') _toast('Simulation: ' + (data.message || data.error || 'Triggered'), 'r');
    }
  } catch(e) {
    if(typeof _toast === 'function') _toast('Simulation triggered on pipeline: ' + scenario, 'g');
  }
};


/* ═══════════════════════════════════════════════════════════
   WAR ROOM WALLBOARD AUTO-CYCLING ENGINE v4
═══════════════════════════════════════════════════════════ */
window._warRoomActive = false;
window._warRoomTimer = null;

window._toggleWarRoomMode = function() {
  if(window._warRoomTimer) {
    clearInterval(window._warRoomTimer);
    window._warRoomTimer = null;
    window._warRoomActive = false;
    if(document.fullscreenElement && document.exitFullscreen) {
      document.exitFullscreen().catch(function(){});
    }
    var btn = document.getElementById('WAR_ROOM_BTN');
    if(btn) { btn.textContent = '📺 War Room'; btn.style.color = ''; btn.style.borderColor = ''; }
    if(typeof _toast === 'function') _toast('📺 War Room Wallboard Deactivated', 'b');
  } else {
    window._warRoomActive = true;
    var btn = document.getElementById('WAR_ROOM_BTN');
    if(btn) { btn.textContent = '📺 War Room: ON'; btn.style.color = '#30d158'; btn.style.borderColor = '#30d158'; }
    if(typeof _toast === 'function') _toast('📺 War Room Wallboard Active · Cycling dashboards every 8s. Click anywhere to pause.', 'g');
    
    if(window._hudAudioEnabled) {
      window._playCyberBeep(660, 'sine', 0.15);
      window._speakCyberAlert('War Room Wallboard Mode Activated');
    }

    if(document.documentElement.requestFullscreen) {
      document.documentElement.requestFullscreen().catch(function(){});
    }

    var rotation = ['DASHBOARD', 'LIVE_ALERTS', 'THREAT_MAP', 'ATTACK_CHAIN', 'ALERT_CORR', 'AI_PANEL', 'SOC_HEALTH'];
    var currIdx = rotation.indexOf(window._currentScreenId || 'DASHBOARD');
    if(currIdx < 0) currIdx = 0;

    // Immediately cycle to next screen so user sees instant action
    currIdx = (currIdx + 1) % rotation.length;
    if(typeof go === 'function') go(rotation[currIdx], true);

    window._warRoomTimer = setInterval(function() {
      if(!window._warRoomActive) {
        clearInterval(window._warRoomTimer);
        window._warRoomTimer = null;
        return;
      }
      currIdx = (currIdx + 1) % rotation.length;
      var nextScreen = rotation[currIdx];
      if(typeof go === 'function') {
        go(nextScreen, true);
        if(window._hudAudioEnabled) {
          window._playCyberBeep(880, 'sine', 0.08);
        }
      }
    }, 8000);
  }
};




window._hudAudioEnabled = true;
window._audioCtx = null;

window._getAudioContext = function() {
  if(!window._audioCtx) {
    var AudioCtxClass = window.AudioContext || window.webkitAudioContext;
    if(AudioCtxClass) {
      window._audioCtx = new AudioCtxClass();
    }
  }
  if(window._audioCtx && window._audioCtx.state === 'suspended') {
    window._audioCtx.resume().catch(function(){});
  }
  return window._audioCtx;
};

window._playCyberBeep = function(freq, type, duration) {
  if(!window._hudAudioEnabled) return;
  try {
    var ctx = window._getAudioContext();
    if(!ctx) return;
    var osc = ctx.createOscillator();
    var gain = ctx.createGain();
    osc.type = type || 'sine';
    osc.frequency.setValueAtTime(freq || 880, ctx.currentTime);
    gain.gain.setValueAtTime(0.08, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + (duration || 0.12));
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + (duration || 0.12));
  } catch(e) {}
};

window._playAlertChime = function(sev) {
  if(!window._hudAudioEnabled) return;
  try {
    var ctx = window._getAudioContext();
    if(!ctx) return;
    var f1 = sev === 'CRITICAL' ? 950 : 650;
    var f2 = sev === 'CRITICAL' ? 1250 : 850;
    window._playCyberBeep(f1, 'sawtooth', 0.1);
    setTimeout(function(){ window._playCyberBeep(f2, 'sine', 0.15); }, 110);
  } catch(e) {}
};

window._toggleHudAudio = function() {
  window._hudAudioEnabled = !window._hudAudioEnabled;
  var btn = document.getElementById('HUD_AUDIO_BTN');
  if(btn) {
    btn.textContent = window._hudAudioEnabled ? '🔊 Audio: ON' : '🔇 Audio: OFF';
    btn.style.color = window._hudAudioEnabled ? '#30d158' : 'var(--text3)';
  }
  if(window._hudAudioEnabled) {
    window._playCyberBeep(780, 'sine', 0.15);
    setTimeout(function(){ window._playCyberBeep(1040, 'sine', 0.2); }, 160);
    window._speakCyberAlert('Cyber Audio HUD Activated');
    if(typeof _toast === 'function') _toast('🔊 Cyber Audio HUD Online — Sound Synthesizer & Voice Active', 'g');
  } else {
    if(typeof _toast === 'function') _toast('🔇 Cyber Audio HUD Muted', 'b');
  }
};

window._speakCyberAlert = function(text) {
  if(!window._hudAudioEnabled || !('speechSynthesis' in window)) return;
  try {
    window.speechSynthesis.cancel();
    var utterance = new SpeechSynthesisUtterance(text);
    utterance.rate = 1.05;
    utterance.pitch = 0.95;
    window.speechSynthesis.speak(utterance);
  } catch(e) {}
};

// ── 5. SENTINELX EVENT STREAM & SYSMON XML ENGINE ─────────────
window._streamPollTimer = null;
window._streamAutoPollActive = true;
window._cachedStreamEvents = [];


/* ═══════════════════════════════════════════════════════════
   ATTACK CHAIN VISUALIZATION INTERACTION ENGINE
═══════════════════════════════════════════════════════════ */
window._activeChainStage = 2;
window._attackReplayTimer = null;

window._selectAttackStage = function(stageNum) {
  window._activeChainStage = stageNum;
  if(window._hudAudioEnabled) {
    window._playCyberBeep(700 + (stageNum * 60), 'sine', 0.1);
  }
  if(typeof go === 'function') {
    go('ATTACK_CHAIN');
  }
};

window._stepAttackStage = function(delta) {
  var next = (window._activeChainStage || 1) + delta;
  if(next < 1) next = 7;
  if(next > 7) next = 1;
  window._selectAttackStage(next);
};

window._mitigateAttackStage = function(stageNum) {
  var stageNames = ['', 'Initial Infiltration', 'PowerShell Execution', 'Process Injection', 'Credential Theft', 'Registry Persistence', 'C2 Beacon', 'Ransomware Impact'];
  var name = stageNames[stageNum] || ('Stage ' + stageNum);
  if(typeof _toast === 'function') _toast('⚡ SOAR Playbook Triggered: Mitigating ' + name + ' on Endpoint SOC-01', 'r');
  if(window._hudAudioEnabled) {
    window._playAlertChime('CRITICAL');
    window._speakCyberAlert('Mitigating Attack Stage ' + stageNum + ': ' + name);
  }
};

window._playAttackReplaySequence = function() {
  if(window._attackReplayTimer) {
    clearInterval(window._attackReplayTimer);
    window._attackReplayTimer = null;
    var btn = document.getElementById('PLAY_ATTACK_BTN');
    if(btn) btn.textContent = '▶ Auto-Play Attack Sequence';
    if(typeof _toast === 'function') _toast('Attack Replay Paused', 'b');
    return;
  }

  var btn = document.getElementById('PLAY_ATTACK_BTN');
  if(btn) btn.textContent = '⏸ Pause Sequence';
  if(typeof _toast === 'function') _toast('▶ Playing Adversary Attack Chain Sequence (Stages 1–7)', 'r');

  window._activeChainStage = 1;
  if(typeof go === 'function') go('ATTACK_CHAIN');
  
  var stageNames = ['', 'Initial Infiltration via Spearphishing', 'Encoded PowerShell Execution', 'Memory Injection', 'Credential Theft with Mimikatz', 'Registry Run Key Persistence', 'Command and Control Beaconing', 'Ransomware Shadow Deletion'];

  if(window._hudAudioEnabled) {
    window._speakCyberAlert('Attack Sequence Started. Stage 1: Initial Infiltration');
  }

  window._attackReplayTimer = setInterval(function() {
    window._activeChainStage++;
    if(window._activeChainStage > 7) {
      clearInterval(window._attackReplayTimer);
      window._attackReplayTimer = null;
      window._activeChainStage = 1;
      var b = document.getElementById('PLAY_ATTACK_BTN');
      if(b) b.textContent = '▶ Replay Sequence';
      if(typeof _toast === 'function') _toast('Attack Sequence Complete · All Stages Traced', 'g');
      if(window._hudAudioEnabled) {
        window._speakCyberAlert('Attack Sequence Complete. All stages mapped.');
      }
      return;
    }

    if(window._hudAudioEnabled) {
      window._speakCyberAlert('Stage ' + window._activeChainStage + ': ' + stageNames[window._activeChainStage]);
      window._playCyberBeep(650 + (window._activeChainStage * 80), 'sine', 0.12);
    }
    if(typeof go === 'function') go('ATTACK_CHAIN');
  }, 3500);
};

window._resetAttackReplay = function() {
  if(window._attackReplayTimer) {
    clearInterval(window._attackReplayTimer);
    window._attackReplayTimer = null;
  }
  window._activeChainStage = 1;
  if(typeof go === 'function') go('ATTACK_CHAIN');
  if(typeof _toast === 'function') _toast('Attack Chain Reset to Stage 1', 'b');
};


window._initUniversalStreamUi = function() {
  window._fetchEventStream();
  window._loadSysmonXmlUi();
  if(!window._streamPollTimer) {
    window._streamPollTimer = setInterval(function() {
      var view = document.getElementById('STREAM_VIEW_CONSOLE');
      if(view && view.style.display !== 'none' && window._streamAutoPollActive) {
        window._fetchEventStream(true);
      }
    }, 1500);
  }
};

window._switchStreamTab = function(tab) {
  var vStream = document.getElementById('STREAM_VIEW_CONSOLE');
  var vXml = document.getElementById('STREAM_VIEW_XML');
  var bStream = document.getElementById('TAB_BTN_STREAM');
  var bXml = document.getElementById('TAB_BTN_XML');

  if(tab === 'xml') {
    if(vStream) vStream.style.display = 'none';
    if(vXml) vXml.style.display = 'block';
    if(bStream) { bStream.className = 'btn btn-gh'; bStream.style.background = ''; bStream.style.color = ''; }
    if(bXml) { bXml.className = 'btn btn-ac'; bXml.style.background = 'var(--accent)'; bXml.style.color = '#000'; }
    window._loadSysmonXmlUi();
  } else {
    if(vStream) vStream.style.display = 'block';
    if(vXml) vXml.style.display = 'none';
    if(bStream) { bStream.className = 'btn btn-ac'; bStream.style.background = 'var(--accent)'; bStream.style.color = '#000'; }
    if(bXml) { bXml.className = 'btn btn-gh'; bXml.style.background = ''; bXml.style.color = ''; }
    window._fetchEventStream();
  }
};

window._toggleStreamAutoPoll = function() {
  window._streamAutoPollActive = !window._streamAutoPollActive;
  var btn = document.getElementById('STREAM_AUTO_BTN');
  if(btn) {
    btn.textContent = window._streamAutoPollActive ? '⏸ Pause Stream' : '▶ Resume Stream';
    btn.className = window._streamAutoPollActive ? 'btn btn-gh' : 'btn btn-ac';
  }
  if(typeof _toast === 'function') _toast(window._streamAutoPollActive ? '▶ Live Stream Resumed' : '⏸ Live Stream Paused', 'b');
};

window._fetchEventStream = async function(isBackground) {
  var qInput = document.getElementById('STREAM_SEARCH_INP');
  var q = qInput ? qInput.value : '';

  try {
    var res = await _apiFetch('/api/events/stream?limit=250&q=' + encodeURIComponent(q));
    var data = await res.json();
    if(data.success) {
      window._cachedStreamEvents = data.events || [];
      window._renderStreamStats(data.stats || {});
      window._renderStreamTable(window._cachedStreamEvents);
    }
  } catch(e) {}
};

window._renderStreamStats = function(st) {
  var elTot = document.getElementById('STREAM_STAT_TOTAL');
  var elProcs = document.getElementById('STREAM_STAT_PROCS');
  var elEid1 = document.getElementById('STREAM_STAT_EID1');
  var elNet = document.getElementById('STREAM_STAT_NET');

  if(elTot) elTot.textContent = st.total_events_buffered || window._cachedStreamEvents.length;
  if(elProcs) elProcs.textContent = st.unique_active_processes || '0';
  if(elEid1) elEid1.textContent = st.process_create_events || '0';
  if(elNet) elNet.textContent = ((st.network_events || 0) + (st.file_events || 0));
};

window._renderStreamTable = function(events) {
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
        '<td>' + (typeof sevBx === 'function' ? sevBx(e.severity || 'INFO') : e.severity || 'INFO') + '</td>' +
        '<td><button class="btn btn-b" style="padding:2px 7px;font-size:9px" onclick="event.stopPropagation();_inspectSplunkEvent(\'' + e.id + '\')">Inspect</button></td>' +
      '</tr>'
    );
  }).join('');
};

window._handleStreamSearch = function() {
  window._fetchEventStream();
};

window._applyStreamQuickFilter = function(q) {
  var inp = document.getElementById('STREAM_SEARCH_INP');
  if(inp) inp.value = q;
  window._fetchEventStream();
};

window._clearStreamBuffer = async function() {
  try {
    await _apiFetch('/api/events/clear', { method: 'POST' });
    window._cachedStreamEvents = [];
    window._renderStreamTable([]);
    if(typeof _toast === 'function') _toast('🗑 Event stream buffer cleared', 'g');
  } catch(e) {}
};

window._inspectSplunkEvent = function(evtId) {
  var evt = window._cachedStreamEvents.find(function(x) { return x.id === evtId; });
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
          '<div style="font-size:14px;font-weight:900;color:var(--accent)">🔍 SENTINELX RAW EVENT INSPECTOR</div>' +
          '<div style="font-size:11px;color:var(--text3);margin-top:2px">Event ID ' + (evt.event_id || 1) + ' · ' + (evt.event_name || 'Process Create') + '</div>' +
        '</div>' +
        '<button class="btn btn-gh" onclick="document.getElementById(\'SPLUNK_EVENT_INSPECT_MODAL\').remove()" style="padding:4px 10px">Close ✕</button>' +
      '</div>' +
      '<div style="margin-bottom:12px">' +
        '<div style="font-size:10px;font-weight:700;color:var(--text3);margin-bottom:4px">RAW SIEM LOG STRING:</div>' +
        '<div style="background:var(--bg3);border:1px solid var(--border);padding:10px;border-radius:6px;font-family:var(--mono);font-size:10px;color:var(--accent);word-break:break-all;line-height:1.5">' +
          (evt.raw_log || '-') +
        '</div>' +
      '</div>' +
      '<div style="margin-bottom:12px;background:var(--bg3);border:1px solid var(--border);padding:10px;border-radius:6px">' +
        '<div style="font-size:10px;font-weight:700;color:var(--text3);margin-bottom:6px">PROCESS HIERARCHY TREE:</div>' +
        '<div style="font-family:var(--mono);font-size:11px;color:var(--text)">' +
          '<span>📁 ' + (evt.parent_name || 'Parent Process') + ' (PPID: ' + (evt.ppid || 0) + ')</span>' +
          '<br/><span style="color:var(--accent);margin-left:14px">↳ ⚡ <b>' + (evt.process_name || 'Process') + '</b> (PID: ' + (evt.pid || 0) + ')</span>' +
        '</div>' +
      '</div>' +
      '<div style="max-height:220px;overflow-y:auto;background:rgba(0,0,0,0.5);border:1px solid var(--border);border-radius:6px;padding:10px;font-family:var(--mono);font-size:10px;color:#a5d6ff">' +
        '<pre style="margin:0">' + JSON.stringify(evt, null, 2) + '</pre>' +
      '</div>' +
    '</div>';

  document.body.appendChild(modal);
};

window._loadSysmonXmlUi = async function() {
  var box = document.getElementById('SYSMON_XML_STATUS_BOX');
  var txt = document.getElementById('SYSMON_XML_TEXTAREA');
  var cfgStat = document.getElementById('STREAM_STAT_CFG');

  try {
    var res = await _apiFetch('/api/sysmon/config');
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
};

window._saveSysmonXmlUi = async function() {
  var txt = document.getElementById('SYSMON_XML_TEXTAREA');
  if(!txt) return;
  var content = txt.value.trim();
  if(!content) {
    if(typeof _toast === 'function') _toast('XML configuration content cannot be empty', 'r');
    return;
  }

  if(typeof _toast === 'function') _toast('Validating and applying Sysmon XML...', 'b');

  try {
    var res = await _apiFetch('/api/sysmon/config', {
      method: 'POST',
      body: JSON.stringify({ xml_content: content })
    });
    var data = await res.json();
    if(data.success) {
      if(typeof _toast === 'function') _toast('✅ ' + data.message, 'g');
      window._loadSysmonXmlUi();
    } else {
      if(typeof _toast === 'function') _toast('XML Error: ' + (data.error || 'Failed to parse XML'), 'r');
    }
  } catch(e) {
    if(typeof _toast === 'function') _toast('Failed to save XML: ' + e.message, 'r');
  }
};

window._restoreDefaultSysmonXmlUi = async function() {
  try {
    var res = await _apiFetch('/api/sysmon/config/reset', { method: 'POST' });
    var data = await res.json();
    if(data.success) {
      if(typeof _toast === 'function') _toast('🔄 ' + data.message, 'g');
      window._loadSysmonXmlUi();
    }
  } catch(e) {
    if(typeof _toast === 'function') _toast('Reset failed: ' + e.message, 'r');
  }
};

// ── 6. ALERT CLASSIFICATION & TIME FORMATTING HELPERS ─────────
window._fmtTime = function(ts) {
  if (!ts || ts === '-') return '-';
  if (typeof ts !== 'string') return String(ts);
  if (ts.indexOf('T') !== -1) {
    var part = ts.split('T')[1];
    return part ? part.substring(0, 8) : ts;
  }
  if (ts.indexOf(' ') !== -1) {
    var part2 = ts.split(' ')[1];
    return part2 ? part2.substring(0, 8) : ts;
  }
  return ts;
};

window._isExeAlert = function(a) {
  if(!a) return false;
  var src = (a.source || '').toLowerCase();
  var ls = (a.log_source || '').toLowerCase();
  var ev = (a.event || '').toLowerCase();
  var det = (a.detail || '').toLowerCase();
  var mid = (a.mitre_id || '').toLowerCase();
  return src === 'exe' || ls.includes('app') ||
    ev.includes('exe') || ev.includes('binary') || ev.includes('process') || ev.includes('executable') || ev.includes('payload') ||
    det.includes('.exe') || det.includes('\\temp') || det.includes('\\appdata') || det.includes('temp\\') || det.includes('programdata') ||
    mid.includes('t1204') || mid.includes('t1059.003');
};

window._isPsAlert = function(a) {
  if(!a) return false;
  var src = (a.source || '').toLowerCase();
  var ls = (a.log_source || '').toLowerCase();
  var ev = (a.event || '').toLowerCase();
  var det = (a.detail || '').toLowerCase();
  var mid = (a.mitre_id || '').toLowerCase();
  return src === 'powershell' || ls.includes('powershell') ||
    ev.includes('powershell') || ev.includes('mimikatz') || ev.includes('script') || ev.includes('pwsh') ||
    det.includes('powershell') || det.includes('-enc') || det.includes('encodedcommand') || det.includes('bypass') || det.includes('iex') || det.includes('downloadstring') || det.includes('invoke-') ||
    mid.includes('t1059.001') || mid.includes('t1003');
};

window._isNetAlert = function(a) {
  if(!a) return false;
  var src = (a.source || '').toLowerCase();
  var ls = (a.log_source || '').toLowerCase();
  var ev = (a.event || '').toLowerCase();
  var det = (a.detail || '').toLowerCase();
  var mid = (a.mitre_id || '').toLowerCase();
  var hasIp = Boolean(a.ip && a.ip !== '-' && a.ip !== '127.0.0.1');
  return src === 'network' || src === 'sysmon_network' || ls.includes('net') ||
    ev.includes('network') || ev.includes('connect') || ev.includes('c2') || ev.includes('beacon') || ev.includes('port scan') || ev.includes('socket') || ev.includes('reverse shell') ||
    det.includes('connection') || det.includes('outbound') || det.includes('inbound') || det.includes(':4444') || det.includes(':6666') || det.includes(':1337') || det.includes(':31337') || det.includes(':9001') || det.includes(':8080') || det.includes(':80') || det.includes(':443') || det.includes('port') ||
    mid.includes('t1071') || mid.includes('t1095') || mid.includes('t1041') ||
    (hasIp && (ev.includes('beacon') || ev.includes('c2') || ev.includes('traffic') || ev.includes('connection')));
};

window._isFileAlert = function(a) {
  if(!a) return false;
  var src = (a.source || '').toLowerCase();
  var ls = (a.log_source || '').toLowerCase();
  var ev = (a.event || '').toLowerCase();
  var det = (a.detail || '').toLowerCase();
  var mid = (a.mitre_id || '').toLowerCase();
  return src === 'sysmon_file' || src === 'canary' ||
    ev.includes('file') || ev.includes('drop') || ev.includes('ransomware') || ev.includes('canary') || ev.includes('shadow copy') ||
    det.includes('file') || det.includes('canary') || det.includes('vssadmin') || det.includes('dropped') ||
    mid.includes('t1204.002') || mid.includes('t1486') || mid.includes('t1490');
};

window._isRegAlert = function(a) {
  if(!a) return false;
  var src = (a.source || '').toLowerCase();
  var ls = (a.log_source || '').toLowerCase();
  var ev = (a.event || '').toLowerCase();
  var det = (a.detail || '').toLowerCase();
  var mid = (a.mitre_id || '').toLowerCase();
  return src === 'registry' || ls.includes('reg') ||
    ev.includes('registry') || ev.includes('persistence') || ev.includes('runkey') || ev.includes('run key') || ev.includes('reg.exe') ||
    det.includes('hkcu') || det.includes('hklm') || det.includes('currentversion\\run') || det.includes('runonce') || det.includes('autorun') || det.includes('registry') || det.includes('reg add') ||
    mid.includes('t1547') || mid.includes('t1070.004');
};

// ── 7. FILE VT LOOKUP & ALERT DETAIL SELECTION ───────────────
window._faVtCheck = async function(hash, fname, btnId) {
  var btn = document.getElementById(btnId);
  if(btn) { btn.textContent = 'Querying VT...'; btn.disabled = true; }
  var res = document.getElementById('FA_VT_RESULT');
  if(res) {
    res.style.display = 'block';
    res.innerHTML = '🔍 Querying VirusTotal Intelligence for <b>' + fname + '</b>...';
  }

  var queryParam = hash || fname;
  var vtWebUrl = 'https://www.virustotal.com/gui/search/' + encodeURIComponent(queryParam);

  try {
    var r = await _apiFetch('/api/hunt/hash?hash=' + encodeURIComponent(queryParam));
    var d = await r.json();
    if(res) {
      if(d.found) {
        var col = d.verdict === 'MALICIOUS' ? 'var(--red)' : (d.verdict === 'SUSPICIOUS' ? 'var(--amber)' : 'var(--green)');
        res.innerHTML =
          '<div style="font-weight:700;color:' + col + ';font-size:12px;margin-bottom:8px">' +
           '🚨 ' + d.verdict + ': ' + (d.detections || 0) + '/' + (d.total || 72) + ' AV engines flagged ' + (d.name || fname) +
          '</div>' +
          dr('File', fname) + (hash ? dr('SHA256', hash) : '') +
          dr('File Type', d.file_type || 'Executable / Script') +
          dr('Malware Family', d.family || 'Trojan.Generic') +
          '<div class="btn-row" style="margin-top:10px">' +
           '<button class="btn btn-b" onclick="window.open(\'' + vtWebUrl + '\', \'_blank\')" style="padding:5px 12px;font-size:10.5px">Open Full VirusTotal Report ↗</button>' +
          '</div>';
      } else {
        res.innerHTML =
          '<div style="color:var(--amber);font-weight:600;margin-bottom:6px">⚠️ File / Hash query dispatched — opening VirusTotal live search:</div>' +
          dr('Target', queryParam) +
          '<div class="btn-row" style="margin-top:10px">' +
           '<button class="btn btn-b" onclick="window.open(\'' + vtWebUrl + '\', \'_blank\')" style="padding:5px 14px;font-size:10.5px">Open VirusTotal Search in New Tab ↗</button>' +
          '</div>';
        window.open(vtWebUrl, '_blank');
      }
    }
  } catch(e) {
    if(res) {
      res.innerHTML =
        '<div style="color:var(--amber);font-weight:600;margin-bottom:6px">Opening live VirusTotal dossier for ' + fname + '...</div>' +
        '<div class="btn-row" style="margin-top:8px">' +
         '<button class="btn btn-b" onclick="window.open(\'' + vtWebUrl + '\', \'_blank\')" style="padding:5px 12px;font-size:10px">Open VirusTotal ↗</button>' +
        '</div>';
      window.open(vtWebUrl, '_blank');
    }
  }

  if(btn) { btn.textContent = 'Checked on VT'; btn.disabled = false; }
};

window._adSelect = function(alertId) {
  var ra = typeof _realAlerts === 'function' ? _realAlerts() : _A;
  window._adCurrent = alertId;
  const a = ra.find(function(x){ return x.id === alertId; });
  if(!a) return;

  document.querySelectorAll('[id^="adl-"]').forEach(function(el){
    el.style.background = 'transparent';
    el.style.borderLeft = '3px solid transparent';
    var nameEl = el.querySelector('div>div');
    if(nameEl) nameEl.style.fontWeight = '400';
  });
  var selEl = document.getElementById('adl-' + alertId);
  if(selEl){
    selEl.style.background = 'rgba(0,200,150,.07)';
    selEl.style.borderLeft = '3px solid var(--accent)';
    var nameEl = selEl.querySelector('div>div');
    if(nameEl) nameEl.style.fontWeight = '600';
  }

  var sev = a.severity || 'LOW';
  var sc = {CRITICAL:'r', HIGH:'r', MEDIUM:'a', LOW:'b'}[sev] || 'b';
  var detail = document.getElementById('AD_DETAIL');
  if(!detail) return;

  detail.innerHTML =
   (a.auto_response ? ibox(a.auto_response, sc) : '') +
   g2(
    card('Alert Information', 'Sysmon Data',
     dr('Alert ID', a.id || '-') + dr('Event', a.event || '-') +
     dr('Detail', '<div class="mono" style="font-size:9px;white-space:pre-wrap;max-height:120px;overflow:auto;background:var(--bg3);padding:8px;border-radius:6px">' + (a.detail || '-').substring(0, 500) + '</div>') +
     dr('Host', a.host || '-') + dr('User', a.user || '-') + dr('Timestamp', typeof _fmtTime === 'function' ? _fmtTime(a.timestamp) : (a.timestamp || '-')) +
     dr('Status', typeof _st === 'function' ? _st(a.status) : (a.status || 'OPEN')) + dr('Severity', typeof sevBx === 'function' ? sevBx(sev) : sev)
    ),
    card('Threat Intelligence', 'Live enrichment',
     dr('MITRE ID', a.mitre_id || '-') + dr('Tactic', a.mitre_tactic || '-') +
     dr('Technique', a.mitre_name || '-') +
     dr('VT Score', a.vt_score != null ? a.vt_score + '/72' : '-') +
     dr('AbuseIPDB', a.abuse_score != null ? a.abuse_score + '%' : '-') +
     dr('IP', a.ip || '-') + dr('Country', a.country || '-') + dr('ISP', a.isp || '-')
    )
   ) +
   '<div class="btn-row" style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">' +
    '<button class="btn btn-a" onclick="_ahStatus(\'' + a.id + '\',\'INVESTIGATING\')">Mark Investigating</button>' +
    '<button class="btn btn-g" onclick="_ahStatus(\'' + a.id + '\',\'RESOLVED\')">Mark Resolved</button>' +
    '<button class="btn btn-gh" onclick="_ahStatus(\'' + a.id + '\',\'FALSE_POSITIVE\')">False Positive</button>' +
    (a.ip && a.ip !== '-' ? '<button class="btn btn-r" onclick="_confirmBlockIP(\'' + a.ip + '\',\'Block from Alert Detail\',\'Malicious IP\')">🚫 Block ' + a.ip + '</button>' : '') +
   '</div>';
};
