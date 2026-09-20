/* wifipilot web UI — vanilla JS, no build step.
 *
 * The server owns all state; this file is a thin renderer over two inputs:
 *   - "state" messages (full snapshot, sent every ~3s and on connect)
 *   - "event" messages (live bus events: scans, attacks, cracks, advisor tokens)
 * Everything is rendered from the snapshot, so the UI can never drift from
 * what the engine actually did.
 */
'use strict';

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

let SNAPSHOT = null;
let EVENT_QUEUE = [];
let renderTimer = null;
let ws = null;
let reconnectDelay = 1000;
let chatStreaming = null;

/* ------------------------------------------------------------------ ws */
function connect() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${proto}://${location.host}/ws`);
  ws.onopen = () => {
    setConn('connected', 'badge-conn');
    reconnectDelay = 1000;
  };
  ws.onclose = () => {
    setConn('offline — retrying', 'badge-lost');
    setTimeout(connect, reconnectDelay);
    reconnectDelay = Math.min(reconnectDelay * 1.7, 15000);
  };
  ws.onerror = () => setConn('error', 'badge-lost');
  ws.onmessage = (message) => {
    let payload;
    try { payload = JSON.parse(message.data); } catch (e) { return; }
    if (payload.kind === 'state') {
      SNAPSHOT = payload.data;
      scheduleRender();
    } else if (payload.kind === 'event') {
      EVENT_QUEUE.push(payload.event);
      handleEvent(payload.event);
    }
  };
}

function setConn(text, cls) {
  const badge = $('#conn-badge');
  badge.textContent = text;
  badge.className = 'badge ' + cls;
}

function api(path, body, method) {
  return fetch(path, {
    method: method || (body ? 'POST' : 'GET'),
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  }).then(async (response) => {
    const text = await response.text();
    let data = {};
    try { data = text ? JSON.parse(text) : {}; } catch (e) { data = { detail: text }; }
    if (!response.ok) {
      toast(`⚠ ${data.detail || response.statusText}`, true);
      throw new Error(data.detail || response.statusText);
    }
    if (data.message) toast(data.message);
    return data;
  }).catch((error) => { console.error(path, error); return null; });
}

function toast(text, bad) {
  const el = $('#toast');
  el.textContent = text;
  el.style.borderColor = bad ? 'var(--bad)' : 'var(--accent)';
  el.classList.remove('hidden');
  clearTimeout(el._timer);
  el._timer = setTimeout(() => el.classList.add('hidden'), 4200);
}

/* -------------------------------------------------------------- events */
function handleEvent(event) {
  const kind = event.kind || '';
  const d = event.data || {};
  if (kind === 'advisor.token') {
    appendChatToken(d.piece || '');
    return;
  }
  if (kind === 'advisor.plan') {
    renderPlan(d);
    return;
  }
  if (kind === 'advisor.chat') {
    appendChat(d.role === 'user' ? 'user' : 'assistant', d.message, d.kind === 'triage');
    return;
  }
  if (kind === 'log' || kind === 'warning' || kind === 'error' || kind === 'ap.new') {
    appendLog(event);
  }
  if (kind === 'state' || kind.endsWith('.plan') || kind === 'capture.new') scheduleRender();
}

function appendLog(event) {
  const d = event.data || {};
  const level = (d.level || event.kind || 'info').replace('log', 'info');
  const stream = $('#log-stream');
  const atBottom = stream.scrollTop + stream.clientHeight >= stream.scrollHeight - 30;
  const line = document.createElement('div');
  const text = d.message || d.essid || d.bssid || JSON.stringify(d);
  line.innerHTML = `<span class="t">${event.time || ''}</span> <span class="${level}">${escapeHtml(text)}</span>`;
  stream.appendChild(line);
  while (stream.childElementCount > 800) stream.removeChild(stream.firstChild);
  if (atBottom) stream.scrollTop = stream.scrollHeight;
}

function escapeHtml(text) {
  return String(text == null ? '' : text).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

/* ------------------------------------------------------------ rendering */
function scheduleRender() {
  if (renderTimer) return;
  renderTimer = setTimeout(() => { renderTimer = null; render(); }, 250);
}

function render() {
  if (!SNAPSHOT) return;
  renderHeader(SNAPSHOT);
  renderTargets(SNAPSHOT);
  renderLoot(SNAPSHOT);
  renderAdvisor(SNAPSHOT);
  renderProgress(SNAPSHOT);
  renderSettings(SNAPSHOT);
}

function renderHeader(state) {
  const session = state.session || {};
  const stats = state.stats || {};
  const engine = state.engine || {};
  $('#kpi-aps').textContent = (state.access_points || []).length;
  $('#kpi-clients').textContent = stats.clients_seen || 0;
  $('#kpi-loot').textContent = stats.loot || 0;
  $('#kpi-pswd').textContent = stats.passwords || 0;
  $('#kpi-uptime').textContent = session.uptime_h || '0s';

  const mode = $('#mode-badge');
  mode.textContent = session.demo ? 'simulation' : (session.authorized ? 'live · authorised' : 'live');
  mode.className = 'badge ' + (session.demo ? 'badge-demo' : 'badge-live');

  const phase = $('#phase-badge');
  phase.textContent = engine.phase || 'idle';
  phase.className = 'badge ' + (['attacking', 'cracking', 'scanning'].includes(engine.phase) ? 'badge-run' : 'badge-idle');

  $('#btn-campaign').disabled = !!engine.campaign_running;
  $('#btn-stop').disabled = !engine.campaign_running;
  $('#chk-demo').checked = !!session.demo;
  $('#chk-authorized').checked = !!session.authorized;
  $('#chk-autothink').checked = !!session.auto_think;
  $('#chk-stealth').checked = !!session.stealth;
  $('#tab-count-targets').textContent = (state.access_points || []).length;
  $('#tab-count-loot').textContent = (state.loot || []).length;
  $('#hint-targets').textContent = engine.current_job ? `engine: ${engine.current_job}` : (engine.detail || '');
  $('#paths').textContent = session.state_dir ? ` · session: ${session.state_dir}` : '';
}

function sigClass(signal) {
  if (signal >= -60) return 'sig-good';
  if (signal >= -75) return 'sig-mid';
  return 'sig-bad';
}

function securityTag(ap) {
  const map = { WEP: 'tag-wep', WPA2: 'tag-wpa2', WPA: 'tag-wpa2', 'WPA2/WPA3': 'tag-wpa3', WPA3: 'tag-wpa3', OPEN: 'tag-open', OWE: 'tag-open' };
  return `<span class="tag ${map[ap.encryption] || ''}">${escapeHtml(ap.security || ap.encryption)}</span>`;
}

function lootTags(ap) {
  const bits = [];
  if (ap.handshake) bits.push('<span class="tag tag-ok">HS</span>');
  if (ap.pmkid) bits.push('<span class="tag tag-ok">PMKID</span>');
  if (ap.cracked) bits.push(`<span class="tag tag-wep" title="${escapeHtml(ap.password)}">PSK ★</span>`);
  return bits.join(' ') || '<span class="dim">—</span>';
}

function renderTargets(state) {
  const filter = ($('#inp-filter').value || '').toLowerCase();
  const body = $('#tbl-targets tbody');
  const rows = (state.access_points || []).filter((ap) => {
    if (!filter) return true;
    return [ap.essid, ap.bssid, ap.vendor, ap.encryption].join(' ').toLowerCase().includes(filter);
  });
  body.innerHTML = rows.map((ap) => {
    const attacks = (ap.attacks || []);
    const options = ['', ...attacks].map((a) => `<option value="${a}">${a || 'auto'}</option>`).join('');
    const decided = ap.picked_by === 'llm'
      ? '<span class="tag tag-ai">AI</span>'
      : (ap.picked_by ? `<span class="tag">${escapeHtml(ap.picked_by)}</span>` : '');
    const wps = ap.wps
      ? `<span class="tag tag-wps">WPS ${escapeHtml(ap.wps_locked || '?')}</span>`
      : '<span class="dim">no</span>';
    return `<tr data-bssid="${ap.bssid}">
      <td><button class="chip" data-detail="${ap.bssid}">＋</button></td>
      <td class="essid">${escapeHtml(ap.display_name)}${ap.hidden ? ' <span class="dim">(hidden)</span>' : ''}</td>
      <td class="mono">${ap.bssid}</td>
      <td>${ap.channel || '?'}</td>
      <td class="dim">${escapeHtml(ap.band || '')}</td>
      <td class="sig ${sigClass(ap.signal)}">${ap.signal} dBm</td>
      <td>${securityTag(ap)}</td>
      <td>${wps}</td>
      <td>${ap.clients}</td>
      <td>${lootTags(ap)}</td>
      <td title="${escapeHtml(ap.pick_reason || '')}">${(ap.score || 0).toFixed(1)}</td>
      <td>${decided}</td>
      <td>
        <select data-attack-select="${ap.bssid}">${options}</select>
        <button class="chip" data-attack="${ap.bssid}">▶ run</button>
        <button class="chip" data-crack="${ap.bssid}">🔓 crack</button>
      </td>
    </tr>`;
  }).join('') || '<tr><td colspan="13" class="dim">No access points yet — start a campaign or a rescan.</td></tr>';
}

function renderLoot(state) {
  const grid = $('#loot-grid');
  const loot = state.loot || [];
  grid.innerHTML = loot.map((cap) => `
    <div class="card loot-card ${cap.password ? 'cracked' : ''}">
      <h3>${escapeHtml(cap.essid || cap.bssid)}
        <span class="tag tag-ok">${escapeHtml(cap.kind)}</span></h3>
      <div class="kv">
        <b>BSSID</b><span class="mono">${cap.bssid}</span>
        <b>tool</b><span>${escapeHtml(cap.tool || '—')}</span>
        <b>file</b><span class="mono dim">${escapeHtml((cap.path || '').split('/').pop() || '—')}</span>
        ${cap.eapol ? `<b>EAPOL</b><span>${cap.eapol} message(s)</span>` : ''}
        ${cap.password ? `<b>PSK</b><span class="pw">${escapeHtml(cap.password)}</span>` : ''}
      </div>
      <div class="row">
        ${cap.password ? '' : `<button class="chip" data-crack="${cap.bssid}">🔓 crack now</button>`}
        ${cap.path ? `<a class="chip" href="/api/file?path=${encodeURIComponent(cap.path)}" target="_blank" rel="noopener">⤓ download</a>` : ''}
      </div>
    </div>`).join('') || '<div class="card dim">Nothing captured yet. Handshakes, PMKIDs and cracked PSKs appear here as soon as they land.</div>';
}

function renderAdvisor(state) {
  const ai = state.advisor || {};
  const rows = [
    ['Ollama', ai.available ? `<span class="ok">online</span> (${escapeHtml(ai.host || '')})` : `<span class="dim">offline${ai.last_error ? ' — ' + escapeHtml(ai.last_error) : ''}</span>`],
    ['model', escapeHtml(ai.model || '—')],
    ['auto-think', (state.session || {}).auto_think ? 'enabled' : 'disabled'],
    ['plans', `${ai.plan_count || 0} by model · ${ai.fallback_count || 0} by heuristics`],
    ['calls / errors', `${ai.calls || 0} / ${ai.errors || 0}`],
    ['avg latency', ai.avg_latency ? `${ai.avg_latency}s` : '—'],
    ['tokens used', (state.stats || {}).llm_tokens || 0],
  ];
  $('#ai-status').innerHTML = rows.map(([k, v]) => `<b>${k}</b><span>${v}</span>`).join('');

  const select = $('#sel-model');
  const current = ai.model || '';
  const models = (ai.models || []).map((m) => `<option value="${escapeHtml(m.name)}" ${m.name === current ? 'selected' : ''}>${escapeHtml(m.name)} (${m.size_gb} GB)</option>`);
  select.innerHTML = models.join('') || '<option value="">no models installed</option>';

  if (ai.last_plan) renderPlan(ai.last_plan);
}

function renderPlan(plan) {
  const badge = $('#plan-source');
  const source = plan.source === 'llm' ? `AI · ${plan.model || ''}` : 'deterministic planner';
  badge.textContent = source;
  badge.className = 'badge ' + (plan.source === 'llm' ? 'badge-llm' : 'badge-heur');
  $('#plan-reasoning').textContent = plan.reasoning || '(no reasoning provided)';
  $('#plan-actions').innerHTML = (plan.actions || []).map((a) => `
    <li><b>${escapeHtml(a.attack)}</b> → <span class="mono">${escapeHtml(a.bssid)}</span>
      ${a.reason ? `<span class="dim"> — ${escapeHtml(a.reason)}</span>` : ''}</li>`).join('')
    || '<li class="dim">no actions proposed</li>';
  const dropped = plan.dropped || [];
  $('#plan-dropped').innerHTML = dropped.length
    ? `⚠ rejected by the safety validator: ${dropped.map(escapeHtml).join('; ')}`
    : '';
}

function renderProgress(state) {
  const progress = state.progress || {};
  const percent = progress.active ? Math.max(2, Math.min(100, progress.percent || 0)) : 0;
  $('#progress-bar').style.width = `${percent}%`;
  $('#progress-label').textContent = progress.active
    ? `${progress.label} · ${percent.toFixed(0)}% · ${progress.speed || ''} ${progress.detail || ''}`
    : (state.engine && state.engine.detail) || 'idle';
}

function renderSettings(state) {
  const tools = state.tools || {};
  const list = Object.values(tools.tools || {});
  $('#tbl-tools tbody').innerHTML = list.map((t) => `
    <tr>
      <td class="mono">${escapeHtml(t.name)}</td>
      <td class="dim">${escapeHtml(t.purpose || '')}</td>
      <td>${t.available ? '<span class="tag tag-ok">ready</span>' : '<span class="tag tag-wep">missing</span>'}</td>
      <td class="dim">${escapeHtml(t.version || '—')}</td>
      <td class="dim mono">${escapeHtml(t.install || '')}</td>
    </tr>`).join('');
  const caps = tools.capabilities || {};
  const missing = tools.missing_required || [];
  $('#tool-summary').textContent = missing.length
    ? `missing required: ${missing.join(', ')} — live attacks will fail`
    : `capabilities: ${Object.entries(caps).filter(([, v]) => v).map(([k]) => k).join(', ')}`;

  $('#iface-list').innerHTML = (tools.interfaces || []).map((i) => `
    <b>${escapeHtml(i.name)}</b>
    <span>${escapeHtml(i.driver || '?')} · ${(i.bands || []).join('/') || '?'} ·
      monitor ${i.monitor ? '✅' : '❌'} · injection ${i.injection ? '✅' : '❔'}</span>`).join('')
    || '<b>none</b><span class="dim">no wireless interfaces detected (simulation mode still works)</span>';

  const config = (state.config || {});
  const session = state.session || {};
  $('#settings-kv').innerHTML = [
    ['attacks', (config.attacks || []).join(', ')],
    ['band', config.band || 'both'],
    ['channel hop', config.channel_hop ? 'on' : 'off'],
    ['scan time', `${config.scan_time || 30}s`],
    ['handshake budget', `${config.handshake_timeout || 90}s`],
    ['pmkid budget', `${config.pmkid_timeout || 60}s`],
    ['wps budget', `${config.wps_timeout || 300}s`],
    ['crack budget', `${config.crack_timeout || 600}s`],
    ['cracker', config.cracker || 'auto'],
    ['loot dir', session.output_dir || config.output_dir || 'loot'],
  ].map(([k, v]) => `<b>${k}</b><span>${escapeHtml(String(v))}</span>`).join('');

  const attacks = state.attacks || [];
  $('#attack-toggles').innerHTML = attacks.map((a) => `
    <button class="chip ${a.enabled ? 'on' : ''}" data-toggle-attack="${a.name}"
      title="${escapeHtml(a.description)}">${escapeHtml(a.label)}${a.available ? '' : ' (unavailable)'}</button>`).join('');

  $('#wordlists').innerHTML = (state.wordlists || []).map((w) => `
    <span class="chip" title="${escapeHtml(w.path)}">${escapeHtml(w.name)}${w.builtin ? ' · bundled' : ''}</span>`).join('')
    || '<span class="dim">no wordlists found</span>';
}

/* ---------------------------------------------------------------- chat */
function appendChat(role, message, triage) {
  const log = $('#chat-log');
  const div = document.createElement('div');
  div.className = 'msg ' + (role === 'user' ? 'user' : (triage ? 'sys' : 'assistant'));
  div.textContent = (triage ? '⚕ ' : '') + (message || '');
  if (chatStreaming && role === 'assistant') {
    chatStreaming.replaceWith(div);
    chatStreaming = null;
  } else {
    log.appendChild(div);
  }
  log.scrollTop = log.scrollHeight;
}

function appendChatToken(piece) {
  const log = $('#chat-log');
  if (!chatStreaming) {
    chatStreaming = document.createElement('div');
    chatStreaming.className = 'msg assistant';
    log.appendChild(chatStreaming);
  }
  chatStreaming.textContent += piece;
  log.scrollTop = log.scrollHeight;
}

/* ------------------------------------------------------------- actions */
function wire() {
  $$('.tab').forEach((tab) => tab.onclick = () => {
    $$('.tab').forEach((t) => t.classList.remove('active'));
    $$('.tabpane').forEach((p) => p.classList.remove('active'));
    tab.classList.add('active');
    $('#tab-' + tab.dataset.tab).classList.add('active');
  });

  $('#btn-campaign').onclick = () => api('/api/campaign', {
    targets: $('#inp-targets').value,
    duration: parseDuration($('#inp-duration').value),
    scan_first: $('#chk-scanfirst').checked,
    action: 'start',
  });
  $('#btn-stop').onclick = () => api('/api/campaign', { action: 'stop' });
  $('#btn-cancel').onclick = () => api('/api/cancel', {});
  $('#btn-rescan').onclick = () => api('/api/rescan', { seconds: 20 });
  $('#btn-think').onclick = () => api('/api/ai/think', {}).then((r) => r && r.plan && renderPlan(r.plan));
  $('#btn-recheck').onclick = () => fetch('/api/tools?force=true').then((r) => r.json()).then(() => api('/api/state', null, 'GET'));
  $('#btn-model').onclick = () => api('/api/ai/model', { model: $('#sel-model').value });
  $('#btn-pull').onclick = () => api('/api/ai/pull', { model: $('#inp-pull').value });
  $('#btn-chat').onclick = sendChat;
  $('#inp-chat').onkeydown = (e) => { if (e.key === 'Enter') sendChat(); };
  $$('.chip[data-q]').forEach((chip) => chip.onclick = () => {
    $('#inp-chat').value = chip.dataset.q;
    sendChat();
  });

  $('#chk-autothink').onchange = (e) => api('/api/ai/toggle', { autothink: e.target.checked });
  $('#chk-stealth').onchange = (e) => api('/api/config', { stealth: e.target.checked });
  $('#chk-demo').onchange = (e) => switchMode(e.target.checked);
  $('#chk-authorized').onchange = () => { if ($('#chk-authorized').checked) api('/api/config', { authorized: true }); };
  $('#inp-filter').oninput = () => SNAPSHOT && renderTargets(SNAPSHOT);

  document.body.addEventListener('click', (event) => {
    const target = event.target.closest('[data-attack],[data-crack],[data-detail],[data-toggle-attack]');
    if (!target) return;
    if (target.dataset.attack) {
      const select = document.querySelector(`select[data-attack-select="${target.dataset.attack}"]`);
      api('/api/attack', { bssid: target.dataset.attack, attack: select ? select.value : '' });
    } else if (target.dataset.crack) {
      api('/api/crack', { bssid: target.dataset.crack });
    } else if (target.dataset.detail) {
      showDetail(target.dataset.detail);
    } else if (target.dataset.toggleAttack) {
      toggleAttack(target.dataset.toggleAttack);
    }
  });

  connect();
  setInterval(() => ws && ws.readyState === 1 && !SNAPSHOT && api('/api/state', null, 'GET'), 5000);
}

function switchMode(demo) {
  api('/api/mode', { demo, authorized: $('#chk-authorized').checked }).then((result) => {
    if (!result) { $('#chk-demo').checked = !demo; return; }
    toast(demo ? 'simulation mode: the full pipeline runs against a fake neighbourhood'
               : 'live mode armed — make sure you are authorised');
    SNAPSHOT = null;
    api('/api/state', null, 'GET').then((state) => { if (state && state.session) { SNAPSHOT = state; render(); } });
  });
}

function toggleAttack(name) {
  if (!SNAPSHOT) return;
  const attacks = (SNAPSHOT.attacks || []).map((a) => a.name);
  const enabled = new Set((SNAPSHOT.config && SNAPSHOT.config.attacks) || []);
  if (enabled.has(name)) enabled.delete(name); else enabled.add(name);
  const ordered = attacks.filter((a) => enabled.has(a));
  api('/api/config', { attacks: ordered });
}

function showDetail(bssid) {
  const ap = (SNAPSHOT && SNAPSHOT.access_points || []).find((a) => a.bssid === bssid);
  const panel = $('#detail-panel');
  if (!ap) { return; }
  api('/api/state?detail=' + encodeURIComponent(bssid), null, 'GET').then((state) => {
    const detail = state && state.detail;
    if (!detail) return;
    const clients = (detail.clients_list || []).map((c) =>
      `<li><span class="mono">${c.mac}</span> · ${c.signal} dBm · ${c.packets} frames${c.handshake ? ' · <span class="ok">handshake</span>' : ''}</li>`).join('');
    const attempts = (detail.attempts || []).map((a) =>
      `<li><b>${escapeHtml(a.attack)}</b> — ${escapeHtml(a.status)} · ${a.duration}s · ${escapeHtml(a.result || '')}
        <span class="dim">${escapeHtml((a.detail || '').slice(0, 160))}</span></li>`).join('');
    panel.innerHTML = `
      <div class="card">
        <h3>${escapeHtml(detail.display_name)} <span class="dim mono">${detail.bssid}</span></h3>
        <div class="kv">
          <b>security</b><span>${escapeHtml(detail.security)} / ${escapeHtml(detail.cipher)} / ${escapeHtml(detail.auth)}</span>
          <b>channel</b><span>${detail.channel} (${escapeHtml(detail.band || '?')})</span>
          <b>signal</b><span>${detail.signal} dBm (${detail.quality}%)</span>
          <b>vendor</b><span>${escapeHtml(detail.vendor || 'unknown')}</span>
          <b>WPS</b><span>${detail.wps ? escapeHtml(detail.wps_locked || 'unknown') + (detail.wps_model ? ' · ' + escapeHtml(detail.wps_model) : '') : 'no'}</span>
          <b>PMF/SAE</b><span>${detail.sae ? 'SAE ' : ''}${detail.pmf ? 'PMF' : '—'}</span>
          <b>deauths sent</b><span>${detail.deauths_sent}</span>
          <b>AI notes</b><span>${escapeHtml(detail.pick_reason || '—')}</span>
        </div>
        <h4>Clients</h4><ul class="actions">${clients || '<li class="dim">none seen</li>'}</ul>
        <h4>Attack history</h4><ul class="actions">${attempts || '<li class="dim">no attempts yet</li>'}</ul>
      </div>`;
    panel.classList.remove('hidden');
    panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  });
}

function sendChat() {
  const input = $('#inp-chat');
  const message = input.value.trim();
  if (!message) return;
  appendChat('user', message);
  input.value = '';
  api('/api/ai/chat', { message });
}

function parseDuration(text) {
  if (!text) return 0;
  const match = String(text).trim().match(/^(\d+(?:\.\d+)?)\s*([smhd]?)$/i);
  if (!match) return 0;
  const value = parseFloat(match[1]);
  return value * ({ s: 1, m: 60, h: 3600, d: 86400 }[(match[2] || 's').toLowerCase()] || 1);
}

wire();
