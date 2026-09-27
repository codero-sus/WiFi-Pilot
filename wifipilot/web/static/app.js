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
      if (!MODEL_CACHE.length && payload.data.advisor
          && (payload.data.advisor.provider === 'ollama' ? (payload.data.advisor.models || []).length
              : true)) {
        loadModels('');
      }
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
  if (kind === 'advisor.cost') {
    render();
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
  renderPlatform(SNAPSHOT);
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

  const ai = state.advisor || {};
  const aiBadge = $('#ai-badge');
  const providerNames = { ollama: 'ollama', openrouter: 'openrouter (cloud)', none: 'off' };
  aiBadge.textContent = `ai: ${providerNames[ai.provider] || ai.provider || '—'}`
    + (ai.model ? ` · ${ai.model}` : '');
  aiBadge.className = 'badge ' + (ai.available
    ? (ai.cloud ? 'badge-live' : 'badge-llm')
    : 'badge-idle');
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
      <td>${ap.target_kind ? `<span class="tag">${escapeHtml(ap.target_kind)}</span>` : '<span class="dim">—</span>'}</td>
      <td>${(ap.tags || []).map((t) => `<span class="tag">${escapeHtml(t)}</span>`).join('') || '<span class="dim">—</span>'}</td>
      <td>${ap.clients}</td>
      <td>${lootTags(ap)}</td>
      <td title="${escapeHtml(ap.pick_reason || '')}">${(ap.score || 0).toFixed(1)}</td>
      <td>${decided}</td>
      <td>
        <select data-attack-select="${ap.bssid}">${options}</select>
        <button class="chip" data-attack="${ap.bssid}">▶ run</button>
        <button class="chip" data-crack="${ap.bssid}">🔓 crack</button>
        <button class="chip" data-crack-mask="${ap.bssid}"
          title="mask attack: type a pattern such as Telekom-?d?d?d?d">🎭 mask</button>
        <button class="chip" data-tag="${ap.bssid}" title="tag this AP for scoping">🏷 tag</button>
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
        ${cap.password ? '' : `<button class="chip" data-crack="${cap.bssid}">🔓 crack now</button>
        <button class="chip" data-crack-mask="${cap.bssid}"
          title="mask attack: type a pattern such as Telekom-?d?d?d?d">🎭 mask</button>`}
        ${cap.path ? `<a class="chip" href="/api/file?path=${encodeURIComponent(cap.path)}" target="_blank" rel="noopener">⤓ download</a>` : ''}
      </div>
    </div>`).join('') || '<div class="card dim">Nothing captured yet. Handshakes, PMKIDs and cracked PSKs appear here as soon as they land.</div>';
}

function renderAdvisor(state) {
  const ai = state.advisor || {};
  const policy = ai.policy || {};
  const config = state.config || {};
  const labels = { ollama: 'Ollama (local)', openrouter: 'OpenRouter (cloud)', none: 'disabled' };
  const providerLabel = labels[ai.provider] || ai.provider || '—';
  const reach = ai.available
    ? '<span class="ok">online</span>'
    : `<span class="dim">offline${ai.last_error ? ' — ' + escapeHtml(ai.last_error) : ''}</span>`;
  const rows = [
    ['provider', `<b>${escapeHtml(providerLabel)}</b> ${ai.cloud ? '<span class="tag tag-wep">cloud</span>' : '<span class="tag tag-ok">local</span>'}`],
    ['endpoint', `${reach} <span class="dim">${escapeHtml(ai.host || '')}</span>`],
    ['model', escapeHtml(ai.model || '—')],
    ['auto-think', (state.session || {}).auto_think ? 'enabled' : 'disabled'],
    ['plans', `${ai.plan_count || 0} by model · ${ai.fallback_count || 0} by heuristics`],
    ['calls / errors', `${ai.calls || 0} / ${ai.errors || 0}`],
    ['avg latency', ai.avg_latency ? `${ai.avg_latency}s` : '—'],
    ['tokens / spend', `${ai.tokens || 0}${ai.cost_usd ? ` · $${Number(ai.cost_usd).toFixed(4)}` : ''}`],
  ];
  if (ai.allowance) rows.push(['allowance', escapeHtml(ai.allowance)]);
  if (ai.cloud) {
    const key = ai.key || {};
    rows.push(['api key', key.configured
      ? `<span class="ok">set</span> <span class="dim">${escapeHtml(key.hint || '')}</span>`
      : '<span class="warn">not configured</span>']);
    rows.push(['identifiers', policy.redact_identifiers
      ? 'pseudonymised before sending' : '<span class="warn">sent verbatim</span>']);
  }
  $('#ai-status').innerHTML = rows.map(([k, v]) => `<b>${k}</b><span>${v}</span>`).join('');

  const providerSelect = $('#sel-provider');
  if (providerSelect && config.ai_provider && providerSelect.value !== config.ai_provider) {
    providerSelect.value = config.ai_provider;
  }
  $('#row-pull').style.display = (ai.provider || 'ollama') === 'ollama' ? '' : 'none';
  $('#card-openrouter').classList.toggle('card-active', ai.provider === 'openrouter');

  const or = config.openrouter || {};
  $('#or-status').innerHTML = [
    ['key', (ai.key || {}).configured || or.has_api_key
      ? `<span class="ok">configured</span> <span class="dim">${escapeHtml((ai.key || {}).hint || '')}</span>`
      : '<span class="dim">not configured</span>'],
    ['source', escapeHtml(or.key_source || '—')],
    ['redaction', or.redact_identifiers !== false ? 'on' : '<span class="warn">off</span>'],
    ['budget', policy.max_cost_usd ? `$${Number(policy.max_cost_usd).toFixed(2)}` : 'unlimited'],
    ['spend (this session)', `$${Number(ai.cost_usd || 0).toFixed(4)}`],
  ].map(([k, v]) => `<b>${k}</b><span>${v}</span>`).join('');
  const redactBox = $('#chk-or-redact');
  if (redactBox && document.activeElement !== redactBox) redactBox.checked = or.redact_identifiers !== false;
  const budgetBox = $('#inp-or-budget');
  if (budgetBox && document.activeElement !== budgetBox && policy.max_cost_usd) {
    budgetBox.value = Number(policy.max_cost_usd).toFixed(2);
  }

  $('#ai-privacy').innerHTML = ai.cloud
    ? 'Cloud provider: <b>engagement data leaves this machine</b>'
      + (policy.redact_identifiers ? ' (identifiers pseudonymised).' : ' (identifiers sent verbatim).')
      + ' Switch back to Ollama to keep everything local.'
    : 'Everything runs on this machine through Ollama. Nothing is sent to a remote service '
      + 'unless you switch to OpenRouter, which is off by default.';

  renderModelOptions(ai);
  if (ai.last_plan) renderPlan(ai.last_plan);
}

let MODEL_CACHE = [];

function renderModelOptions(ai) {
  const select = $('#sel-model');
  const current = (ai || {}).model || '';
  const search = ($('#inp-model-search').value || '').toLowerCase();
  const freeOnly = $('#chk-free').checked;
  let models = MODEL_CACHE.length ? MODEL_CACHE : ((ai || {}).models || []);
  if (search) models = models.filter((m) => (m.name || '').toLowerCase().includes(search));
  if (freeOnly) models = models.filter((m) => m.free);
  const options = models.slice(0, 400).map((m) => {
    const price = m.price ? ` — ${m.price}` : '';
    const ctx = m.context ? ` · ${Math.round(m.context / 1000)}k ctx` : '';
    const size = m.size_gb ? ` (${m.size_gb} GB${m.params ? ` · ${m.params}` : ''})` : '';
    return `<option value="${escapeHtml(m.name)}" ${m.name === current ? 'selected' : ''}>`
      + `${escapeHtml(m.name)}${escapeHtml(size + price + ctx)}</option>`;
  });
  select.innerHTML = options.join('') || '<option value="">no models available</option>';
}

function loadModels(provider) {
  const query = $('#inp-model-search').value || '';
  const free = $('#chk-free').checked ? '&free=true' : '';
  const extra = provider ? `&provider=${encodeURIComponent(provider)}` : '';
  return fetch(`/api/ai/models?limit=400&q=${encodeURIComponent(query)}${free}${extra}`)
    .then((r) => r.json())
    .then((data) => {
      MODEL_CACHE = data.models || [];
      renderModelOptions(SNAPSHOT ? SNAPSHOT.advisor : {});
      toast(`${MODEL_CACHE.length} ${data.provider} models${data.error ? ` — ${data.error}` : ''}`);
    })
    .catch(() => {});
}

function renderPlatform(state) {
  const platform = state.platform || {};
  const tools = state.tools || {};
  const kv = $('#platform-kv');
  if (!kv) return;
  kv.innerHTML = [
    ['os', `${escapeHtml(platform.os || '?')} ${escapeHtml(platform.distro || '')}`],
    ['kernel', escapeHtml(platform.kernel || '—')],
    ['supported', platform.supported
      ? '<span class="ok">yes — wifipilot is Linux-only</span>'
      : '<span class="warn">unsupported platform</span>'],
    ['package manager', escapeHtml(platform.package_manager || '—')],
  ].map(([k, v]) => `<b>${k}</b><span>${v}</span>`).join('');
  if (tools.install_command) {
    $('#tool-summary').innerHTML = `missing tools? <code>${escapeHtml(tools.install_command)}</code>`;
  }
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

async function refreshAdvice() {
  const box = $('#advice-list');
  if (!box) return;
  try {
    const data = await api('/api/advice', null, 'GET');
    const items = (data && data.advice) || [];
    box.innerHTML = items.slice(0, 6).map((item) => `
      <div class="row" style="margin:2px 0">
        <span class="tag">${item.priority}</span>
        <b>${escapeHtml(item.action)}</b>
        <span>${escapeHtml(item.essid || item.bssid || '')}</span>
        <span class="dim">${escapeHtml(item.why || '')} · ${escapeHtml(item.confidence || '')}</span>
      </div>`).join('') || '<span class="dim">nothing to advise yet</span>';
  } catch (err) {
    box.textContent = 'advice unavailable';
  }
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
  $('#btn-provider').onclick = () => {
    const provider = $('#sel-provider').value;
    if (provider === 'openrouter' && !$('#chk-or-consent').checked) {
      toast('tick the consent box before switching to the cloud provider', true);
      return;
    }
    api('/api/ai/provider', { provider, consent: $('#chk-or-consent').checked })
      .then(() => loadModels(provider === 'auto' ? '' : provider));
  };
  $('#btn-or-key').onclick = () => api('/api/ai/key', { key: $('#inp-or-key').value })
    .then(() => { $('#inp-or-key').value = ''; loadModels('openrouter'); });
  $('#chk-or-redact').onchange = (e) =>
    api('/api/config', { openrouter: { redact_identifiers: e.target.checked } });
  $('#btn-or-budget').onclick = () => api('/api/config', {
    openrouter: { max_cost_usd: Number($('#inp-or-budget').value) || 0 },
  });
  $('#btn-models-refresh').onclick = () => loadModels('');
  $('#inp-model-search').oninput = () => renderModelOptions(SNAPSHOT ? SNAPSHOT.advisor : {});
  $('#inp-model-search').onkeydown = (e) => { if (e.key === 'Enter') loadModels(''); };
  $('#chk-free').onchange = () => loadModels('');
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
    const target = event.target.closest('[data-attack],[data-crack],[data-crack-mask],[data-detail],[data-toggle-attack],[data-tag]');
    if (!target) return;
    if (target.dataset.attack) {
      const select = document.querySelector(`select[data-attack-select="${target.dataset.attack}"]`);
      api('/api/attack', { bssid: target.dataset.attack, attack: select ? select.value : '' });
    } else if (target.dataset.crack) {
      api('/api/crack', { bssid: target.dataset.crack });
    } else if (target.dataset.crackMask) {
      const answer = prompt('mask attack (comma-separated, hashcat syntax)\n' +
        'e.g. Telekom-?d?d?d?d, ?d?d?d?d?d?d?d?d\n\n' +
        'Leave empty to derive patterns from the target.', '');
      if (answer === null) return;
      const masks = answer.split(',').map((m) => m.trim()).filter(Boolean);
      api('/api/crack', { bssid: target.dataset.crackMask, masks });
    } else if (target.dataset.tag) {
      const name = prompt('tag this access point (e.g. in-scope, guest, retest)', 'in-scope');
      if (!name) return;
      api('/api/tag', { bssid: target.dataset.tag, tag: name });
    } else if (target.dataset.detail) {
      showDetail(target.dataset.detail);
    } else if (target.dataset.toggleAttack) {
      toggleAttack(target.dataset.toggleAttack);
    }
  });

  connect();
  setInterval(() => ws && ws.readyState === 1 && !SNAPSHOT && api('/api/state', null, 'GET'), 5000);
  refreshAdvice();
  setInterval(refreshAdvice, 30000);
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
