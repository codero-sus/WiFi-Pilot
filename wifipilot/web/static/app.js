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
      toast(`${data.detail || response.statusText}`, true);
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
  renderEditions(SNAPSHOT);
  renderPresets(SNAPSHOT);
  renderTasks(SNAPSHOT);
  renderSetup(SNAPSHOT);
  renderAbout(SNAPSHOT);
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
  const off = ai.disabled || ai.provider === 'none' || !!(state.config || {}).ai_disabled;
  const aiBadge = $('#ai-badge');
  if (off) {
    aiBadge.textContent = 'ai: off · deterministic planner';
    aiBadge.className = 'badge badge-off';
  } else {
    const providerNames = { ollama: 'ollama', cortex: 'cortex (local)',
      openrouter: 'openrouter (cloud)', none: 'off' };
    aiBadge.textContent = `ai: ${providerNames[ai.provider] || ai.provider || '—'}`
      + (ai.model ? ` · ${ai.model}` : '') + (ai.cloud ? ' · cloud' : '');
    aiBadge.className = 'badge ' + (ai.available
      ? (ai.cloud ? 'badge-live' : 'badge-llm')
      : 'badge-idle');
  }
  const tab = $('#tab-btn-ai');
  if (tab) tab.classList.toggle('tab-muted', off);
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

function attackTitle(a) {
  const bits = [a.description || a.label];
  const meta = [];
  if (a.category_label) meta.push(`category ${a.category_label}`);
  if (a.noise) meta.push(`noise ${a.noise}`);
  if (a.impact) meta.push(`impact ${a.impact}`);
  if (a.offline) meta.push('no radio needed');
  if (a.requires && a.requires.length) meta.push(`needs ${a.requires.join(', ')}`);
  if (meta.length) bits.push('', meta.join(' · '));
  if (a.detection) bits.push('', `blue team: ${a.detection}`);
  return bits.join('\n');
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
      <td><button class="chip" data-detail="${ap.bssid}" title="full detail"><svg class="ic" aria-hidden="true"><use href="#i-info"/></svg></button></td>
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
        <button class="chip" data-attack="${ap.bssid}"><svg class="ic" aria-hidden="true"><use href="#i-play"/></svg>run</button>
        <button class="chip" data-crack="${ap.bssid}"><svg class="ic" aria-hidden="true"><use href="#i-key"/></svg>crack</button>
        <button class="chip" data-crack-mask="${ap.bssid}"
          title="mask attack: type a pattern such as Telekom-?d?d?d?d"><svg class="ic" aria-hidden="true"><use href="#i-hash"/></svg>mask</button>
        <button class="chip" data-tag="${ap.bssid}" title="tag this AP for scoping"><svg class="ic" aria-hidden="true"><use href="#i-tag"/></svg>tag</button>
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
        ${cap.password ? '' : `<button class="chip" data-crack="${cap.bssid}"><svg class="ic" aria-hidden="true"><use href="#i-key"/></svg>crack now</button>
        <button class="chip" data-crack-mask="${cap.bssid}"
          title="mask attack: type a pattern such as Telekom-?d?d?d?d"><svg class="ic" aria-hidden="true"><use href="#i-hash"/></svg>mask</button>`}
        ${cap.path ? `<a class="chip" href="/api/file?path=${encodeURIComponent(cap.path)}" target="_blank" rel="noopener"><svg class="ic" aria-hidden="true"><use href="#i-download"/></svg>download</a>` : ''}
      </div>
    </div>`).join('') || '<div class="card dim">Nothing captured yet. Handshakes, PMKIDs and cracked PSKs appear here as soon as they land.</div>';
}

function renderAdvisor(state) {
  const ai = state.advisor || {};
  const policy = ai.policy || {};
  const config = state.config || {};
  const off = ai.disabled || ai.provider === 'none' || !!config.ai_disabled;
  const labels = { ollama: 'Ollama (local)', cortex: 'Cortex LLMHoster (local)',
    openrouter: 'OpenRouter (cloud)', none: 'off' };
  const providerLabel = labels[ai.provider] || ai.provider || '—';
  const reach = off ? '<span class="dim">no model in use</span>'
    : (ai.available
      ? '<span class="ok">online</span>'
      : `<span class="dim">offline${ai.last_error ? ' — ' + escapeHtml(ai.last_error) : ''}</span>`);
  const rows = [
    ['provider', off
      ? '<b>off</b> <span class="tag tag-ok">deterministic planner</span>'
      : `<b>${escapeHtml(providerLabel)}</b> ${ai.cloud ? '<span class="tag tag-wep">cloud</span>' : '<span class="tag tag-ok">local</span>'}`],
    ['endpoint', off ? '<span class="dim">nothing is contacted</span>'
      : `${reach} <span class="dim">${escapeHtml(ai.host || '')}</span>`],
    ['model', off ? '<span class="dim">—</span>' : escapeHtml(ai.model || '—')],
    ['auto-think', off ? '<span class="dim">n/a</span>'
      : ((state.session || {}).auto_think ? 'enabled' : 'disabled')],
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

  const offNote = $('#ai-off-note');
  if (offNote) offNote.hidden = !off;
  const quickOff = $('#btn-ai-off');
  if (quickOff) quickOff.hidden = off;
  const openrouterCard = $('#card-openrouter');
  if (openrouterCard) openrouterCard.classList.toggle('card-off', off);
  const chatCard = $('#card-chat');
  if (chatCard) chatCard.classList.toggle('card-off', off);
  for (const id of ['#btn-think', '#btn-chat', '#inp-chat', '#sel-model', '#btn-model',
                    '#btn-models-refresh', '#inp-pull', '#btn-pull', '#inp-or-key',
                    '#btn-or-key', '#chk-or-consent']) {
    const node = $(id);
    if (node) node.disabled = off;
  }
  $('#row-pull').style.display = off ? 'none' : ((ai.provider || 'ollama') === 'ollama' ? '' : 'none');

  $('#ai-privacy').innerHTML = off
    ? 'The advisor is <b>off</b>. No model is called and nothing about this engagement '
      + 'leaves this machine — the deterministic planner scores targets and picks attacks. '
      + 'Turn it back on from the provider picker above whenever you want a second opinion.'
    : (ai.cloud
      ? 'Cloud provider: <b>engagement data leaves this machine</b>'
        + (policy.redact_identifiers ? ' (identifiers pseudonymised).' : ' (identifiers sent verbatim).')
        + ' Switch back to Ollama to keep everything local.'
      : 'Everything runs on this machine through Ollama. Nothing is sent to a remote service '
        + 'unless you switch to OpenRouter, which is off by default.');

  if (!off) renderModelOptions(ai);
  if (ai.last_plan) renderPlan(ai.last_plan);
}

let MODEL_CACHE = [];

function renderModelOptions(ai) {
  const select = $('#sel-model');
  if (!select) return;
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
    ? `rejected by the safety validator: ${dropped.map(escapeHtml).join('; ')}`
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
      monitor ${i.monitor ? '<b class="ok">yes</b>' : '<b class="bad">no</b>'} · injection ${i.injection ? '<b class="ok">yes</b>' : '<span class="dim">unknown</span>'}</span>`).join('')
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

  // Grouped by the same category the catalogue reports, so 54 chips stay readable
  // and the noise/impact a click is about to make is one hover away.
  const attacks = state.attacks || [];
  const groups = new Map();
  for (const a of attacks) {
    const key = a.category_label || a.category || 'attacks';
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(a);
  }
  $('#attack-toggles').innerHTML = [...groups.entries()].map(([label, items]) => `
    <div class="attack-group" data-category="${escapeHtml(items[0].category || '')}">
      <div class="attack-group-head">${escapeHtml(label)}
        <span class="dim">${items.filter((a) => a.enabled).length}/${items.length}</span></div>
      <div class="chips">${items.map((a) => `
        <button class="chip ${a.enabled ? 'on' : ''}" data-toggle-attack="${a.name}"
          title="${escapeHtml(attackTitle(a))}">${escapeHtml(a.label)}${a.offline ? ' · offline' : ''}${a.available ? '' : ' (unavailable)'}</button>`).join('')}</div>
    </div>`).join('')
    || '<span class="dim">no attacks registered</span>';

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
  div.textContent = (message || '');
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
/* ==================================================================== */
/* editions, devices, the attack catalogue and the help panel            */
/* ==================================================================== */

const EDITIONS = {
  all: { label: 'every edition', hint: 'WiFi, Bluetooth and IP attacks are all planned' },
  wifi: { label: 'WiFi', hint: 'access points, handshakes, WPS, rogue APs, deauth — the radio' },
  bluetooth: { label: 'Bluetooth', hint: 'BLE and classic: KNOB, BIAS, BlueBorne, HID injection' },
  it: { label: 'IT', hint: 'cameras, printers, servers, PLCs, IoT — the devices behind the AP' },
};

let CATALOG = [];            // every attack, from /api/catalog
let DEVICES = [];            // the device shelf, from /api/devices
let GROUPS = [];
let DEMO_HOSTS = [];
let DEMO_BLE = [];
let SELECTED = { device: '', host: '', port: 0, detail: null };
let CAT_LIMIT = 150;

function editionCounts(state) {
  return ((state || SNAPSHOT || {}).edition || {}).attacks || {};
}

let PRESETS = [];
function renderPresets(state) {
  const select = $('#sel-preset');
  if (!select || !state) return;
  const rows = state.presets || [];
  if (rows.length && rows !== PRESETS) {
    PRESETS = rows;
    const current = select.value;
    select.innerHTML = '<option value="">— none (planner decides) —</option>'
      + rows.map((p) => `<option value="${escapeHtml(p.name)}">${escapeHtml(p.label)} · ${p.attacks} attacks · ~${p.minutes} min</option>`).join('')
      + rows.map((p) => `<option value="${escapeHtml(p.name)}:stealth">${escapeHtml(p.label)} :stealth · ${p.stealth_attacks} attacks · ~${p.minutes} min</option>`).join('');
    select.value = current;
  }
  const chosen = select.value.replace(/:.*$/, '');
  const hint = rows.find((p) => p.name === chosen);
  select.title = hint ? hint.description : 'a time-boxed set of attacks';
  const accelSel = $('#sel-accel');
  if (accelSel && state.accel && state.accel.hardware) {
    const hw = state.accel.hardware;
    accelSel.title = `detected: ${hw.cpu.count} CPU · ${hw.ram.available_mb} MB RAM free · `
      + (hw.gpu.present ? `GPU via ${hw.gpu.via}` : 'no GPU')
      + ` — active: ${(state.accel.resolved || state.accel.allowed || []).join('+') || 'off'}`;
  }
}

function renderEditions(state) {
  const summary = (state || {}).edition || {};
  const counts = summary.attacks || {};
  const active = summary.active || 'all';
  const total = summary.total || Object.values(counts).reduce((a, b) => a + b, 0);
  $$('#edition-switch .seg-btn').forEach((btn) => {
    const id = btn.dataset.edition;
    btn.classList.toggle('active', id === active);
    const badge = btn.querySelector('b');
    if (badge) badge.textContent = id === 'all' ? total : (counts[id] || 0);
  });
  const names = { all: 'all', wifi: 'WiFi', bluetooth: 'Bluetooth', it: 'IT' };
  const badge = $('#edition-badge');
  if (badge) {
    badge.textContent = `edition: ${names[active] || active}`;
    badge.className = 'badge ' + (active === 'all' ? 'badge-idle' : 'badge-run');
  }
  const note = $('#edition-note');
  if (note) note.textContent = (EDITIONS[active] || {}).hint || '';
  const tabCount = $('#tab-count-devices');
  if (tabCount) tabCount.textContent = total || (CATALOG.length || 0);
}

function setEdition(id) {
  api('/api/edition', { edition: id }).then((result) => {
    if (!result) return;
    toast(`edition: ${id === 'all' ? 'all three' : id} — ${(result.attacks && result.attacks[id]) || result.total} attacks enabled`);
    if (SNAPSHOT) { SNAPSHOT.edition = result; renderEditions(SNAPSHOT); }
    loadDevices();
    loadCatalogue();
  });
}

/* ------------------------------------------------------------ devices */
function loadDevices() {
  return api('/api/devices', null, 'GET').then((data) => {
    if (!data) return;
    DEVICES = data.devices || [];
    GROUPS = data.groups || [];
    DEMO_HOSTS = data.demo_hosts || [];
    DEMO_BLE = data.demo_ble || [];
    const groupSel = $('#sel-device-group');
    if (groupSel && groupSel.options.length <= 1) {
      GROUPS.forEach((group) => {
        const option = document.createElement('option');
        option.value = group.id;
        option.textContent = group.label;
        groupSel.appendChild(option);
      });
    }
    const hostSel = $('#sel-demo-host');
    if (hostSel) {
      const previous = hostSel.value;
      hostSel.innerHTML = '<option value="">pick a simulated host…</option>'
        + DEMO_HOSTS.map((host) => `<option value="${host.ip}">${host.ip} · ${escapeHtml(host.label || host.name || '')}${host.device ? ' · ' + escapeHtml(host.device) : ''}</option>`).join('');
      hostSel.value = previous;
    }
    const btSel = $('#sel-demo-bt');
    if (btSel) {
      const previous = btSel.value;
      btSel.innerHTML = '<option value="">pick a simulated device…</option>'
        + DEMO_BLE.filter((dev) => dev.kind !== 'bredr' || dev.name)
          .map((dev) => `<option value="${dev.address}">${dev.address} · ${escapeHtml(dev.name || dev.model || dev.device || 'unnamed')}${dev.profile ? ' · ' + escapeHtml(dev.profile) : ''}</option>`).join('');
      btSel.value = previous;
    }
    renderDeviceGrid();
  });
}

function renderDeviceGrid() {
  const grid = $('#device-grid');
  if (!grid) return;
  const needle = ($('#inp-device-filter').value || '').toLowerCase();
  const group = $('#sel-device-group').value;
  const onlyActive = $('#chk-device-domain').checked;
  const edition = ((SNAPSHOT || {}).edition || {}).active || 'all';
  const rows = DEVICES.filter((dev) => {
    if (group && dev.group !== group) return false;
    if (onlyActive && edition !== 'all' && dev.domain !== edition) return false;
    if (!needle) return true;
    return [dev.id, dev.label, dev.group_label, dev.description, (dev.protocols || []).join(' '),
            (dev.vendors || []).join(' '), (dev.ports || []).join(' ')]
      .join(' ').toLowerCase().includes(needle);
  });
  const scope = onlyActive && edition !== 'all' ? ` the ${edition} edition` : ' every edition';
  $('#device-summary').textContent = `${rows.length} of ${DEVICES.length} device types${scope}`;
  grid.innerHTML = rows.map((dev) => `
    <div class="device-card ${dev.id === SELECTED.device ? 'selected' : ''}" data-pick-device="${dev.id}">
      <div class="dev-head">
        <span class="dev-label">${escapeHtml(dev.label)}</span>
        <span class="dev-count">${dev.attack_count != null ? dev.attack_count : (dev.attacks || []).length} attacks</span>
      </div>
      <div class="dev-sub">${escapeHtml(dev.group_label || dev.group)} · <span class="risk-${dev.risk}">${escapeHtml(dev.risk || '')}</span></div>
      <div class="dev-ports">${(dev.ports || []).slice(0, 8).join(' · ') || 'no fixed port'}</div>
    </div>`).join('') || '<span class="dim">no device type matches that filter</span>';
}

function pickDevice(id, host) {
  api('/api/device', { device: id, host: host || $('#inp-it-host').value || '', port: Number($('#inp-it-port').value) || 0 })
    .then((result) => {
      if (!result) return;
      SELECTED.device = id;
      SELECTED.host = (result.selected || {}).host || '';
      SELECTED.port = (result.selected || {}).port || 0;
      SELECTED.detail = result.device || null;
      if (SELECTED.host) $('#inp-it-host').value = SELECTED.host;
      renderDeviceGrid();
      renderDevicePanel();
    });
}

function renderDevicePanel() {
  const detail = SELECTED.detail;
  const body = $('#dev-body');
  if (!detail) {
    $('#dev-title').textContent = 'Pick a device';
    return;
  }
  $('#dev-title').innerHTML = `${escapeHtml(detail.label)} <span class="dim" style="font-weight:400">· ${escapeHtml(detail.group_label || detail.group)} · <span class="risk-${detail.risk}">${escapeHtml(detail.risk || '')} risk</span></span>`;
  $('#dev-briefing').textContent = detail.briefing || detail.description || '';
  const attacks = detail.attacks || [];
  const discovery = attacks.filter((a) => a.category === 'discovery');
  const loud = attacks.filter((a) => ['loud', 'extreme'].includes(a.noise));
  const pills = (items) => items.map((item) => `<span class="pill">${escapeHtml(item)}</span>`).join('');
  body.innerHTML = `
    <div class="dev-kv">
      <b>address</b><span class="mono">${escapeHtml(SELECTED.host || 'not set — point the attacks at a host above')}${SELECTED.port ? ':' + SELECTED.port : ''}</span>
      <b>ports</b><span class="mono">${(detail.ports || []).join(', ') || '—'}</span>
      <b>protocols</b><span>${(detail.protocols || []).join(', ') || '—'}</span>
      <b>vendors</b><span>${(detail.vendors || []).join(', ') || 'any'}</span>
      <b>attack mix</b><span>${attacks.length} apply · ${discovery.length} discovery · ${loud.length} loud</span>
    </div>
    <h4>How you recognise it</h4>
    <div class="pill-row">${pills(detail.tells || []) || '<span class="dim">no single tell — fingerprint it from the answers</span>'}</div>
    <h4>What to run first</h4>
    <div class="pill-row">${pills((detail.plan || detail.attack_names || []).slice(0, 8))}</div>
    <h4>Attacks for this device (${attacks.length})</h4>
    <div class="attack-scroll">
      <table class="attack-table">
        <thead><tr><th>attack</th><th>what it does</th><th>category</th><th>noise</th><th>port</th><th></th></tr></thead>
        <tbody>${attacks.map(attackRow).join('')}</tbody>
      </table>
    </div>`;
}

function attackRow(row) {
  const loud = ['loud', 'extreme'].includes(row.noise);
  const description = row.description || row.label || '';
  return `<tr class="${loud ? 'loud' : ''}">
    <td class="aname">${escapeHtml(row.name)}</td>
    <td class="adesc">${escapeHtml(description.slice(0, 170))}${description.length > 170 ? '…' : ''}</td>
    <td class="cat">${escapeHtml(row.category || '')}</td>
    <td class="noise-${row.noise}">${escapeHtml(row.noise || '')}</td>
    <td class="mono dim">${row.port || '—'}</td>
    <td>
      <button class="chip" data-run-attack="${escapeHtml(row.name)}" title="run it through the engine"><svg class="ic" aria-hidden="true"><use href="#i-play"/></svg></button>
      <button class="chip" data-explain="${escapeHtml(row.name)}" title="what it does, what the defender sees">?</button>
    </td>
  </tr>`;
}

/* --------------------------------------------------- attack catalogue */
function loadCatalogue() {
  return api('/api/catalog', null, 'GET').then((data) => {
    if (!data) return;
    CATALOG = data.attacks || [];
    const categorySel = $('#sel-attack-category');
    if (categorySel && categorySel.options.length <= 1) {
      Array.from(new Set(CATALOG.map((a) => a.category))).sort().forEach((name) => {
        const option = document.createElement('option');
        option.value = name;
        option.textContent = name;
        categorySel.appendChild(option);
      });
    }
    const tabCount = $('#tab-count-devices');
    if (tabCount && !CATALOG.length) tabCount.textContent = '0';
    renderCatalogue();
  });
}

function renderCatalogue() {
  const body = $('#cat-body');
  if (!body) return;
  const needle = ($('#inp-attack-filter').value || '').toLowerCase();
  const category = $('#sel-attack-category').value;
  const domain = $('#sel-attack-domain').value;
  const onlyDevice = $('#chk-only-device').checked && SELECTED.device;
  const rows = CATALOG.filter((row) => {
    if (category && row.category !== category) return false;
    if (domain && row.domain !== domain) return false;
    if (onlyDevice && !(row.devices || []).includes(SELECTED.device)) return false;
    if (!needle) return true;
    return [row.name, row.label, row.description, row.protocol, (row.devices || []).join(' ')]
      .join(' ').toLowerCase().includes(needle);
  });
  $('#cat-count').textContent = `${rows.length} of ${CATALOG.length}`;
  const shown = rows.slice(0, CAT_LIMIT);
  body.innerHTML = shown.map(attackRow).join('')
    + (rows.length > shown.length
      ? `<tr><td colspan="7" class="dim">${rows.length - shown.length} more — narrow the filter (the table shows the first ${CAT_LIMIT})</td></tr>`
      : '')
    || '<tr><td colspan="7" class="dim">nothing matches that filter</td></tr>';
}

/* --------------------------------------------------------------- help */
function helpAnswer(payload, question) {
  const box = $('#help-answer');
  const source = $('#help-src');
  box.textContent = 'looking it up…';
  source.textContent = '';
  return api('/api/help', payload).then((data) => {
    if (!data) { box.textContent = 'the help panel could not be reached'; return; }
    box.textContent = data.answer || '';
    source.textContent = data.source === 'advisor'
      ? 'answered by the advisor, grounded in the catalogue'
      : 'answered from the catalogue — no model was called';
    source.className = 'help-src ' + (data.source === 'advisor' ? 'advisor' : '');
  });
}

function explainAttack(name) {
  $('#help-card').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  return api('/api/explain', { name, device: SELECTED.device || '' }).then((data) => {
    if (!data) return;
    $('#help-answer').textContent = data.answer || '';
    $('#help-src').textContent = data.source === 'advisor'
      ? 'answered by the advisor, grounded in the catalogue'
      : 'answered from the catalogue — no model was called';
    $('#help-src').className = 'help-src ' + (data.source === 'advisor' ? 'advisor' : '');
  });
}

function askHelp(question) {
  const text = (question || $('#inp-help').value || '').trim();
  if (!text) { toast('type a question, or press ? on an attack row', true); return; }
  return helpAnswer({ question: text, device: SELECTED.device || '' });
}

function runAttack(name, bssid) {
  const host = SELECTED.host || $('#inp-it-host').value || '';
  const port = Number($('#inp-it-port').value) || 0;
  const chain = (host || port)
    ? api('/api/device', { host, port })
    : Promise.resolve(null);
  return chain.then(() => api('/api/attack', { attack: name, bssid: bssid || '' }))
    .then((result) => {
      if (result) toast(result.message || `queued ${name}`);
    });
}

function runDiscoverySet() {
  const detail = SELECTED.detail;
  if (!detail) { toast('pick a device first', true); return; }
  const rows = (detail.attacks || []).filter((row) => row.category === 'discovery');
  if (!rows.length) { toast('no discovery attack for this device — run the ones in the list', true); return; }
  const host = SELECTED.host || $('#inp-it-host').value || '';
  const port = Number($('#inp-it-port').value) || 0;
  api('/api/device', { host, port }).then(() => {
    let queued = 0;
    rows.slice(0, 6).forEach((row, index) => {
      setTimeout(() => {
        api('/api/attack', { attack: row.name, bssid: '', reason: 'device discovery set' })
          .then((result) => { if (result) queued += 1; });
      }, index * 900);                       // one at a time: the engine runs one job
    });
    toast(`queued the discovery rows for ${detail.label} (${Math.min(rows.length, 6)})`);
  });
}

/* ------------------------------------------------------------ wiring */
function wire() {
  loadCatalogue();
  loadDevices();
  $$('.tab').forEach((tab) => tab.onclick = () => {
    $$('.tab').forEach((t) => t.classList.remove('active'));
    $$('.tabpane').forEach((p) => p.classList.remove('active'));
    tab.classList.add('active');
    $('#tab-' + tab.dataset.tab).classList.add('active');
    if (tab.dataset.tab === 'devices' && !DEVICES.length) loadDevices();
    if (tab.dataset.tab === 'docs' && !DOCS.loaded) loadDocs();
  });

  $('#btn-campaign').onclick = () => api('/api/campaign', {
    targets: $('#inp-targets').value,
    duration: parseDuration($('#inp-duration').value),
    scan_first: $('#chk-scanfirst').checked,
    preset: $('#sel-preset') ? $('#sel-preset').value : '',
    force: $('#chk-force') ? $('#chk-force').checked : false,
    accel: $('#sel-accel') ? $('#sel-accel').value : '',
    action: 'start',
  });
  $('#btn-stop').onclick = () => api('/api/campaign', { action: 'stop' });
  $('#btn-cancel').onclick = () => api('/api/cancel', {});
  $('#btn-rescan').onclick = () => api('/api/rescan', { seconds: 20 });
  $('#btn-think').onclick = () => api('/api/ai/think', {}).then((r) => {
    if (r && r.disabled) { toast('advisor is off — the deterministic planner is already deciding'); return; }
    if (r && r.plan) renderPlan(r.plan);
  });
  $('#btn-recheck').onclick = () => fetch('/api/tools?force=true').then((r) => r.json()).then(() => api('/api/state', null, 'GET'));
  $('#btn-model').onclick = () => api('/api/ai/model', { model: $('#sel-model').value });
  $('#btn-ai-off').onclick = () => {
    api('/api/ai/toggle', { disabled: true });
    toast('advisor off — the deterministic planner is deciding');
  };
  $('#btn-ai-toggle').onclick = () => {
    api('/api/ai/toggle', { disabled: false });
    toast('advisor on — auto (local Ollama first)');
  };
  $('#btn-provider').onclick = () => {
    const provider = $('#sel-provider').value;
    if (provider === 'openrouter' && !$('#chk-or-consent').checked) {
      toast('tick the consent box before switching to the cloud provider', true);
      return;
    }
    api('/api/ai/provider', { provider, consent: $('#chk-or-consent').checked })
      .then(() => loadModels(provider === 'auto' ? '' : provider));
  };
  $('#btn-cortex').onclick = () => api('/api/ai/provider', {
    provider: 'cortex', host: $('#inp-cortex-host').value.trim() || undefined,
  }).then((r) => {
    if (!r) return;
    toast('provider: ' + (r.provider || 'cortex') + ' — a local model served by Cortex LLMHoster');
    loadModels('cortex');
  });
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
  $$('#edition-switch .seg-btn').forEach((btn) => btn.onclick = () => setEdition(btn.dataset.edition));
  $('#btn-devices-refresh').onclick = () => loadDevices();
  $('#inp-device-filter').oninput = renderDeviceGrid;
  $('#sel-device-group').onchange = renderDeviceGrid;
  $('#chk-device-domain').onchange = renderDeviceGrid;
  $('#sel-demo-host').onchange = () => {
    const host = $('#sel-demo-host').value;
    if (!host) return;
    $('#inp-it-host').value = host;
    const row = DEMO_HOSTS.find((entry) => entry.ip === host);
    if (row && row.device) pickDevice(row.device, host);
    else api('/api/device', { host }).then(() => toast(`IT attacks point at ${host}`));
  };
  $('#sel-demo-bt').onchange = () => {
    const address = $('#sel-demo-bt').value;
    if (!address) return;
    api('/api/sim/target', { address }).then((result) => {
      if (!result) return;
      const name = (result.device || {}).name || address;
      toast(`Bluetooth attacks point at ${name} (${address})`);
    });
  };
  $('#btn-point-host').onclick = () => {
    const host = $('#inp-it-host').value.trim();
    const port = Number($('#inp-it-port').value) || 0;
    if (!host) { toast('type a host (or pick a simulated one)', true); return; }
    api('/api/device', { host, port, device: SELECTED.device || '' })
      .then((result) => {
        if (!result) return;
        SELECTED.host = host;
        SELECTED.port = port;
        $('#select-note').textContent = `the IT and Bluetooth attacks now talk to ${host}${port ? ':' + port : ''}`;
        toast(`pointing the IT attacks at ${host}${port ? ':' + port : ''}`);
        renderDevicePanel();
      });
  };
  $('#btn-run-plan').onclick = runDiscoverySet;
  $('#inp-attack-filter').oninput = renderCatalogue;
  $('#sel-attack-category').onchange = renderCatalogue;
  $('#sel-attack-domain').onchange = renderCatalogue;
  $('#chk-only-device').onchange = renderCatalogue;
  $('#btn-help').onclick = () => askHelp('');
  $('#inp-help').onkeydown = (event) => { if (event.key === 'Enter') askHelp(''); };
  $('#btn-help-explain').onclick = () => {
    const name = (SELECTED.device && ((SELECTED.detail || {}).attacks || [])[0] || {}).name;
    if (name) explainAttack(name);
    else toast('pick a device (or press ? on an attack row)', true);
  };
  $$('.chip[data-helpq]').forEach((chip) => chip.onclick = () => {
    $('#inp-help').value = chip.dataset.helpq;
    askHelp('');
  });
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
    const target = event.target.closest('[data-attack],[data-crack],[data-crack-mask],[data-detail],[data-toggle-attack],[data-tag],[data-pick-device],[data-run-attack],[data-explain],[data-run-attack-row]');
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
    } else if (target.dataset.pickDevice) {
      pickDevice(target.dataset.pickDevice);
    } else if (target.dataset.runAttack) {
      runAttack(target.dataset.runAttack, '');
    } else if (target.dataset.explain) {
      explainAttack(target.dataset.explain);
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
  const ai = (SNAPSHOT || {}).advisor || {};
  if (ai.disabled || ai.provider === 'none') {
    toast('advisor is off — turn it on to ask a model; the planner needs no prompting', true);
    return;
  }
  appendChat('user', message);
  input.value = '';
  api('/api/ai/chat', { message }).then((r) => {
    if (r && r.disabled) {
      toast(r.note || 'advisor is off', true);
      appendChat('system', 'The advisor is off, so no model answered. The deterministic '
        + 'planner is still choosing attacks.');
    }
  });
}

function parseDuration(text) {
  if (!text) return 0;
  const match = String(text).trim().match(/^(\d+(?:\.\d+)?)\s*([smhd]?)$/i);
  if (!match) return 0;
  const value = parseFloat(match[1]);
  return value * ({ s: 1, m: 60, h: 3600, d: 86400 }[(match[2] || 's').toLowerCase()] || 1);
}


/* ------------------------------------------- sidebar views & navigation */
function iconSvg(name) {
  return `<svg class="ic" aria-hidden="true"><use href="#i-${name}"/></svg>`;
}

function gotoTab(name) {
  const btn = $$('.tab').filter((t) => t.dataset.tab === name)[0];
  if (btn) btn.click();
}

function fmtWhen(value) {
  if (!value && value !== 0) return '—';
  if (typeof value === 'number') {
    return new Date(value * 1000).toLocaleTimeString([], { hour12: false });
  }
  return String(value);
}

const ATTEMPT_TAG = { running: 'tag-running', success: 'tag-ok', failed: 'tag-failed', skipped: 'tag-skipped' };

function renderTasks(state) {
  const attempts = state.attempts || [];
  const findings = state.findings || [];
  const engine = state.engine || {};
  const progress = state.progress || {};
  const stats = state.stats || {};
  const session = state.session || {};
  const last = attempts[attempts.length - 1] || {};
  const statusSel = $('#sel-attempt-status');
  const filterInp = $('#inp-attempt-filter');
  const sig = [attempts.length, findings.length, progress.percent || 0, progress.active,
    last.status || '', last.result || '', engine.detail || '', engine.campaign_running,
    statusSel ? statusSel.value : '', filterInp ? filterInp.value : ''].join('|');
  if (renderTasks._sig === sig) return;
  renderTasks._sig = sig;

  const pill = $('#tab-count-tasks');
  if (pill) pill.textContent = stats.attacks_run != null ? stats.attacks_run : attempts.length;

  $('#tasks-campaign').innerHTML = `
    <b>campaign</b><span>${engine.campaign_running
      ? '<span class="tag tag-running">running</span>' : '<span class="tag">idle</span>'}</span>
    <b>phase</b><span>${escapeHtml(engine.phase || '—')}</span>
    <b>detail</b><span>${escapeHtml(engine.detail || '—')}</span>
    <b>current job</b><span class="mono">${escapeHtml(engine.current_job || '—')}</span>
    <b>queued</b><span>${engine.queue_depth || 0}</span>
    <b>uptime</b><span>${escapeHtml(session.uptime_h || '—')}</span>`;

  const percent = progress.active ? Math.max(2, Math.min(100, progress.percent || 0)) : 0;
  $('#tasks-progress-bar').style.width = `${percent}%`;
  $('#tasks-progress-label').textContent = progress.active
    ? `${progress.label || 'working'} · ${percent.toFixed(0)}% · ${progress.speed || ''} ${progress.detail || ''}`
    : 'nothing in flight';

  const by = { running: 0, success: 0, failed: 0, skipped: 0 };
  attempts.forEach((a) => { if (by[a.status] != null) by[a.status] += 1; });
  $('#tasks-stats').innerHTML = `
    <b>attacks run</b><span>${stats.attacks_run != null ? stats.attacks_run : attempts.length}</span>
    <b>recent</b><span>${attempts.length} tracked · ${by.success} ok · ${by.failed} failed · ${by.running} running · ${by.skipped} skipped</span>
    <b>handshakes</b><span>${stats.handshakes || 0}</span>
    <b>loot</b><span>${stats.loot || 0} capture(s) · ${stats.passwords || 0} password(s)</span>
    <b>findings</b><span>${findings.length}</span>`;

  const act = state.active_attempt;
  const activeBox = $('#tasks-active');
  activeBox.className = act ? '' : 'dim';
  activeBox.innerHTML = act
    ? `<b>${escapeHtml(act.attack || 'attack')}</b> → <span class="mono">${escapeHtml(act.bssid || '')}</span>
       <span class="dim">via ${escapeHtml(act.tool || '—')} · since ${fmtWhen(act.started)}${act.detail ? ' · ' + escapeHtml(act.detail) : ''}</span>`
    : 'nothing running right now';

  const status = statusSel ? statusSel.value : '';
  const needle = filterInp ? filterInp.value.trim().toLowerCase() : '';
  const rows = attempts.slice().reverse().filter((a) => {
    if (status && a.status !== status) return false;
    if (needle && !(`${a.attack || ''} ${a.bssid || ''} ${a.tool || ''} ${a.result || ''}`).toLowerCase().includes(needle)) return false;
    return true;
  });
  $('#tbl-attempts tbody').innerHTML = rows.map((a) => `
    <tr>
      <td class="mono dim">${escapeHtml(fmtWhen(a.started))}</td>
      <td>${escapeHtml(a.attack || '—')}</td>
      <td class="mono">${escapeHtml(a.bssid || '—')}</td>
      <td><span class="tag ${ATTEMPT_TAG[a.status] || ''}">${escapeHtml(a.status || '—')}</span></td>
      <td class="dim">${typeof a.duration === 'number' && a.duration ? a.duration.toFixed(1) : '—'}</td>
      <td class="dim">${escapeHtml(a.tool || '—')}</td>
      <td class="dim" title="${escapeHtml(a.result || a.detail || '')}">${escapeHtml(String(a.result || a.detail || '').slice(0, 90))}</td>
      <td>${a.chosen_by === 'ai' ? '<span class="tag tag-ai">AI</span>' : `<span class="dim">${escapeHtml(a.chosen_by || 'planner')}</span>`}</td>
    </tr>`).join('')
    || '<tr><td colspan="8" class="dim">no attempts match yet — start a campaign or run one attack from Targets.</td></tr>';

  const findingsBox = $('#findings-list');
  findingsBox.className = findings.length ? '' : 'dim';
  findingsBox.innerHTML = findings.slice().reverse().map((f) => {
    const sev = String(f.severity || 'info').toLowerCase();
    return `<div class="finding sev-${escapeHtml(sev)}">
      <div class="f-head"><b>${escapeHtml(f.title || f.kind || 'finding')}</b>
        <span class="tag">${escapeHtml(f.kind || '')}</span>
        <span class="dim">${escapeHtml(sev)} · ${escapeHtml(fmtWhen(f.created))}${f.bssid ? ' · ' + escapeHtml(f.bssid) : ''}${f.source ? ' · ' + escapeHtml(f.source) : ''}</span></div>
      ${f.detail ? `<div class="f-detail">${escapeHtml(f.detail)}</div>` : ''}
    </div>`;
  }).join('') || 'no findings yet';
}

function setupCheckItems(state) {
  const tools = state.tools || {};
  const platform = state.platform || {};
  const session = state.session || {};
  const items = [];
  items.push(platform.supported === false
    ? ['bad', `unsupported platform — ${escapeHtml(platform.platform || '?')}; wifipilot is Linux-only`]
    : ['ok', `Linux host — ${escapeHtml(platform.distro || platform.os || 'posix')} (kernel ${escapeHtml(platform.kernel || '?')})`]);
  const ifaces = tools.interfaces || [];
  const monitorIface = ifaces.filter((i) => i.monitor)[0];
  if (monitorIface) items.push(['ok', `monitor-mode radio ready — ${escapeHtml(monitorIface.name)} (${escapeHtml(monitorIface.driver || 'driver ?')})`]);
  else if (ifaces.length) items.push(['warn', `wireless interface present (${escapeHtml(ifaces[0].name)}) but no confirmed monitor mode — several attacks need it`]);
  else items.push(['warn', session.demo ? 'no wireless radio detected — demo mode simulates one' : 'no wireless radio detected — plug in a monitor-capable adapter']);
  const missing = tools.missing_required || [];
  items.push(missing.length
    ? ['warn', `required tools missing: ${missing.map(escapeHtml).join(', ')} — install below or via <code>wifipilot tools install</code>`]
    : ['ok', 'aircrack-ng toolchain complete — every required tool is on PATH']);
  const wordlists = state.wordlists || (state.config || {}).wordlists || [];
  items.push(wordlists.length
    ? ['ok', `${wordlists.length} wordlist(s) ready for cracking`]
    : ['warn', 'no wordlist configured — cracking falls back to smart candidates (SSID rules + defaults)']);
  items.push(session.demo
    ? ['warn', 'demo mode — all traffic is simulated; flip to live below once the radio is in']
    : ['ok', 'live mode — talking to the real radio']);
  const adv = state.advisor || {};
  items.push(adv.available
    ? ['ok', `advisor model reachable (${escapeHtml(adv.provider || 'llm')})`]
    : ['warn', 'no advisor model — the deterministic planner decides on its own (fully supported)']);
  return items;
}

function renderSetup(state) {
  const tools = state.tools || {};
  const config = state.config || {};
  const session = state.session || {};
  const items = setupCheckItems(state);
  const list = Object.values(tools.tools || {});
  const sig = JSON.stringify(items) + '|' + list.filter((t) => t.available).length + '|' + session.demo;
  if (renderSetup._sig === sig) return;
  renderSetup._sig = sig;

  const icons = { ok: 'check-c', warn: 'alert', bad: 'x-c' };
  $('#setup-checklist').innerHTML = items.map(([level, text]) =>
    `<li class="${level}">${iconSvg(icons[level])}<span>${text}</span></li>`).join('');

  const ready = list.filter((t) => t.available).length;
  const missing = tools.missing_required || [];
  $('#setup-tools').innerHTML = `
    <b>installed</b><span>${ready} / ${list.length} tools on PATH</span>
    <b>missing required</b><span>${missing.length ? missing.map(escapeHtml).join(', ') : '<span class="ok">none</span>'}</span>
    <b>capabilities</b><span>${escapeHtml(Object.entries(tools.capabilities || {}).filter(([, v]) => v).map(([k]) => k).join(', ') || '—')}</span>`;

  $('#setup-radio').innerHTML = (tools.interfaces || []).map((i) => `
    <b>${escapeHtml(i.name)}</b><span>${escapeHtml(i.driver || '?')} · ${(i.bands || []).map(escapeHtml).join('/') || '?'} ·
      monitor ${i.monitor ? '<b class="ok">yes</b>' : '<b class="bad">no</b>'} · injection ${i.injection ? '<b class="ok">yes</b>' : '<span class="dim">unknown</span>'}</span>`).join('')
    || '<b>none</b><span class="dim">no wireless interfaces detected</span>';

  $('#setup-mode').innerHTML = `
    <b>mode</b><span>${session.demo ? '<span class="tag">demo (simulated)</span>' : '<span class="tag tag-ok">live radio</span>'}</span>
    <b>authorized</b><span>${session.authorized ? 'yes' : 'no — tick “authorized” in the control bar before going live'}</span>
    <b>scanner</b><span>${session.scanning ? 'running' : 'stopped'}</span>`;

  $('#setup-accel').innerHTML = `
    <b>acceleration</b><span>${escapeHtml(config.accel || 'auto')}</span>
    <b>jobs</b><span>${config.jobs || 'auto (all cores)'}</span>
    <b>parallel crack</b><span>${config.parallel_crack === false ? 'off' : 'on'}</span>
    <b>workers</b><span>${config.accel_workers || 'auto'}</span>`;

  const wordlists = state.wordlists || config.wordlists || [];
  $('#setup-wordlists').innerHTML = wordlists.length
    ? wordlists.map((w) => {
      const name = typeof w === 'string' ? w.split('/').pop() : (w.name || (w.path || '').split('/').pop() || 'wordlist');
      const size = w && w.size ? ` · ${(w.size / 1024).toFixed(0)} KB` : '';
      const full = typeof w === 'string' ? w : (w.path || '');
      return `<span class="chip" title="${escapeHtml(full)}">${escapeHtml(name)}${size}</span>`;
    }).join('')
    : '<span class="dim">none configured — cracking uses smart candidates only</span>';
}

function renderAbout(state) {
  const edition = state.edition || {};
  const counts = edition.attacks || {};
  const total = edition.total || Object.values(counts).reduce((a, b) => a + b, 0);
  const platform = state.platform || {};
  const session = state.session || {};
  const sig = total + '|' + session.demo + '|' + (edition.active || '');
  if (renderAbout._sig === sig) return;
  renderAbout._sig = sig;
  $('#about-attacks').textContent = total
    ? `${total} attacks — ${counts.wifi || 0} Wi-Fi · ${counts.bluetooth || 0} Bluetooth · ${counts.it || 0} IT`
    : 'attack registry';
  $('#about-kv').innerHTML = `
    <b>mode</b><span>${session.demo ? 'demo (simulated radio)' : 'live'}</span>
    <b>edition</b><span>${escapeHtml(edition.active || 'all')}</span>
    <b>session</b><span class="mono">${escapeHtml(session.id || '—')}</span>
    <b>output</b><span class="mono">${escapeHtml(session.output_dir || '—')}</span>
    <b>platform</b><span>${escapeHtml(platform.distro || platform.os || '—')} · kernel ${escapeHtml(platform.kernel || '?')}${platform.package_manager ? ' · ' + escapeHtml(platform.package_manager) : ''}</span>
    <b>uptime</b><span>${escapeHtml(session.uptime_h || '—')}</span>`;
}

/* ------------------------------------------------------------------ docs */
const DOCS = { loaded: false, list: [], current: null, filter: '' };

function loadDocs() {
  api('/api/docs', null, 'GET').then((data) => {
    DOCS.list = (data && data.docs) || [];
    DOCS.loaded = true;
    renderDocsList();
    if (DOCS.current) return;
    const preferred = ['GETTING-STARTED.md', 'README.md', 'USAGE.md', 'MANUAL.md'];
    const first = DOCS.list.filter((d) => preferred.includes(d.name))[0] || DOCS.list[0];
    if (first) openDoc(first.name);
  });
}

function renderDocsList() {
  const box = $('#docs-list');
  if (!box) return;
  const needle = DOCS.filter;
  const rows = DOCS.list.filter((d) => !needle || `${d.name} ${d.title || ''}`.toLowerCase().includes(needle));
  box.innerHTML = rows.map((d) => `
    <button class="doc-item ${d.name === DOCS.current ? 'active' : ''}" data-doc="${escapeHtml(d.name)}">
      <span>${escapeHtml(d.title || d.name)}</span>
      <span class="doc-name">${escapeHtml(d.name)}</span>
    </button>`).join('') || '<div class="dim">no documents match</div>';
}

function openDoc(name) {
  if (!name) return;
  DOCS.current = name;
  renderDocsList();
  const body = $('#docs-content');
  body.innerHTML = '<p class="dim">loading…</p>';
  api(`/api/docs/${encodeURIComponent(name)}`, null, 'GET').then((data) => {
    body.innerHTML = data && data.markdown != null
      ? mdToHtml(data.markdown)
      : '<p class="dim">could not load this document.</p>';
    body.scrollTop = 0;
  });
}

function mdInline(text) {
  const codes = [];
  text = text.replace(/`([^`]+)`/g, (m, c) => { codes.push(c); return `\u0001${codes.length - 1}\u0002`; });
  text = text.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (m, label, url) => {
    const ext = /^https?:/i.test(url) ? ' target="_blank" rel="noopener"' : '';
    return `<a href="${url}"${ext}>${label}</a>`;
  });
  text = text.replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>');
  text = text.replace(/(^|[^*])\*([^*\n]+)\*/g, '$1<i>$2</i>');
  text = text.replace(/\u0001(\d+)\u0002/g, (m, i) => `<code>${codes[Number(i)]}</code>`);
  return text;
}

/* Minimal, safe-enough markdown: the source is HTML-escaped first, then a
 * line-based pass builds headings, code fences, tables, lists, quotes and
 * paragraphs. Internal .md links are routed by the docs click handler. */
function mdToHtml(source) {
  const lines = escapeHtml(source || '').split('\n');
  const out = [];
  let inCode = false;
  let listTag = null;
  let tableHead = false;
  let para = [];
  const flushPara = () => { if (para.length) { out.push(`<p>${mdInline(para.join(' '))}</p>`); para = []; } };
  const closeList = () => { if (listTag) { out.push(`</${listTag}>`); listTag = null; } };
  const closeTable = () => { if (tableHead) { out.push('</tbody></table>'); tableHead = false; } };
  lines.forEach((rawLine) => {
    const line = rawLine.replace(/\s+$/, '');
    if (/^```/.test(line)) {
      flushPara(); closeList(); closeTable();
      out.push(inCode ? '</code></pre>' : '<pre><code>');
      inCode = !inCode;
      return;
    }
    if (inCode) { out.push(line); return; }
    const heading = line.match(/^(#{1,4})\s+(.*)$/);
    if (heading) {
      flushPara(); closeList(); closeTable();
      const level = heading[1].length;
      out.push(`<h${level}>${mdInline(heading[2])}</h${level}>`);
      return;
    }
    if (/^\s*(-{3,}|\*{3,})\s*$/.test(line)) { flushPara(); closeList(); closeTable(); out.push('<hr>'); return; }
    if (/^(?:>|&gt;)\s?/.test(line)) {
      flushPara(); closeList(); closeTable();
      out.push(`<blockquote>${mdInline(line.replace(/^(?:>|&gt;)\s?/, ''))}</blockquote>`);
      return;
    }
    if (/^\s*\|/.test(line)) {
      flushPara(); closeList();
      if (/^[\s|:-]+$/.test(line)) return;           // separator row
      const cells = line.split('|').slice(1, -1).map((c) => c.trim());
      if (!tableHead) {
        out.push('<table><thead><tr>' + cells.map((c) => `<th>${mdInline(c)}</th>`).join('') + '</tr></thead><tbody>');
        tableHead = true;
      } else {
        out.push('<tr>' + cells.map((c) => `<td>${mdInline(c)}</td>`).join('') + '</tr>');
      }
      return;
    }
    closeTable();
    const ul = line.match(/^\s*[-*]\s+(.*)$/);
    const ol = line.match(/^\s*\d+[.)]\s+(.*)$/);
    if (ul || ol) {
      flushPara();
      const tag = ul ? 'ul' : 'ol';
      if (listTag !== tag) { closeList(); out.push(`<${tag}>`); listTag = tag; }
      out.push(`<li>${mdInline((ul || ol)[1])}</li>`);
      return;
    }
    if (!line.trim()) { flushPara(); closeList(); return; }
    closeList();
    para.push(line.trim());
  });
  flushPara(); closeList(); closeTable();
  if (inCode) out.push('</code></pre>');
  return out.join('\n');
}

/* ------------------------------------------------------- sidebar wiring */
function showInstallPlan(result) {
  const box = $('#setup-plan');
  if (!box) return;
  if (!result) { box.textContent = 'install request failed — see the event log'; box.classList.remove('hidden'); return; }
  const plan = result.plan || {};
  const commands = (plan.commands || []).map((cmd) => Array.isArray(cmd) ? cmd.join(' ') : String((cmd && cmd.command) || cmd));
  const lines = [
    `manager: ${plan.manager || '—'}${plan.supported === false ? ' (unsupported — install manually)' : ''}`,
    `missing: ${(plan.missing_tools || []).join(', ') || 'nothing'}`,
  ];
  if (commands.length) lines.push('', ...commands);
  if (result.after_missing) lines.push('', `still missing after run: ${result.after_missing.join(', ') || 'nothing'}`);
  box.textContent = lines.join('\n');
  box.classList.remove('hidden');
}

function wireNav() {
  try {
    if (localStorage.getItem('wp-side-collapsed') === '1') document.body.classList.add('side-collapsed');
  } catch (e) { /* storage unavailable */ }
  const toggleSide = () => {
    const on = document.body.classList.toggle('side-collapsed');
    try { localStorage.setItem('wp-side-collapsed', on ? '1' : '0'); } catch (e) { /* storage unavailable */ }
  };
  const collapseBtn = $('#btn-collapse');
  if (collapseBtn) collapseBtn.onclick = toggleSide;

  document.addEventListener('click', (event) => {
    const go = event.target.closest('[data-goto]');
    if (go) { gotoTab(go.dataset.goto); return; }
    const doc = event.target.closest('[data-doc]');
    if (doc) openDoc(doc.dataset.doc);
  });

  const rerenderTasks = () => { renderTasks._sig = null; if (SNAPSHOT) renderTasks(SNAPSHOT); };
  const statusSel = $('#sel-attempt-status');
  if (statusSel) statusSel.onchange = rerenderTasks;
  const attemptFilter = $('#inp-attempt-filter');
  if (attemptFilter) attemptFilter.oninput = rerenderTasks;

  const docSearch = $('#inp-doc-search');
  if (docSearch) docSearch.oninput = () => { DOCS.filter = docSearch.value.trim().toLowerCase(); renderDocsList(); };
  const docBody = $('#docs-content');
  if (docBody) docBody.addEventListener('click', (event) => {
    const link = event.target.closest('a');
    if (!link) return;
    const href = link.getAttribute('href') || '';
    if (/\.md(#.*)?$/i.test(href) && !/^https?:/i.test(href)) {
      event.preventDefault();
      openDoc(href.split('/').pop().split('#')[0]);
    }
  });

  const planBtn = $('#btn-setup-plan');
  if (planBtn) planBtn.onclick = () => api('/api/tools/install', { dry_run: true, yes: false }).then(showInstallPlan);
  const installBtn = $('#btn-setup-install');
  if (installBtn) installBtn.onclick = () => {
    if (!window.confirm('Install the missing tools on this machine now?')) return;
    installBtn.disabled = true;
    api('/api/tools/install', { dry_run: false, yes: true })
      .then(showInstallPlan)
      .then(() => { installBtn.disabled = false; });
  };
  const recheckBtn = $('#btn-setup-recheck');
  if (recheckBtn) recheckBtn.onclick = () => fetch('/api/tools?force=true').then((r) => r.json())
    .then(() => api('/api/state', null, 'GET').then((s) => {
      if (s && s.session) { SNAPSHOT = s; renderSetup._sig = null; render(); }
    }));
  const toDemo = $('#btn-setup-demo');
  if (toDemo) toDemo.onclick = () => { $('#chk-demo').checked = true; switchMode(true); };
  const toLive = $('#btn-setup-live');
  if (toLive) toLive.onclick = () => {
    if (!$('#chk-authorized').checked) { toast('tick “authorized” in the control bar first', true); return; }
    $('#chk-demo').checked = false;
    switchMode(false);
  };

  const ORDER = ['targets', 'tasks', 'devices', 'loot', 'ai', 'log', 'setup', 'settings', 'docs', 'about'];
  document.addEventListener('keydown', (event) => {
    if (event.metaKey || event.ctrlKey || event.altKey) return;
    const tag = (event.target.tagName || '').toUpperCase();
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || event.target.isContentEditable) return;
    if (event.key >= '0' && event.key <= '9') {
      const idx = event.key === '0' ? 9 : Number(event.key) - 1;
      if (ORDER[idx]) gotoTab(ORDER[idx]);
    } else if (event.key === '/') {
      event.preventDefault();
      gotoTab('targets');
      const filter = $('#inp-filter');
      if (filter) filter.focus();
    } else if (event.key === 'b' || event.key === 'B') {
      toggleSide();
    }
  });
}

wireNav();

wire();
