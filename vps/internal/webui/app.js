(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  let token = sessionStorage.getItem('tw_token') || '';
  let timer = null;

  const state = {
    peers: [],
    forwards: [],
    status: null,
  };

  function showLogin(message) {
    $('panel').hidden = true;
    $('login').hidden = false;
    if (message) {
      const box = $('login-error');
      box.textContent = message;
      box.hidden = false;
    }
  }

  function showPanel() {
    $('login').hidden = true;
    $('panel').hidden = false;
  }

  async function api(path, options = {}) {
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers.Authorization = `Bearer ${token}`;
    const res = await fetch(path, { ...options, headers: { ...headers, ...(options.headers || {}) } });
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch (_) { data = text; }
    if (res.status === 401) {
      token = '';
      sessionStorage.removeItem('tw_token');
      showLogin('Token inválido o caducado.');
      throw new Error('no autorizado');
    }
    if (!res.ok) {
      throw new Error((data && data.error) || `HTTP ${res.status}`);
    }
    return data;
  }

  function badge(ok, textOk, textBad) {
    const span = document.createElement('span');
    span.className = `badge ${ok ? 'ok' : 'bad'}`;
    span.textContent = ok ? textOk : textBad;
    return span;
  }

  function cell(text) {
    const td = document.createElement('td');
    td.textContent = text;
    return td;
  }

  function formatBytes(bytes) {
    const n = Number(bytes) || 0;
    if (n <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    let v = n;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
    return `${v.toFixed(1)} ${units[i]}`;
  }

  function formatHandshake(ts) {
    if (!ts) return 'nunca';
    const seconds = Math.max(0, Math.floor(Date.now() / 1000 - ts));
    if (seconds < 60) return `hace ${seconds}s`;
    if (seconds < 3600) return `hace ${Math.floor(seconds / 60)}m`;
    return `hace ${Math.floor(seconds / 3600)}h`;
  }

  function formatUptime(seconds) {
    const s = Number(seconds) || 0;
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    if (d > 0) return `${d}d ${h}h`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
  }

  function renderStatus() {
    const st = state.status;
    if (!st) return;
    $('version').textContent = `v${st.version}`;
    $('wg-running').textContent = st.wg && st.wg.running ? 'activo' : 'parado';
    $('peers-count').textContent = String(st.peers_total);
    $('peers-connected').textContent = String(st.peers_connected);
    $('forwards-count').textContent = `${st.forwards_enabled}/${st.forwards_total}`;
    $('api-listen').textContent = st.api_listen;
    $('uptime').textContent = formatUptime(st.uptime_seconds);
  }

  function peerStatusFor(publicKey) {
    const peers = (state.status && state.status.wg && state.status.wg.peers) || [];
    return peers.find((p) => p.public_key === publicKey);
  }

  function renderPeers() {
    const body = $('peers-body');
    body.replaceChildren();
    if (state.peers.length === 0) {
      const tr = document.createElement('tr');
      const td = cell('Sin peers');
      td.colSpan = 5;
      td.className = 'muted';
      tr.append(td);
      body.append(tr);
      return;
    }
    for (const peer of state.peers) {
      const runtime = peerStatusFor(peer.public_key) || {};
      const tr = document.createElement('tr');
      tr.append(cell(peer.name || '—'));
      tr.append(cell(peer.allowed_ip));
      const status = document.createElement('td');
      status.append(badge(Boolean(runtime.connected), 'conectado', 'sin conexión'));
      tr.append(status);
      tr.append(cell(formatHandshake(runtime.latest_handshake)));
      const actions = document.createElement('td');
      const del = document.createElement('button');
      del.className = 'ghost';
      del.textContent = 'Eliminar';
      del.addEventListener('click', () => removePeer(peer));
      actions.append(del);
      tr.append(actions);
      body.append(tr);
    }
  }

  function renderTargets() {
    const select = $('target-ip');
    const current = select.value;
    select.replaceChildren();
    for (const peer of state.peers) {
      const option = document.createElement('option');
      option.value = peer.allowed_ip;
      option.textContent = `${peer.name || 'peer'} (${peer.allowed_ip})`;
      select.append(option);
    }
    if (current) select.value = current;
  }

  function renderForwards() {
    const body = $('forwards-body');
    body.replaceChildren();
    if (state.forwards.length === 0) {
      const tr = document.createElement('tr');
      const td = cell('Sin puertos abiertos');
      td.colSpan = 5;
      td.className = 'muted';
      tr.append(td);
      body.append(tr);
      return;
    }
    for (const fwd of state.forwards) {
      const tr = document.createElement('tr');
      tr.append(cell(fwd.name || '—'));
      tr.append(cell(`${fwd.domain || ''}:${fwd.public_port} (${fwd.access_mode || 'direct'})`));
      tr.append(cell(`${fwd.target_ip}:${fwd.target_port}`));
      const enabled = document.createElement('td');
      const toggle = document.createElement('input');
      toggle.type = 'checkbox';
      toggle.checked = Boolean(fwd.enabled);
      toggle.addEventListener('change', () => patchForward(fwd, { enabled: toggle.checked }));
      enabled.append(toggle);
      tr.append(enabled);
      const actions = document.createElement('td');
      const del = document.createElement('button');
      del.className = 'ghost';
      del.textContent = 'Cerrar';
      del.addEventListener('click', () => removeForward(fwd));
      actions.append(del);
      tr.append(actions);
      body.append(tr);
    }
  }

  function showMessage(id, text, ok) {
    const box = $(id);
    box.textContent = text;
    box.className = `msg ${ok ? 'ok' : 'bad'}`;
    box.hidden = false;
    setTimeout(() => { box.hidden = true; }, 6000);
  }

  async function load() {
    const [status, peers, forwards, certificates] = await Promise.all([
      api('/api/status'),
      api('/api/peers'),
      api('/api/forwards'),
      api('/api/certificates'),
    ]);
    state.status = status;
    state.peers = peers || [];
    state.forwards = forwards || [];
    renderStatus();
    renderPeers();
    renderTargets();
    renderForwards();
    $('certificates').replaceChildren();
    for (const cert of certificates || []) {
      const p = document.createElement('p');
      p.textContent = `${cert.domain} · ${cert.state}${cert.not_after ? ' · ' + new Date(cert.not_after).toLocaleString() : ''}${cert.error ? ' · ' + cert.error : ''}`;
      $('certificates').append(p);
    }
  }

  async function removePeer(peer) {
    if (!confirm(`¿Eliminar el peer ${peer.name || peer.allowed_ip}?`)) return;
    try {
      await api(`/api/peers/${peer.id}`, { method: 'DELETE' });
      await load();
    } catch (err) {
      showMessage('peer-msg', err.message, false);
    }
  }

  async function removeForward(fwd) {
    if (!confirm(`¿Cerrar el puerto ${fwd.public_port}?`)) return;
    try {
      await api(`/api/forwards/${fwd.id}`, { method: 'DELETE' });
      await load();
    } catch (err) {
      showMessage('forward-msg', err.message, false);
    }
  }

  async function patchForward(fwd, patch) {
    try {
      await api(`/api/forwards/${fwd.id}`, { method: 'PATCH', body: JSON.stringify(patch) });
      await load();
    } catch (err) {
      showMessage('forward-msg', err.message, false);
      await load();
    }
  }

  $('login-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    token = $('token').value.trim();
    sessionStorage.setItem('tw_token', token);
    $('login-error').hidden = true;
    try {
      await load();
      showPanel();
      startPolling();
    } catch (err) {
      showLogin(err.message === 'no autorizado' ? 'Token inválido.' : err.message);
    }
  });

  $('peer-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = new FormData(event.target);
    const body = {
      name: String(form.get('name') || '').trim(),
      allowed_ip: String(form.get('allowed_ip') || '').trim(),
      public_key: String(form.get('public_key') || '').trim(),
    };
    try {
      const created = await api('/api/peers', { method: 'POST', body: JSON.stringify(body) });
      event.target.reset();
      if (created && created.private_key) {
        showMessage('peer-msg', `Peer creado. Clave privada (guárdala): ${created.private_key}`, true);
      } else {
        showMessage('peer-msg', 'Peer creado.', true);
      }
      await load();
    } catch (err) {
      showMessage('peer-msg', err.message, false);
    }
  });

  $('forward-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = new FormData(event.target);
    const body = {
      name: String(form.get('name') || '').trim(),
      public_port: Number(form.get('public_port')),
      target_ip: String(form.get('target_ip') || '').trim(),
      target_port: Number(form.get('target_port')),
      protocol: String(form.get('protocol') || 'tcp'),
      access_mode: String(form.get('access_mode') || 'direct'),
      domain: String(form.get('domain') || '').trim().toLowerCase(),
      accept_acme_terms: form.get('accept_acme_terms') === 'on',
      enabled: true,
    };
    if (body.protocol === 'udp' && body.access_mode !== 'direct') {
      showMessage('forward-msg', 'UDP solo admite modo directo, sin terminación HTTP/HTTPS/TLS.', false);
      return;
    }
    try {
      await api('/api/forwards', { method: 'POST', body: JSON.stringify(body) });
      event.target.reset();
      showMessage('forward-msg', 'Puerto abierto.', true);
      await load();
    } catch (err) {
      showMessage('forward-msg', err.message, false);
    }
  });

  $('rotate').addEventListener('click', async () => {
    if (!confirm('Rotar el token invalidará el de Umbrel. ¿Continuar?')) return;
    try {
      const result = await api('/api/token/rotate', { method: 'POST' });
      token = result.token;
      sessionStorage.setItem('tw_token', token);
      showMessage('token-msg', `Nuevo token: ${result.token}`, true);
    } catch (err) {
      showMessage('token-msg', err.message, false);
    }
  });

  $('retry-certificates').addEventListener('click', async () => {
    try {
      await api('/api/certificates/retry', {method: 'POST'});
      showMessage('forward-msg', 'Reintento programado. No se eliminan certificados válidos.', true);
      await load();
    } catch (err) { showMessage('forward-msg', err.message, false); }
  });

  function startPolling() {
    if (timer) clearInterval(timer);
    timer = setInterval(() => {
      if (document.visibilityState === 'visible') {
        load().catch(() => {});
      }
    }, 10000);
  }

  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && token) {
      load().catch(() => {});
    }
  });

  if (token) {
    load().then(showPanel).then(startPolling).catch(() => showLogin());
  } else {
    showLogin();
  }
})();
