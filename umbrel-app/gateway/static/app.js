(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const state = { status: null, services: [], exposures: [], wg: null, search: '' };
  let pollTimer = null;

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function badge(text, cls) {
    return el('span', `badge ${cls || 'info'}`, text);
  }

  function showGlobal(kind, message) {
    const box = kind === 'ok' ? $('global-ok') : $('global-error');
    const other = kind === 'ok' ? $('global-error') : $('global-ok');
    other.hidden = true;
    box.textContent = message;
    box.hidden = false;
    window.clearTimeout(showGlobal._timer);
    showGlobal._timer = window.setTimeout(() => { box.hidden = true; }, 7000);
  }

  function showMsg(id, message, ok) {
    const box = $(id);
    box.textContent = message;
    box.className = `msg ${ok ? 'ok' : 'bad'}`;
    box.hidden = false;
  }

  async function api(path, options = {}) {
    const headers = { Accept: 'application/json' };
    if (options.body) headers['Content-Type'] = 'application/json';
    const res = await fetch(path, { ...options, headers: { ...headers, ...(options.headers || {}) } });
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch (_) { data = { error: text }; }
    if (!res.ok) {
      throw new Error((data && data.error) || `HTTP ${res.status}`);
    }
    return data;
  }

  function formatAgo(ts) {
    if (!ts) return 'nunca';
    const seconds = Math.max(0, Math.floor(Date.now() / 1000 - Number(ts)));
    if (seconds < 10) return 'ahora';
    if (seconds < 60) return `hace ${seconds}s`;
    if (seconds < 3600) return `hace ${Math.floor(seconds / 60)}m`;
    return `hace ${Math.floor(seconds / 3600)}h`;
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

  function setPill(id, text, cls) {
    const node = $(id);
    node.textContent = text;
    node.className = `pill ${cls || ''}`;
  }

  function renderStatus() {
    const st = state.status;
    if (!st) return;
    const wg = st.wg || {};
    const sync = st.last_sync || {};

    if (!wg.running) {
      setPill('pill-wg', 'Túnel parado', 'bad');
    } else if (wg.connected) {
      setPill('pill-wg', 'Túnel conectado', 'ok');
    } else {
      setPill('pill-wg', 'Túnel sin handshake', 'warn');
    }

    if (!st.paired) {
      setPill('pill-vps', 'VPS sin emparejar', 'bad');
    } else if (sync.ok) {
      setPill('pill-vps', 'VPS OK', 'ok');
    } else {
      setPill('pill-vps', 'VPS con errores', 'bad');
    }

    if (!sync.at) {
      setPill('pill-sync', 'Sin sincronizar', 'warn');
    } else {
      setPill('pill-sync', `Sync ${formatAgo(sync.at)}`, sync.ok ? 'ok' : 'bad');
    }

    $('stat-wg').textContent = wg.running ? (wg.connected ? 'Conectado' : 'Sin handshake') : 'Parado';
    $('stat-vps').textContent = st.paired ? 'Emparejado' : 'Sin emparejar';
    $('stat-open').textContent = `${st.exposures_enabled || 0} / ${st.exposures || 0}`;
    $('stat-services').textContent = String(st.services || 0);
    $('stat-sync').textContent = formatAgo(sync.at);

    $('pair-api').textContent = (st.vps && st.vps.api) || '—';
    $('pair-endpoint').textContent = (st.vps && st.vps.endpoint) || '—';
    $('pair-ip').textContent = wg.address || '—';

    $('wg-state').textContent = wg.running ? (wg.connected ? 'Conectado' : 'Activo, sin handshake') : 'Parado';
    $('wg-address').textContent = wg.address || '—';
    const peer = (wg.peers && wg.peers[0]) || null;
    if (peer && peer.latest_handshake) {
      $('wg-handshake').textContent = `${formatAgo(peer.latest_handshake)} · ↓${formatBytes(peer.rx)} ↑${formatBytes(peer.tx)}`;
    } else {
      $('wg-handshake').textContent = '—';
    }

    renderSyncDetail(sync);
  }

  function renderSyncDetail(sync) {
    const box = $('sync-detail');
    box.replaceChildren();
    if (!sync || !sync.at) {
      box.append(el('span', 'muted', 'Todavía no se ha sincronizado.'));
      return;
    }
    const line = el('div', sync.ok ? 'ok-line' : 'error-line');
    line.textContent = sync.ok
      ? `Correcto: ${sync.created || 0} creados, ${sync.updated || 0} actualizados, ${sync.deleted || 0} eliminados.`
      : `Con errores: ${sync.created || 0} creados, ${sync.updated || 0} actualizados, ${sync.deleted || 0} eliminados.`;
    box.append(line);
    if (sync.vps_status) {
      const vps = sync.vps_status;
      const info = el('div', 'muted');
      info.textContent = `VPS v${vps.version || '?'} · ${vps.peers_connected || 0} peer(s) conectados · ${vps.forwards_enabled || 0} puerto(s) activos`;
      box.append(info);
    }
    for (const error of sync.errors || []) {
      box.append(el('div', 'error-line', error));
    }
  }

  function renderServices() {
    const body = $('services-body');
    body.replaceChildren();
    const query = state.search.trim().toLowerCase();
    const list = state.services.filter((svc) => {
      const haystack = `${svc.app} ${svc.name} ${svc.service} ${svc.target_port}`.toLowerCase();
      return !query || haystack.includes(query);
    });
    $('services-empty').hidden = list.length > 0;

    for (const svc of list) {
      const tr = document.createElement('tr');

      const appCell = document.createElement('td');
      appCell.append(el('strong', '', svc.name));
      appCell.append(el('span', 'sub', `${svc.app}${svc.service && svc.service !== svc.name ? ` · ${svc.service}` : ''}`));
      tr.append(appCell);

      tr.append(el('td', '', `${svc.target_ip}:${svc.target_port}`));

      const notes = document.createElement('td');
      if (svc.sensitive) notes.append(badge('sensible', 'warn'));
      if (svc.system) notes.append(badge('sistema', 'info'));
      if (svc.exposed) notes.append(badge(svc.exposure_enabled ? 'abierto' : 'desactivado', svc.exposure_enabled ? 'ok' : 'warn'));
      if (!svc.sensitive && !svc.system && !svc.exposed) notes.append(badge('tcp', 'info'));
      if (svc.description) notes.title = svc.description;
      tr.append(notes);

      const portCell = document.createElement('td');
      const input = document.createElement('input');
      input.type = 'number';
      input.min = '1';
      input.max = '65535';
      input.value = String(svc.default_public_port || svc.target_port);
      input.dataset.portFor = svc.id;
      input.disabled = Boolean(svc.exposed);
      input.setAttribute('aria-label', `Puerto público para ${svc.name}`);
      portCell.append(input);
      tr.append(portCell);

      const actionCell = document.createElement('td');
      const label = svc.exposed ? (svc.exposure_enabled ? 'Abierto' : 'Desactivado') : 'Abrir';
      const button = el('button', svc.exposed ? 'ghost small' : 'small', label);
      button.type = 'button';
      button.disabled = Boolean(svc.exposed);
      if (!svc.exposed) {
        button.addEventListener('click', () => exposeService(svc));
      }
      actionCell.append(button);
      tr.append(actionCell);

      body.append(tr);
    }
  }

  function renderExposures() {
    const body = $('exposures-body');
    body.replaceChildren();
    $('exposures-empty').hidden = state.exposures.length > 0;

    for (const exposure of state.exposures) {
      const tr = document.createElement('tr');

      const nameCell = document.createElement('td');
      nameCell.append(el('strong', '', exposure.name || exposure.service || 'servicio'));
      nameCell.append(el('span', 'sub', `${exposure.target_ip}:${exposure.target_port}`));
      tr.append(nameCell);

      tr.append(el('td', '', String(exposure.public_port)));

      const targetCell = document.createElement('td');
      targetCell.append(el('span', '', `${exposure.tunnel_ip || '10.0.0.2'}:${exposure.tunnel_port}`));
      targetCell.append(el('span', 'sub', 'DNAT del VPS'));
      tr.append(targetCell);

      const toggleCell = document.createElement('td');
      const toggle = document.createElement('input');
      toggle.type = 'checkbox';
      toggle.checked = Boolean(exposure.enabled);
      toggle.addEventListener('change', () => updateExposure(exposure.id, { enabled: toggle.checked }));
      toggleCell.append(toggle);
      tr.append(toggleCell);

      const statusCell = document.createElement('td');
      if (exposure.sync_error) {
        statusCell.append(badge('error', 'bad'));
        statusCell.title = exposure.sync_error;
        statusCell.append(el('span', 'sub', exposure.sync_error));
      } else {
        statusCell.append(badge('sincronizado', 'ok'));
        if (exposure.vps_forward_id) statusCell.append(el('span', 'sub', `VPS ${exposure.vps_forward_id}`));
      }
      tr.append(statusCell);

      const actions = document.createElement('td');
      const change = el('button', 'ghost small', 'Puerto');
      change.type = 'button';
      change.addEventListener('click', () => changePublicPort(exposure));
      const remove = el('button', 'danger ghost small', 'Cerrar');
      remove.type = 'button';
      remove.addEventListener('click', () => deleteExposure(exposure));
      actions.append(change, remove);
      tr.append(actions);

      body.append(tr);
    }
  }

  function findPortInput(serviceId) {
    return Array.from(document.querySelectorAll('input[data-port-for]'))
      .find((node) => node.dataset.portFor === serviceId) || null;
  }

  async function exposeService(service) {
    const input = findPortInput(service.id);
    const publicPort = input ? Number(input.value) : service.default_public_port;
    try {
      const result = await api('/api/exposures', {
        method: 'POST',
        body: JSON.stringify({ service_id: service.id, public_port: publicPort }),
      });
      const errors = (result.sync && result.sync.errors) || [];
      if (errors.length) {
        showGlobal('error', errors.join(' · '));
      } else {
        showGlobal('ok', `Puerto ${publicPort} abierto para ${service.name}.`);
      }
      await refreshAll();
    } catch (err) {
      showGlobal('error', err.message);
    }
  }

  async function updateExposure(id, patch) {
    try {
      const result = await api(`/api/exposures/${id}`, { method: 'PATCH', body: JSON.stringify(patch) });
      const errors = (result.sync && result.sync.errors) || [];
      if (errors.length) showGlobal('error', errors.join(' · '));
      await refreshAll();
    } catch (err) {
      showGlobal('error', err.message);
      await refreshAll();
    }
  }

  async function changePublicPort(exposure) {
    const value = window.prompt('Nuevo puerto público en el VPS:', String(exposure.public_port));
    if (value === null) return;
    const port = Number(value);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      showGlobal('error', 'Puerto inválido.');
      return;
    }
    await updateExposure(exposure.id, { public_port: port });
  }

  async function deleteExposure(exposure) {
    if (!window.confirm(`¿Cerrar el puerto ${exposure.public_port}?`)) return;
    try {
      const result = await api(`/api/exposures/${exposure.id}`, { method: 'DELETE' });
      const errors = (result.sync && result.sync.errors) || [];
      if (errors.length) showGlobal('error', errors.join(' · '));
      else showGlobal('ok', 'Puerto cerrado.');
      await refreshAll();
    } catch (err) {
      showGlobal('error', err.message);
    }
  }

  async function refreshStatus() {
    const status = await api('/api/status');
    state.status = status;
    renderStatus();
  }

  async function refreshServices(force = false) {
    if (force) {
      await api('/api/services/refresh', { method: 'POST' });
    }
    state.services = await api('/api/services');
    renderServices();
  }

  async function refreshExposures() {
    state.exposures = await api('/api/exposures');
    renderExposures();
  }

  async function refreshAll() {
    const results = await Promise.allSettled([refreshStatus(), refreshServices(), refreshExposures()]);
    const failure = results.find((r) => r.status === 'rejected');
    if (failure) showGlobal('error', failure.reason.message || String(failure.reason));
  }

  async function loadWg() {
    const data = await api('/api/wireguard');
    state.wg = data;
    $('wg-config').textContent = data.config || '(sin configuración de WireGuard)';
    const vps = (state.status && state.status.vps) || {};
    $('manual-endpoint').value = vps.endpoint || '';
    $('manual-server-pub').value = vps.server_pubkey || '';
    return data;
  }

  function switchTab(name) {
    document.querySelectorAll('.tab').forEach((tab) => {
      tab.classList.toggle('active', tab.dataset.tab === name);
    });
    document.querySelectorAll('.tab-panel').forEach((panel) => {
      panel.classList.toggle('active', panel.id === `tab-${name}`);
    });
    if (name === 'conexion') {
      loadWg().catch((err) => showGlobal('error', err.message));
    }
    if (name === 'abiertos') {
      refreshExposures().catch((err) => showGlobal('error', err.message));
    }
  }

  function bind() {
    document.querySelectorAll('.tab').forEach((tab) => {
      tab.addEventListener('click', () => switchTab(tab.dataset.tab));
    });

    $('service-search').addEventListener('input', (event) => {
      state.search = event.target.value;
      renderServices();
    });

    $('refresh-services').addEventListener('click', async () => {
      try {
        await refreshServices(true);
        showGlobal('ok', 'Lista de servicios actualizada.');
      } catch (err) {
        showGlobal('error', err.message);
      }
    });

    $('sync-now').addEventListener('click', async () => {
      try {
        const result = await api('/api/sync', { method: 'POST' });
        if (result.errors && result.errors.length) showGlobal('error', result.errors.join(' · '));
        else showGlobal('ok', 'Sincronización correcta.');
        await refreshAll();
      } catch (err) {
        showGlobal('error', err.message);
      }
    });

    $('pair-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const code = $('pair-code').value.trim();
      if (!code) return;
      try {
        const result = await api('/api/pair', { method: 'POST', body: JSON.stringify({ code }) });
        showMsg('pair-msg', result.wg || 'Emparejado.', true);
        $('pair-code').value = '';
        await refreshAll();
        await loadWg();
      } catch (err) {
        showMsg('pair-msg', err.message, false);
      }
    });

    $('unpair').addEventListener('click', async () => {
      if (!window.confirm('¿Desemparejar y cerrar los puertos gestionados por esta app?')) return;
      try {
        await api('/api/unpair', { method: 'POST' });
        showGlobal('ok', 'Desemparejado. La configuración de WireGuard se ha eliminado.');
        await refreshAll();
        await loadWg();
      } catch (err) {
        showGlobal('error', err.message);
      }
    });

    $('toggle-wg').addEventListener('click', () => {
      const pre = $('wg-config');
      pre.classList.toggle('hidden');
      $('toggle-wg').textContent = pre.classList.contains('hidden') ? 'Mostrar' : 'Ocultar';
    });

    $('copy-wg').addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText($('wg-config').textContent);
        showGlobal('ok', 'Configuración copiada.');
      } catch (_) {
        showGlobal('error', 'No se pudo copiar al portapapeles.');
      }
    });

    $('manual-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      try {
        const result = await api('/api/wireguard/manual', {
          method: 'POST',
          body: JSON.stringify({
            endpoint: $('manual-endpoint').value.trim(),
            server_pubkey: $('manual-server-pub').value.trim(),
            client_ip: $('manual-client-ip').value.trim(),
          }),
        });
        $('manual-output').textContent = `${result.instructions}\n\n${result.config}`;
        $('manual-output').classList.remove('hidden');
        showMsg('manual-msg', result.message || 'Configuración generada.', Boolean(result.applied));
        await refreshAll();
        await loadWg();
      } catch (err) {
        showMsg('manual-msg', err.message, false);
      }
    });

    $('apply-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      try {
        const result = await api('/api/wireguard/apply', {
          method: 'POST',
          body: JSON.stringify({ config: $('apply-config').value }),
        });
        showMsg('apply-msg', result.message || 'Configuración aplicada.', Boolean(result.ok));
        await refreshAll();
        await loadWg();
      } catch (err) {
        showMsg('apply-msg', err.message, false);
      }
    });

    $('settings-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      try {
        await api('/api/settings', {
          method: 'POST',
          body: JSON.stringify({
            api: $('settings-api').value.trim(),
            token: $('settings-token').value.trim(),
            sync_interval: Number($('settings-interval').value),
          }),
        });
        $('settings-token').value = '';
        showMsg('settings-msg', 'Ajustes guardados.', true);
        await refreshAll();
      } catch (err) {
        showMsg('settings-msg', err.message, false);
      }
    });

    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') refreshAll().catch(() => {});
    });
  }

  async function init() {
    bind();
    try {
      await refreshAll();
      const settings = await api('/api/settings');
      $('settings-api').value = settings.api || '';
      $('settings-interval').value = String((settings.settings && settings.settings.sync_interval) || 30);
      if (state.status && state.status.paired) {
        await loadWg();
      }
    } catch (err) {
      showGlobal('error', err.message);
    }
    pollTimer = window.setInterval(() => {
      if (document.visibilityState === 'visible') refreshStatus().catch(() => {});
    }, 10000);
  }

  init();
})();
