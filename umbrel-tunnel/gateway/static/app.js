(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);

  function readConfig() {
    const node = $('ut-config');
    if (!node) return { lang: 'es', csrf: '', i18n: {} };
    try {
      return JSON.parse(node.textContent || '{}');
    } catch (_) {
      return { lang: 'es', csrf: '', i18n: {} };
    }
  }

  const UT = readConfig();
  const state = {
    status: null,
    services: [],
    exposures: [],
    manualServices: [],
    wg: null,
    bootstrap: null,
    search: '',
    filter: 'all',
  };
  let pollTimer = null;

  function t(key, params) {
    let text = (UT.i18n && UT.i18n[key]) || key;
    if (params) {
      text = text.replace(/\{(\w+)\}/g, (match, name) => (
        Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : match
      ));
    }
    return text;
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function badge(text, cls) {
    return el('span', `badge ${cls || 'info'}`, text);
  }

  function ask(message, value) {
    return new Promise((resolve) => {
      const previous = document.activeElement;
      const dialog = el('dialog', 'action-dialog');
      const form = el('form', 'stack');
      form.method = 'dialog';
      const title = el('p', '', message);
      title.id = 'action-dialog-title';
      dialog.setAttribute('aria-labelledby', title.id);
      form.append(title);
      let input;
      if (value !== undefined) {
        input = el('input');
        input.type = 'number'; input.min = '1'; input.max = '65535'; input.required = true;
        input.value = String(value);
        input.setAttribute('aria-label', message);
        form.append(input);
      }
      const actions = el('div', 'row');
      const cancel = el('button', 'ghost', t('common.close'));
      cancel.type = 'button';
      cancel.addEventListener('click', () => dialog.close());
      const ok = el('button', '', t('common.ok'));
      ok.value = 'ok';
      actions.append(cancel, ok);
      form.append(actions);
      dialog.append(form);
      document.body.append(dialog);
      dialog.addEventListener('close', () => {
        const result = dialog.returnValue === 'ok' ? (input ? input.value : true) : null;
        dialog.remove();
        if (previous && previous.isConnected) previous.focus();
        resolve(result);
      }, { once: true });
      dialog.showModal();
      (input || cancel).focus();
    });
  }

  function showGlobal(kind, message) {
    const stack = $('toast-stack');
    if (!stack) return;
    // Errors stay until the user dismisses them: the old 8-second alert made
    // failed opens look like nothing had happened.
    while (stack.children.length >= 4) stack.firstElementChild.remove();
    const toast = el('div', `toast ${kind === 'ok' ? 'ok' : 'error'}`);
    toast.setAttribute('role', kind === 'ok' ? 'status' : 'alert');
    toast.append(el('div', 'toast-text', message));
    const close = el('button', 'toast-close', '×');
    close.type = 'button';
    close.setAttribute('aria-label', t('common.close'));
    close.addEventListener('click', () => toast.remove());
    toast.append(close);
    stack.append(toast);
    if (kind === 'ok') {
      window.setTimeout(() => toast.remove(), 8000);
    }
  }

  function syncFeedback(result, okMessage, changedMessage) {
    // ``/api/sync`` returns the sync result directly; other endpoints wrap it
    // in ``{sync: ...}``. Accept both so a failed manual sync is never
    // reported as successful.
    const sync = (result && result.sync) || result || {};
    const details = sync.details || [];
    if (details.length) {
      showGlobal('error', details.join('\n'));
      return false;
    }
    const errors = sync.errors || [];
    if (errors.length) {
      showGlobal('error', errors.join(' · '));
      return false;
    }
    if (result && result.port_changed && result.requested_public_port) {
      showGlobal('warn', changedMessage || t('open.port_changed', {
        requested: result.requested_public_port,
        port: result.exposure ? result.exposure.public_port : '',
      }));
    }
    if (okMessage) showGlobal('ok', okMessage);
    return true;
  }

  function setPending(button, pending, label) {
    if (!button) return;
    if (pending) {
      button.dataset.label = button.textContent;
      button.disabled = true;
      button.textContent = label;
    } else {
      button.disabled = false;
      if (button.dataset.label) button.textContent = button.dataset.label;
    }
  }

  function showMsg(id, message, ok) {
    const box = $(id);
    box.textContent = message;
    box.className = `msg ${ok ? 'ok' : 'bad'}`;
    box.hidden = false;
  }

  async function api(path, options = {}) {
    const method = (options.method || 'GET').toUpperCase();
    const headers = { Accept: 'application/json' };
    if (options.body) headers['Content-Type'] = 'application/json';
    if (method !== 'GET' && method !== 'HEAD') headers['X-CSRF-Token'] = UT.csrf || '';
    const res = await fetch(path, {
      ...options,
      headers: { ...headers, ...(options.headers || {}) },
    });
    const text = await res.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch (_) {
      data = { error: text };
    }
    if (res.status === 401) {
      window.location.href = '/login';
      throw new Error(t('error.unauthorized'));
    }
    if (!res.ok) {
      const err = new Error((data && (data.error || data.detail)) || `HTTP ${res.status}`);
      err.code = data && data.code;
      err.detail = data && data.detail;
      throw err;
    }
    return data;
  }

  function formatAgo(ts) {
    if (!ts) return t('common.never');
    const seconds = Math.max(0, Math.floor(Date.now() / 1000 - Number(ts)));
    if (seconds < 10) return t('common.now');
    if (seconds < 60) return t('common.ago_seconds', { count: seconds });
    if (seconds < 3600) return t('common.ago_minutes', { count: Math.floor(seconds / 60) });
    return t('common.ago_hours', { count: Math.floor(seconds / 3600) });
  }

  function formatBytes(bytes) {
    const n = Number(bytes) || 0;
    if (n <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    let v = n;
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i += 1;
    }
    return `${v.toFixed(1)} ${units[i]}`;
  }

  function setPill(id, text, cls) {
    const node = $(id);
    if (!node) return;
    node.textContent = text;
    node.className = `pill ${cls || ''}`;
  }

  function renderStatus() {
    const st = state.status;
    if (!st) return;
    const wg = st.wg || {};
    const sync = st.last_sync || {};

    if (!wg.running) {
      setPill('pill-wg', t('status.wg_stopped'), 'bad');
    } else if (wg.connected) {
      setPill('pill-wg', t('status.wg_connected'), 'ok');
    } else {
      setPill('pill-wg', t('status.wg_no_handshake'), 'warn');
    }

    if (!st.paired) {
      setPill('pill-vps', t('status.vps_unpaired'), 'bad');
    } else if (sync.ok && !Number(st.exposures_failed || 0)) {
      setPill('pill-vps', t('status.vps_ok'), 'ok');
    } else {
      setPill('pill-vps', t('status.vps_errors'), 'bad');
    }

    if (!sync.at) {
      setPill('pill-sync', t('status.sync_never'), 'warn');
    } else {
      setPill('pill-sync', t('status.sync_ago', { ago: formatAgo(sync.at) }), sync.ok ? 'ok' : 'bad');
    }

    $('stat-wg').textContent = wg.running
      ? (wg.connected ? t('stats.wg_connected') : t('stats.wg_no_handshake'))
      : t('stats.wg_stopped');
    $('stat-vps').textContent = st.paired ? t('stats.vps_paired') : t('stats.vps_unpaired');
    $('stat-open').textContent = `${st.exposures_enabled || 0} / ${st.exposures || 0}`;
    $('stat-services').textContent = String(st.services || 0);
    $('stat-sync').textContent = formatAgo(sync.at);

    const vps = st.vps || {};
    $('pair-api').textContent = vps.api || t('common.dash');
    $('pair-endpoint').textContent = vps.endpoint || t('common.dash');
    $('pair-ip').textContent = vps.umbrel_ip || wg.address || t('common.dash');
    $('pair-subnet').textContent = vps.subnet || t('common.dash');

    $('wg-state').textContent = wg.running
      ? (wg.connected ? t('connection.wg_connected') : t('connection.wg_no_handshake'))
      : t('connection.wg_stopped');
    $('wg-address').textContent = wg.address || t('common.dash');
    const peer = (wg.peers && wg.peers[0]) || null;
    if (peer && peer.latest_handshake) {
      $('wg-handshake').textContent = t('connection.handshake_line', {
        ago: formatAgo(peer.latest_handshake),
        rx: formatBytes(peer.rx),
        tx: formatBytes(peer.tx),
      });
    } else {
      $('wg-handshake').textContent = t('common.dash');
    }

    renderSyncDetail(sync);
    renderBootstrap();
  }

  function renderBootstrap() {
    const onboarding = $('onboarding');
    const pairCard = $('pair-card');
    if (!onboarding || !pairCard) return;
    const paired = Boolean(state.status && state.status.paired);
    const data = state.bootstrap || {};
    const active = Boolean(data.active);
    onboarding.hidden = paired;
    // Keep the manual ut1 form available when there is no pending bootstrap
    // (for VPS installs done outside the app-first flow).
    pairCard.hidden = !paired && active;
    const unpairButton = $('unpair');
    if (unpairButton) unpairButton.hidden = !paired;
    if (paired) return;

    $('bootstrap-form').hidden = active;
    $('bootstrap-pending').hidden = !active;
    if (!active) return;

    $('bootstrap-command').textContent = data.command || '';
    $('bootstrap-public-key').textContent = data.public_key || t('common.dash');
    $('bootstrap-endpoint').textContent = data.endpoint || t('common.dash');
    $('bootstrap-subnet').textContent = data.subnet || t('common.dash');
    $('bootstrap-tunnel-ip').textContent = data.umbrel_ip || t('common.dash');
  }

  function renderSyncDetail(sync) {
    const box = $('sync-detail');
    if (!box) return;
    box.replaceChildren();
    if (!sync || !sync.at) {
      box.append(el('span', 'muted', t('sync.empty')));
      return;
    }
    const line = el('div', sync.ok ? 'ok-line' : 'error-line');
    line.textContent = t(sync.ok ? 'sync.ok' : 'sync.error', {
      created: sync.created || 0,
      updated: sync.updated || 0,
      deleted: sync.deleted || 0,
    });
    box.append(line);
    if (sync.vps_status) {
      const vps = sync.vps_status;
      box.append(el('div', 'muted', t('sync.vps_info', {
        version: vps.version || '?',
        peers: vps.peers_connected || 0,
        forwards: vps.forwards_enabled || 0,
      })));
    }
    for (const error of sync.errors || []) {
      box.append(el('div', 'error-line', error));
    }
    const details = sync.details || [];
    if (details.length) {
      const wrap = el('details', 'details');
      wrap.append(el('summary', '', t('sync.details')));
      for (const detail of details) {
        wrap.append(el('div', 'error-line', detail));
      }
      box.append(wrap);
    }
  }

  function serviceName(svc) {
    if (svc.service_identified === false) return t('services.unidentified_service', { port: svc.target_port });
    return svc.name_key ? t(svc.name_key) : svc.name;
  }

  function serviceDescription(svc) {
    // Only system services have translated descriptions. Catalog descriptions
    // are Spanish-only, so do not leak them into the English UI.
    if (!svc.name_key) return '';
    const key = `${svc.name_key}.description`;
    const translated = t(key);
    return translated !== key ? translated : (svc.description || '');
  }

  function renderServices() {
    if (document.activeElement && document.activeElement.matches('#services-body input')) return;
    const body = $('services-body');
    body.replaceChildren();
    const query = state.search.trim().toLowerCase();
    const candidates = [...state.services];
    for (const exposure of state.exposures) {
      if (!candidates.some((svc) => svc.exposure_id === exposure.id)) {
        candidates.push({ id: exposure.service_id || exposure.id, app: exposure.app || exposure.name,
          name: exposure.name, target_ip: exposure.target_ip, target_port: exposure.target_port,
          protocol: exposure.protocol, exposed: true, exposure_id: exposure.id,
          exposure_enabled: exposure.enabled, exposure_error: Boolean(exposure.sync_error),
          public_port: exposure.public_port, can_open: true });
      }
    }
    const list = candidates.filter((svc) => {
      const haystack = `${svc.app} ${serviceName(svc)} ${svc.service} ${svc.target_port}`.toLowerCase();
      const matches = state.filter === 'all'
        || (state.filter === 'published' && svc.exposed)
        || (state.filter === 'closed' && !svc.exposed)
        || (state.filter === 'errors' && svc.exposure_error);
      return matches && (!query || haystack.includes(query));
    });
    $('services-empty').hidden = list.length > 0;

    for (const svc of list) {
      const tr = document.createElement('tr');
      const displayName = serviceName(svc);

      const appCell = document.createElement('td');
      appCell.append(el('strong', '', svc.id.startsWith('manual:') ? displayName : svc.app));
      appCell.append(badge(t(svc.id.startsWith('manual:') ? 'ui.manual' : 'ui.detected'), 'info'));
      const sub = `${displayName}${svc.service_identified !== false && svc.service && svc.service !== displayName ? ` · ${svc.service}` : ''}`;
      if (!svc.id.startsWith('manual:')) appCell.append(el('span', 'sub', sub));
      tr.append(appCell);

      const unidentified = svc.service_identified === false;
      const destination = el('td', '', unidentified
        ? t('services.unidentified_container')
        : `${svc.container_name || svc.target_ip}:${svc.target_port}`);
      if (!svc.system) destination.append(el('span', 'sub', t(unidentified ? 'services.detected_ip' : 'services.internal_ip', {
        ip: svc.resolved_ip || t('services.ip_unavailable'),
      })));
      tr.append(destination);

      const notes = document.createElement('td');
      notes.append(badge(String(svc.protocol || 'tcp').toUpperCase(), 'info'));
      if (svc.sensitive) notes.append(badge(t('services.badge.sensitive'), 'warn'));
      if (svc.system) notes.append(badge(t('services.badge.system'), 'info'));
      if (svc.exposed) {
        notes.append(badge(
          svc.exposure_enabled ? t('services.badge.open') : t('services.badge.off'),
          svc.exposure_enabled ? 'ok' : 'warn',
        ));
        if (svc.exposure_error) notes.append(badge(t('open.badge.error'), 'bad'));
      } else if (svc.protocol === 'udp') {
        notes.append(badge(t('services.badge.udp'), 'info'));
      } else {
        notes.append(badge(t('services.badge.tcp'), 'info'));
      }
      const description = serviceDescription(svc);
      if (description) notes.title = description;
      tr.append(notes);

      const portCell = document.createElement('td');
      const input = document.createElement('input');
      input.type = 'number';
      input.min = '1';
      input.max = '65535';
      input.value = String(svc.exposed && svc.public_port
        ? svc.public_port
        : (svc.default_public_port || svc.target_port));
      input.dataset.portFor = svc.id;
      input.disabled = Boolean(svc.exposed) || !svc.can_open;
      input.setAttribute('aria-label', t('services.aria.port', { name: displayName }));
      input.title = t('ui.help.public');
      portCell.append(input);
      tr.append(portCell);

      const actionCell = document.createElement('td');
      let label = t('services.open');
      let className = 'small';
      if (svc.exposed) {
        label = svc.exposure_enabled ? t('services.opened') : t('services.disabled');
        className = 'ghost small';
      } else if (!svc.can_open) {
        label = t('services.badge.udp');
        className = 'ghost small';
      }
      const button = el('button', className, label);
      button.type = 'button';
      button.disabled = Boolean(svc.exposed) || !svc.can_open;
      if (!svc.exposed && !svc.can_open) button.title = t('services.udp_unsupported');
      if (!svc.exposed && svc.can_open) {
        button.addEventListener('click', () => exposeService(svc, button));
      }
      actionCell.append(button);
      const exposure = state.exposures.find((item) => item.id === svc.exposure_id);
      if (exposure) {
        if (exposure.sync_error) {
          const details = el('details', 'details');
          details.append(el('summary', '', t('sync.details')),
            el('span', 'sub', exposure.sync_error_detail || exposure.sync_error));
          notes.append(details);
        }
        button.hidden = true;
        const action = (key, callback) => {
          const node = el('button', 'ghost small', t(key));
          node.type = 'button';
          node.addEventListener('click', callback);
          actionCell.append(node);
        };
        action(exposure.enabled ? 'ui.pause' : 'ui.resume', () => updateExposure(exposure.id, { enabled: !exposure.enabled }));
        action('open.change_port', () => changePublicPort(exposure));
        action('open.close', () => deleteExposure(exposure));
        if (exposure.sync_error) action('open.retry', () => retryExposure(exposure));
        if (exposure.remote_conflict) {
          ['adopt', 'restore'].forEach((choice) => action(`ui.${choice}`, async () => {
            try {
              const result = await api(`/api/exposures/${exposure.id}/resolve`, { method: 'POST', body: JSON.stringify({ action: choice }) });
              syncFeedback(result, '');
              await refreshAll();
            } catch (err) { showGlobal('error', err.message); }
          }));
        }
        if (!exposure.sync_error && exposure.enabled) notes.append(el('span', 'sub', t('ui.applied')));
        const endpoint = ((state.status || {}).vps || {}).endpoint || '';
        if (endpoint) {
          const host = endpoint.replace(/:\d+$/, '');
          const address = `${host}:${exposure.public_port}`;
          portCell.append(el('span', 'sub', address));
          action('ui.copy', async () => {
            try { await navigator.clipboard.writeText(address); showGlobal('ok', t('ui.copy')); }
            catch (_) { showGlobal('error', t('connection.copy_failed')); }
          });
        }
      }
      const manual = state.manualServices.find((item) => svc.id.startsWith(`manual:${item.id}:`));
      if (manual && !exposure) {
        const remove = el('button', 'danger ghost small', t('advanced.manual_remove'));
        remove.addEventListener('click', () => deleteManualService(manual));
        actionCell.append(remove);
      }
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
      nameCell.append(el('strong', '', exposure.name || exposure.service || t('manual.app')));
      nameCell.append(el('span', 'sub', `${exposure.target_ip}:${exposure.target_port}`));
      tr.append(nameCell);

      tr.append(el('td', '', String(exposure.public_port)));

      const targetCell = document.createElement('td');
      targetCell.append(el('span', '', `${exposure.tunnel_ip || '10.0.0.2'}:${exposure.tunnel_port}`));
      targetCell.append(el('span', 'sub', t('open.dnat')));
      tr.append(targetCell);

      const toggleCell = document.createElement('td');
      const toggle = document.createElement('input');
      toggle.type = 'checkbox';
      toggle.checked = Boolean(exposure.enabled);
      toggle.setAttribute('aria-label', exposure.name || exposure.id);
      toggle.addEventListener('change', () => updateExposure(exposure.id, { enabled: toggle.checked }));
      toggleCell.append(toggle);
      tr.append(toggleCell);

      const statusCell = document.createElement('td');
      if (exposure.sync_error) {
        statusCell.append(badge(t('open.badge.error'), 'bad'));
        const detail = exposure.sync_error_detail || exposure.sync_error;
        statusCell.title = detail;
        statusCell.append(el('span', 'sub', exposure.sync_error));
        if (detail && detail !== exposure.sync_error) {
          const wrap = el('details', 'details');
          wrap.append(el('summary', '', t('sync.details')));
          wrap.append(el('div', 'error-line', detail));
          statusCell.append(wrap);
        }
      } else {
        statusCell.append(badge(t('open.badge.synced'), 'ok'));
        if (exposure.vps_forward_id) statusCell.append(el('span', 'sub', `VPS ${exposure.vps_forward_id}`));
      }
      tr.append(statusCell);

      const actions = document.createElement('td');
      if (exposure.sync_error) {
        const retry = el('button', 'ghost small', t('open.retry'));
        retry.type = 'button';
        retry.addEventListener('click', () => retryExposure(exposure, retry));
        actions.append(retry);
      }
      const change = el('button', 'ghost small', t('open.change_port'));
      change.type = 'button';
      change.addEventListener('click', () => changePublicPort(exposure));
      const remove = el('button', 'danger ghost small', t('open.close'));
      remove.type = 'button';
      remove.addEventListener('click', () => deleteExposure(exposure));
      actions.append(change, remove);
      tr.append(actions);

      body.append(tr);
    }
  }

  function renderManualServices() {
    const body = $('manual-services-body');
    body.replaceChildren();
    $('manual-services-empty').hidden = state.manualServices.length > 0;
    for (const item of state.manualServices) {
      const tr = document.createElement('tr');
      const nameCell = document.createElement('td');
      nameCell.append(el('strong', '', item.name || `${item.host}:${item.port}`));
      nameCell.append(el('span', 'sub', item.id ? `ID ${item.id}` : ''));
      tr.append(nameCell);
      tr.append(el('td', '', item.target || `${item.host}:${item.port}`));
      tr.append(el('td', '', String(item.protocol || 'tcp').toUpperCase()));

      const statusCell = document.createElement('td');
      const exposure = item.exposure || null;
      if (!exposure) {
        statusCell.append(badge(t('advanced.manual_status_closed'), 'info'));
      } else if (exposure.sync_error) {
        statusCell.append(badge(t('advanced.manual_exposure_error'), 'bad'));
        statusCell.append(el('span', 'sub', exposure.sync_error_detail || exposure.sync_error));
      } else {
        statusCell.append(badge(t('advanced.manual_status_open', {
          port: exposure.public_port,
        }), 'ok'));
      }
      tr.append(statusCell);

      const actions = document.createElement('td');
      if (!exposure && ['tcp', 'udp'].includes(item.protocol || 'tcp')) {
        const open = el('button', 'small', t('advanced.manual_open'));
        open.type = 'button';
        open.addEventListener('click', () => openManualService(item, open));
        actions.append(open);
      } else if (exposure && exposure.sync_error) {
        const retry = el('button', 'ghost small', t('advanced.manual_retry'));
        retry.type = 'button';
        retry.addEventListener('click', () => retryExposure(exposure, retry));
        actions.append(retry);
      } else if (!exposure) {
        const disabled = el('button', 'ghost small', t('services.badge.udp'));
        disabled.type = 'button';
        disabled.disabled = true;
        disabled.title = t('advanced.manual_udp_open');
        actions.append(disabled);
      }
      if (exposure) {
        const view = el('button', 'ghost small', t('advanced.manual_view'));
        view.type = 'button';
        view.addEventListener('click', () => switchTab('open'));
        const close = el('button', 'danger ghost small', t('open.close'));
        close.type = 'button';
        close.addEventListener('click', () => deleteExposure(exposure));
        actions.append(view, close);
      }
      const remove = el('button', 'danger ghost small', t('advanced.manual_remove'));
      remove.type = 'button';
      remove.addEventListener('click', () => deleteManualService(item));
      actions.append(remove);
      tr.append(actions);
      body.append(tr);
    }
  }

  function findPortInput(serviceId) {
    return Array.from(document.querySelectorAll('input[data-port-for]'))
      .find((node) => node.dataset.portFor === serviceId) || null;
  }

  async function exposeService(service, button) {
    if (service.sensitive && !await ask(t('ui.sensitive'))) return;
    if (!service.can_open) {
      showGlobal('error', t('services.udp_unsupported'));
      return;
    }
    const input = findPortInput(service.id);
    const publicPort = input && input.value ? Number(input.value) : null;
    setPending(button, true, t('advanced.manual_open_pending'));
    try {
      const result = await api('/api/exposures', {
        method: 'POST',
        body: JSON.stringify({ service_id: service.id, public_port: publicPort }),
      });
      result.requested_public_port = publicPort;
      const port = result.exposure ? result.exposure.public_port : publicPort;
      syncFeedback(result, t('services.port_opened', { port, name: serviceName(service) }));
      await refreshAll();
    } catch (err) {
      showGlobal('error', err.message);
    } finally {
      setPending(button, false);
    }
  }

  async function updateExposure(id, patch) {
    try {
      const result = await api(`/api/exposures/${id}`, { method: 'PATCH', body: JSON.stringify(patch) });
      syncFeedback(result, '');
      await refreshAll();
    } catch (err) {
      showGlobal('error', err.message);
      await refreshAll();
    }
  }

  async function retryExposure(exposure, button) {
    setPending(button, true, t('open.retrying'));
    try {
      const result = await api(`/api/exposures/${exposure.id}/retry`, { method: 'POST' });
      const ok = syncFeedback(result, t('open.retry_ok', { port: exposure.public_port }));
      if (!ok) showGlobal('error', t('open.retry_failed'));
      await refreshAll();
    } catch (err) {
      showGlobal('error', err.message);
      await refreshAll();
    } finally {
      setPending(button, false);
    }
  }

  async function openManualService(item, button) {
    const input = $('manual-service-public-port');
    const requested = input && input.value ? Number(input.value) : null;
    setPending(button, true, t('advanced.manual_open_pending'));
    try {
      const result = await api(`/api/manual-services/${item.id}/open`, {
        method: 'POST',
        body: JSON.stringify({ public_port: requested }),
      });
      result.requested_public_port = requested;
      const port = result.exposure ? result.exposure.public_port : '';
      const ok = syncFeedback(
        result,
        result.existing
          ? t('advanced.manual_port_opened', { port })
          : t('advanced.manual_opened', { port }),
        t('advanced.manual_public_changed', { requested, port }),
      );
      if (!ok) showGlobal('error', t('advanced.manual_open_hint'));
      await refreshAll();
    } catch (err) {
      showGlobal('error', err.message);
      await refreshAll();
    } finally {
      setPending(button, false);
    }
  }

  async function changePublicPort(exposure) {
    const value = await ask(`${exposure.name || exposure.id}: ${t('open.change_prompt')}`, exposure.public_port);
    if (value === null) return;
    const port = Number(value);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      showGlobal('error', t('open.invalid_port'));
      return;
    }
    await updateExposure(exposure.id, { public_port: port });
  }

  async function deleteExposure(exposure) {
    if (!await ask(t('open.close_confirm', { port: exposure.public_port }))) return;
    try {
      const result = await api(`/api/exposures/${exposure.id}`, { method: 'DELETE' });
      syncFeedback(result, t('services.port_closed'));
      await refreshAll();
    } catch (err) {
      showGlobal('error', err.message);
    }
  }

  async function deleteManualService(item) {
    const name = item.name || `${item.host}:${item.port}`;
    if (!await ask(t('advanced.manual_confirm_remove', { name }))) return;
    try {
      await api(`/api/manual-services/${item.id}`, { method: 'DELETE' });
      showMsg('manual-service-msg', t('advanced.manual_removed'), true);
      await refreshManualServices();
      await refreshServices();
      showGlobal('ok', t('advanced.manual_removed'));
    } catch (err) {
      const message = err.code === 'manual_service_in_use'
        ? t('advanced.manual_in_use')
        : err.message;
      showMsg('manual-service-msg', message, false);
      showGlobal('error', message);
    }
  }

  function renderDiagnostics(data) {
    const box = $('diagnostics-result');
    if (!box) return;
    box.replaceChildren();
    box.classList.remove('muted');
    const checks = data.checks || [];
    const failed = checks.filter((check) => !check.ok);
    box.append(el(
      'div',
      failed.length ? 'error-line' : 'ok-line',
      failed.length ? t('advanced.diag_failed') : t('advanced.diag_ok'),
    ));

    const list = el('div', 'diag-checks');
    for (const check of checks) {
      const row = el('div', `diag-check ${check.ok ? 'ok' : 'bad'}`);
      row.append(badge(check.ok ? t('common.ok') : t('common.error'), check.ok ? 'ok' : 'bad'));
      row.append(el('span', '', t(`advanced.diag_check.${check.id}`)));
      if (check.detail) row.append(el('span', 'sub', check.detail));
      list.append(row);
    }
    box.append(list);

    const vps = data.vps || {};
    const forwards = data.forwards || {};
    if (vps.status) {
      box.append(el('div', 'muted', t('advanced.diag_vps', {
        version: vps.status.version || '?',
        peers: vps.status.peers_connected || 0,
        forwards: forwards.ours || 0,
      })));
    }
    if (vps.error) box.append(el('div', 'error-line', vps.error));
    const peer = data.peer || {};
    const vpsInfo = (state.status && state.status.vps) || {};
    if (data.paired && peer.present === false) {
      box.append(el('div', 'error-line', t('advanced.diag_peer_missing', {
        ip: vpsInfo.umbrel_ip || '',
      })));
    }
    if (data.paired && peer.present && peer.matches === false) {
      box.append(el('div', 'error-line', t('advanced.diag_peer_mismatch')));
    }
    if (!forwards.error) {
      box.append(el('div', 'muted', t('advanced.diag_forwards', {
        ours: forwards.ours || 0,
        total: forwards.total || 0,
      })));
    }
    if (data.proxy && !data.proxy.running) {
      box.append(el('div', 'muted', t('advanced.diag_proxy_off')));
    }
    for (const exposure of (data.exposures || []).filter((item) => !item.sync_ok)) {
      box.append(el('div', 'error-line', t('advanced.diag_exposure_error', {
        name: exposure.name || exposure.id,
        error: exposure.sync_error || '',
      })));
    }
  }

  async function runDiagnostics(button) {
    setPending(button, true, t('advanced.diag_running'));
    try {
      const data = await api('/api/diagnostics');
      renderDiagnostics(data);
    } catch (err) {
      const box = $('diagnostics-result');
      if (box) {
        box.classList.remove('muted');
        box.replaceChildren(el('div', 'error-line', err.message));
      }
      showGlobal('error', err.message);
    } finally {
      setPending(button, false);
    }
  }

  async function refreshStatus() {
    const status = await api('/api/status');
    state.status = status;
    renderStatus();
  }

  async function refreshBootstrap() {
    state.bootstrap = await api('/api/bootstrap');
    renderBootstrap();
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

  async function refreshManualServices() {
    state.manualServices = await api('/api/manual-services');
    renderManualServices();
  }

  async function refreshSettings() {
    const settings = await api('/api/settings');
    $('settings-api').value = settings.api || '';
    $('settings-interval').value = String((settings.settings && settings.settings.sync_interval) || 30);
  }

  async function refreshAll() {
    const results = await Promise.allSettled([
      refreshStatus(),
      refreshBootstrap(),
      refreshServices(),
      refreshExposures(),
      refreshManualServices(),
    ]);
    const failure = results.find((r) => r.status === 'rejected');
    renderServices();
    if (failure) showGlobal('error', failure.reason.message || String(failure.reason));
  }

  async function loadWg() {
    const data = await api('/api/wireguard');
    state.wg = data;
    $('wg-config').textContent = data.config || t('connection.wg_redacted');
    $('wg-public-key').textContent = data.public_key || t('common.dash');
    $('wg-server-key').textContent = data.server_pubkey || t('common.dash');
    const vps = (state.status && state.status.vps) || {};
    $('manual-endpoint').value = data.endpoint || vps.endpoint || '';
    $('manual-server-pub').value = data.server_pubkey || vps.server_pubkey || '';
    $('manual-client-ip').value = data.address || vps.umbrel_ip || '10.0.0.2';
    $('manual-subnet').value = data.subnet || vps.subnet || '10.0.0.0/24';
    return data;
  }

  function switchTab(name) {
    if (name === 'open' || name === 'advanced') name = name === 'open' ? 'services' : 'connection';
    document.querySelectorAll('.tab').forEach((tab) => {
      const active = tab.dataset.tab === name;
      tab.classList.toggle('active', active);
      tab.setAttribute('aria-selected', active ? 'true' : 'false');
    });
    document.querySelectorAll('.tab-panel').forEach((panel) => {
      panel.classList.toggle('active', panel.id === `tab-${name}`);
    });
    if (name === 'connection') {
      refreshSettings().catch((err) => showGlobal('error', err.message));
      loadWg().catch((err) => showGlobal('error', err.message));
    }
    if (name === 'open') {
      refreshExposures().catch((err) => showGlobal('error', err.message));
    }
    if (name === 'advanced') {
      refreshSettings().catch((err) => showGlobal('error', err.message));
      refreshManualServices().catch((err) => showGlobal('error', err.message));
    }
  }

  function bind() {
    $('manual-service-slot').append($('manual-services-card'));
    $('diagnostics-slot').append($('run-diagnostics').closest('section'));
    $('settings-slot').append($('api-settings-card'));
    $('settings-slot').append(document.querySelector('#tab-advanced > section:last-child'));
    $('settings-slot').append($('sync-detail').closest('section'));
    $('settings-slot').append($('sync-now'));
    $('settings-navigation').addEventListener('click', () => switchTab('connection'));
    $('back-services').addEventListener('click', () => switchTab('services'));
    $('add-service').addEventListener('click', () => {
      $('manual-services-card').hidden = false;
      $('manual-service-name').focus();
    });
    $('cancel-add-service').addEventListener('click', () => { $('manual-services-card').hidden = true; });
    document.querySelectorAll('[data-filter]').forEach((button) => {
      button.addEventListener('click', () => {
        state.filter = button.dataset.filter;
        document.querySelectorAll('[data-filter]').forEach((node) => node.setAttribute('aria-pressed', String(node === button)));
        renderServices();
      });
    });
    const help = {
      'manual-service-name': 'name', 'bootstrap-vps-ip': 'vps',
      'bootstrap-code': 'pair', 'pair-code': 'pair',
      'manual-endpoint': 'endpoint', 'manual-server-pub': 'key',
      'manual-client-ip': 'ip', 'manual-subnet': 'subnet',
      'manual-service-host': 'host', 'manual-service-port': 'port',
      'manual-service-public-port': 'public', 'manual-service-protocol': 'protocol',
      'settings-api': 'api', 'settings-token': 'token', 'settings-interval': 'interval', 'manual-mtu': 'mtu',
    };
    Object.entries(help).forEach(([id, key]) => {
      const input = $(id);
      const details = el('details', 'field-help');
      const summary = el('summary', '', `ⓘ ${t('ui.help')}`);
      const text = el('span', 'sub', t(`ui.help.${key}`));
      text.id = `${id}-help`;
      input.setAttribute('aria-describedby', text.id);
      details.append(summary, text);
      input.parentElement.append(details);
    });
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
        showGlobal('ok', t('services.refreshed'));
      } catch (err) {
        showGlobal('error', err.message);
      }
    });

    $('sync-now').addEventListener('click', async () => {
      try {
        const result = await api('/api/sync', { method: 'POST' });
        syncFeedback(result, t('open.synced'));
        await refreshAll();
      } catch (err) {
        showGlobal('error', err.message);
      }
    });

    $('bootstrap-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const vpsIp = $('bootstrap-vps-ip').value.trim();
      if (!vpsIp) return;
      try {
        state.bootstrap = await api('/api/bootstrap', {
          method: 'POST',
          body: JSON.stringify({ vps_ip: vpsIp }),
        });
        renderBootstrap();
        showMsg('onboarding-msg', t('onboarding.generated'), true);
      } catch (err) {
        showMsg('onboarding-msg', err.detail ? `${err.message} (${err.detail})` : err.message, false);
      }
    });

    $('bootstrap-link-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const code = $('bootstrap-code').value.trim();
      if (!code) return;
      try {
        const result = await api('/api/pair', { method: 'POST', body: JSON.stringify({ code }) });
        showMsg('onboarding-msg', result.wg || t('onboarding.linked'), Boolean(result.ok));
        $('bootstrap-code').value = '';
        await refreshAll();
        await loadWg();
        if (result.ok && state.status && state.status.paired) switchTab('services');
      } catch (err) {
        showMsg('onboarding-msg', err.detail ? `${err.message} (${err.detail})` : err.message, false);
      }
    });

    $('copy-bootstrap-command').addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText($('bootstrap-command').textContent);
        showGlobal('ok', t('onboarding.copied'));
      } catch (_) {
        showGlobal('error', t('onboarding.copy_failed'));
      }
    });

    $('reset-bootstrap').addEventListener('click', async () => {
      if (!window.confirm(t('onboarding.reset_confirm'))) return;
      try {
        await api('/api/bootstrap', { method: 'DELETE' });
        state.bootstrap = { active: false };
        renderBootstrap();
        showMsg('onboarding-msg', t('onboarding.reset_done'), true);
      } catch (err) {
        showMsg('onboarding-msg', err.message, false);
      }
    });

    $('pair-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const code = $('pair-code').value.trim();
      if (!code) return;
      try {
        const result = await api('/api/pair', { method: 'POST', body: JSON.stringify({ code }) });
        showMsg('pair-msg', result.wg || t('connection.pair_ok'), Boolean(result.ok));
        $('pair-code').value = '';
        await refreshAll();
        await loadWg();
      } catch (err) {
        showMsg('pair-msg', err.detail ? `${err.message} (${err.detail})` : err.message, false);
      }
    });

    $('unpair').addEventListener('click', async () => {
      if (!window.confirm(t('connection.unpair_confirm'))) return;
      try {
        await api('/api/unpair', { method: 'POST' });
        showGlobal('ok', t('connection.unpaired'));
        await refreshAll();
        await loadWg();
        switchTab('connection');
      } catch (err) {
        showGlobal('error', err.message);
      }
    });

    $('toggle-wg').addEventListener('click', () => {
      const pre = $('wg-config');
      pre.classList.toggle('hidden');
      $('toggle-wg').textContent = pre.classList.contains('hidden')
        ? t('connection.show')
        : t('connection.hide');
    });

    $('copy-wg').addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText($('wg-config').textContent);
        showGlobal('ok', t('connection.copied'));
      } catch (_) {
        showGlobal('error', t('connection.copy_failed'));
      }
    });

    $('rotate-wg').addEventListener('click', async () => {
      if (!window.confirm(t('connection.rotate_confirm'))) return;
      try {
        const result = await api('/api/wireguard/rotate', { method: 'POST' });
        showMsg('wg-msg', result.message || t('connection.rotated'), true);
        await refreshAll();
        await loadWg();
      } catch (err) {
        showMsg('wg-msg', err.message, false);
      }
    });

    $('retry-register').addEventListener('click', async () => {
      try {
        await api('/api/register', { method: 'POST' });
        showMsg('wg-msg', t('connection.registered'), true);
        await refreshAll();
      } catch (err) {
        showMsg('wg-msg', err.message, false);
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
            subnet: $('manual-subnet').value.trim(),
            mtu: Number($('manual-mtu').value),
          }),
        });
        $('manual-output').textContent = result.instructions || '';
        $('manual-output').classList.remove('hidden');
        showMsg('manual-msg', result.message || t('connection.manual_generated'), Boolean(result.applied));
        await refreshAll();
        await loadWg();
      } catch (err) {
        showMsg('manual-msg', err.detail ? `${err.message} (${err.detail})` : err.message, false);
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
        showMsg('settings-msg', t('advanced.saved'), true);
        await refreshAll();
      } catch (err) {
        showMsg('settings-msg', err.message, false);
      }
    });

    const manualPort = $('manual-service-port');
    const manualPublicPort = $('manual-service-public-port');
    let publicPortEdited = false;
    manualPublicPort.addEventListener('input', () => {
      publicPortEdited = manualPublicPort.value !== '';
      if (!publicPortEdited) manualPublicPort.value = manualPort.value;
    });
    manualPort.addEventListener('input', () => {
      if (!publicPortEdited) manualPublicPort.value = manualPort.value;
    });
    $('manual-service-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const mode = event.submitter && event.submitter.dataset.mode === 'add' ? 'add' : 'open';
      const protocol = $('manual-service-protocol').value;
      const publicPortValue = $('manual-service-public-port').value;
      if (mode === 'open' && !['tcp', 'udp', 'both'].includes(protocol)) {
        showMsg('manual-service-msg', t('advanced.manual_udp_open'), false);
        return;
      }
      const buttons = Array.from(event.target.querySelectorAll('button[type="submit"]'));
      buttons.forEach((button) => { button.disabled = true; });
      const pendingLabel = mode === 'open'
        ? t('advanced.manual_open_pending')
        : t('advanced.manual_add_pending');
      const submitter = event.submitter;
      if (submitter) submitter.textContent = pendingLabel;
      try {
        const requested = publicPortValue ? Number(publicPortValue) : null;
        const create = async (selected) => api('/api/manual-services', {
          method: 'POST',
          body: JSON.stringify({
            name: $('manual-service-name').value.trim(),
            host: $('manual-service-host').value.trim(),
            port: Number($('manual-service-port').value),
            protocol: selected,
            public_port: requested,
            open: mode === 'open',
          }),
        });
        let result;
        if (protocol === 'both') {
          const results = await Promise.allSettled(['tcp', 'udp'].map(create));
          results.forEach((item, index) => {
            if (item.status === 'fulfilled') syncFeedback(item.value, `${index ? 'UDP' : 'TCP'}: ${item.value.exposure ? item.value.exposure.public_port : t('advanced.manual_added')}`);
          });
          const failed = results.filter((item) => item.status === 'rejected');
          if (failed.length) throw new Error(failed.map((item) => item.reason.message).join(' · '));
          result = results[0].value;
        } else {
          result = await create(protocol);
        }
        $('manual-service-name').value = '';
        $('manual-service-host').value = '';
        $('manual-service-port').value = '';
        $('manual-service-public-port').value = '';
        publicPortEdited = false;
        if (mode === 'open') {
          result.requested_public_port = requested;
          const port = result.exposure ? result.exposure.public_port : '';
          const openedMessage = result.created === false
            ? t('advanced.manual_port_opened', { port })
            : t('advanced.manual_opened', { port });
          const ok = syncFeedback(
            result,
            openedMessage,
            t('advanced.manual_public_changed', { requested, port }),
          );
          if (!ok) showGlobal('error', t('advanced.manual_open_hint'));
          showMsg('manual-service-msg', ok ? openedMessage : t('advanced.manual_open_hint'), ok);
        } else {
          showMsg('manual-service-msg', t('advanced.manual_added'), true);
        }
        await refreshAll();
        await refreshServices(true);
      } catch (err) {
        let message = err.message;
        if (err.code === 'invalid_manual_service') message = t('advanced.manual_invalid');
        if (err.code === 'no_public_port') message = t('error.no_public_port');
        if (err.code === 'unsupported_protocol') message = t('advanced.manual_udp_open');
        showMsg('manual-service-msg', message, false);
        showGlobal('error', message);
        await refreshManualServices().catch(() => {});
      } finally {
        buttons.forEach((button) => { button.disabled = false; });
        if (submitter) {
          submitter.textContent = submitter.dataset.mode === 'add'
            ? t('advanced.manual_add_only')
            : t('advanced.manual_add_open');
        }
      }
    });

    $('run-diagnostics').addEventListener('click', () => runDiagnostics($('run-diagnostics')));

    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') refreshAll().catch(() => {});
    });
  }

  async function init() {
    bind();
    try {
      await refreshAll();
      await refreshSettings();
      if (state.status && state.status.paired) {
        await loadWg();
      } else {
        // First run: send the user straight to the VPS onboarding wizard.
        switchTab('connection');
      }
    } catch (err) {
      showGlobal('error', err.message);
    }
    pollTimer = window.setInterval(() => {
      if (document.visibilityState === 'visible') refreshAll().catch(() => {});
    }, 10000);
  }

  init();
})();
