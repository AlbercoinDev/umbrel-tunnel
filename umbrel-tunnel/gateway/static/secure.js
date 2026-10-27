(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const cfg = JSON.parse($('ut-config').textContent);
  const es = cfg.lang === 'es';
  const text = (a, b) => es ? a : b;
  async function api(path, method = 'GET', body) {
    const response = await fetch(path, {method, headers: {'Content-Type': 'application/json', 'X-CSRF-Token': cfg.csrf}, body: body === undefined ? undefined : JSON.stringify(body)});
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || response.statusText);
    return result;
  }
  async function refresh() {
    try {
      const services = await api('/api/services');
      const selected = $('secure-service').value;
      $('secure-service').replaceChildren();
      for (const s of services.filter(s => (s.protocol || 'tcp') === 'tcp')) {
        const o = document.createElement('option'); o.value = s.id;
        o.textContent = `${s.app} · ${s.name} → ${s.target_ip}:${s.target_port}`;
        $('secure-service').append(o);
      }
      if ([...$('secure-service').options].some(o => o.value === selected)) $('secure-service').value = selected;
      const [certs, exposures] = await Promise.all([api('/api/certificates'), api('/api/exposures')]);
      $('secure-status').replaceChildren();
      for (const e of exposures.filter(e => ['https', 'tls'].includes(e.access_mode))) {
        const domain = (e.domains || [])[0];
        const c = certs.find(c => c.domain === domain) || {};
        const p = document.createElement('p');
        p.textContent = `${domain}:${e.public_port} → ${e.target_ip}:${e.target_port} · ${e.enabled ? (c.state || 'pending') : text('pausado', 'paused')}${c.not_after ? ' · ' + new Date(c.not_after).toLocaleString() : ''}${e.sync_error_detail ? ' · ' + e.sync_error_detail : ''}${c.error ? ' · ' + c.error : ''}`;
        const edit = document.createElement('button'); edit.type = 'button'; edit.className = 'ghost small'; edit.textContent = text('Editar', 'Edit');
        edit.onclick = () => { $('secure-service').value = e.service_id; $('secure-mode').value = e.access_mode; $('secure-mode').dispatchEvent(new Event('change')); $('secure-port').value = e.public_port; $('secure-domain').value = domain; $('secure-domain').focus(); };
        p.append(' ', edit); $('secure-status').append(p);
      }
    } catch (err) { $('secure-message').textContent = err.message; }
  }
  $('secure-mode').onchange = () => { const https = $('secure-mode').value === 'https'; $('secure-port').disabled = https; $('secure-port').value = https ? 443 : 50002; };
  $('secure-refresh').onclick = refresh;
  $('secure-retry').onclick = async () => {
    try {
      await api('/api/certificates/retry', 'POST', {});
      $('secure-message').textContent = text('Reintento programado (máximo uno por minuto por dominio). No se eliminan certificados válidos.', 'Retry scheduled (at most once per minute per domain). Valid certificates are not deleted.');
      await refresh();
    } catch (err) { $('secure-message').textContent = err.message; }
  };
  $('secure-form').onsubmit = async (event) => {
    event.preventDefault();
    const button = event.submitter; button.disabled = true;
    try {
      const result = await api('/api/exposures', 'POST', {service_id: $('secure-service').value, access_mode: $('secure-mode').value, domain: $('secure-domain').value, public_port: Number($('secure-port').value), accept_acme_terms: $('secure-terms').checked});
      if (!result.ok) throw new Error(result.exposure.sync_error_detail || JSON.stringify(result.sync));
      $('secure-message').textContent = text('Publicación configurada. El certificado puede tardar unos minutos; comprueba el estado. Se renovará automáticamente mientras DNS y puerto 80 sigan accesibles.', 'Publication configured. Certificate issuance may take a few minutes; check status. Renewal is automatic while DNS and port 80 remain reachable.');
      await refresh();
    } catch (err) { $('secure-message').textContent = err.message; }
    finally { button.disabled = false; }
  };
  refresh();
})();
