const { createApp, ref, onMounted } = Vue;

createApp({
  setup() {
    const peers = ref([]);
    const forwards = ref([]);
    const status = ref({});
    const showAddPeer = ref(false);
    const showAddForward = ref(false);
    const configPeer = ref(null);
    const peerConfigText = ref('');
    const newPeer = ref({ name: '', public_key: '', allowed_ip: '10.0.0.2' });
    const newFwd = ref({ name: '', dport: 3006, target_ip: '10.0.0.2', target_port: 3006, auth_mode: 'none' });

    async function api(path, opts = {}) {
      const res = await fetch(path, {
        headers: { 'Content-Type': 'application/json' },
        ...opts,
      });
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    }

    async function loadData() {
      peers.value = await api('/api/peers');
      forwards.value = await api('/api/forwards');
      status.value = await api('/api/status');
    }

    async function addPeer() {
      await api('/api/peers', {
        method: 'POST',
        body: JSON.stringify(newPeer.value),
      });
      newPeer.value = { name: '', public_key: '', allowed_ip: '10.0.0.2' };
      showAddPeer.value = false;
      await loadData();
    }

    async function deletePeer(id) {
      if (!confirm('Delete this peer?')) return;
      await api(`/api/peers/${id}`, { method: 'DELETE' });
      await loadData();
    }

    async function showPeerConfig(peer) {
      const res = await api(`/api/peers/${peer.id}/config`);
      peerConfigText.value = res.config;
      configPeer.value = peer;
    }

    async function copyConfig() {
      await navigator.clipboard.writeText(peerConfigText.value);
    }

    async function addForward() {
      await api('/api/forwards', {
        method: 'POST',
        body: JSON.stringify(newFwd.value),
      });
      newFwd.value = { name: '', dport: 3006, target_ip: '10.0.0.2', target_port: 3006, auth_mode: 'none' };
      showAddForward.value = false;
      await loadData();
    }

    async function deleteForward(id) {
      if (!confirm('Delete this forward?')) return;
      await api(`/api/forwards/${id}`, { method: 'DELETE' });
      await loadData();
    }

    async function toggleForward(fwd) {
      await api(`/api/forwards/${fwd.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ enabled: !fwd.enabled }),
      });
      await loadData();
    }

    onMounted(loadData);

    return {
      peers, forwards, status,
      showAddPeer, showAddForward, configPeer, peerConfigText,
      newPeer, newFwd,
      addPeer, deletePeer, showPeerConfig, copyConfig,
      addForward, deleteForward, toggleForward,
    };
  }
}).mount('#app');
