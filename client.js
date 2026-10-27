'use strict';
const statusLabel = document.querySelector('#status');
const desktop = document.querySelector('#desktop');
const closeButton = document.querySelector('#close');
const metricsLabel = document.querySelector('#metrics');
let stopped = false, mounted = false;
async function request(path, options = {}) {
  const response = await fetch(path, { credentials: 'same-origin', cache: 'no-store', ...options });
  if (!response.ok) throw new Error(response.status === 401 ? 'SESSION_ENDED' : 'UNAVAILABLE');
  return response.json();
}
function finish(message) {
  stopped = true;
  desktop.removeAttribute('src'); desktop.hidden = true; closeButton.hidden = true;
  statusLabel.textContent = message;
}
async function poll() {
  if (stopped) return;
  try {
    const state = await request('/metrics');
    closeButton.hidden = false;
    if (state.status === 'error') { finish('Le navigateur n’a pas démarré. Relance le test depuis un nouveau lien autorisé.'); await request('/close', { method: 'POST' }); return; }
    statusLabel.textContent = state.status === 'ready'
      ? `Démonstration ouverte · fermeture dans ${Math.ceil(state.remaining_seconds / 60)} min`
      : 'Démarrage du navigateur… Cela peut prendre une minute sur le serveur gratuit.';
    if (state.status === 'ready' && !mounted) {
      mounted = true;
      desktop.src = '/novnc/vnc.html?autoconnect=1&resize=scale&reconnect=0&path=websockify';
      desktop.hidden = false;
    }
    const bytes = Number(state.memory.cgroup_current_bytes);
    metricsLabel.textContent = bytes ? `Mémoire du conteneur : ${(bytes / 1048576).toFixed(0)} Mio / 512 Mio` : 'Mesure mémoire disponible sur le serveur Linux.';
    setTimeout(poll, 2000);
  } catch { finish('Session fermée ou expirée. Ouvre un nouveau lien autorisé pour recommencer.'); }
}
closeButton.addEventListener('click', async () => {
  closeButton.disabled = true;
  try { await request('/close', { method: 'POST' }); finish('Test terminé. Le navigateur distant est fermé.'); }
  catch { finish('Connexion interrompue. La session se ferme automatiquement au plus tard après 10 minutes.'); }
});
(async () => {
  // Fragments never reach HTTP logs. Remove before loading any remote desktop.
  const fragment = new URLSearchParams(location.hash.slice(1));
  let token = fragment.get('token');
  history.replaceState(null, '', location.pathname);
  try {
    if (token) {
      if (!/^[a-fA-F0-9]{64}$/.test(token) || token.length !== 64) throw new Error('INVALID');
      await request('/session', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
      token = null;
    } else { await request('/status'); }
    await poll();
  } catch { token = null; finish('Accès privé. Ouvre le lien de démonstration fourni par ton administrateur.'); }
})();
