'use strict';
const statusLabel = document.querySelector('#status');
const desktop = document.querySelector('#desktop');
const closeButton = document.querySelector('#close');
const metricsLabel = document.querySelector('#metrics');
const tools = document.querySelector('#tools');
const keyboardButton = document.querySelector('#keyboard');
const panButton = document.querySelector('#pan');
const hint = document.querySelector('#hint');
let stopped = false, mounted = false, mode = null;
let phase = 'starting', remainingMinutes = 10;
let idleHint = 'Aucun envoi de campagne depuis cette fenêtre.';
let remoteObserver = null;
const errors = {
  REQUEST_FAILED: 'La connexion n’a pas pu être confirmée. Reviens dans l’administration pour réessayer.',
  SESSION_EXPIRED: 'Ce lien a expiré. Ouvre une nouvelle connexion depuis l’administration.',
  SESSION_CANCELED: 'La connexion a été annulée.',
  SESSION_BUSY: 'Une connexion est déjà en cours. Reviens dans l’administration pour la suivre.',
  CAPTCHA_REQUIRED: 'Le service demande une vérification supplémentaire. La connexion n’est pas confirmée.',
  SANDBOX_UNAVAILABLE: 'Le navigateur sécurisé n’est pas disponible pour le moment.',
  MEMORY_LIMIT_REACHED: 'Le navigateur a atteint sa capacité. Reviens dans l’administration pour réessayer.',
  BROWSER_UNAVAILABLE: 'Le navigateur n’a pas démarré. Reviens dans l’administration pour réessayer.',
  ACCESS_REFUSED: 'Ce lien privé n’est plus utilisable. Ouvre la connexion depuis l’administration.',
  CONFIGURATION_REQUIRED: 'La connexion au robot n’est pas encore disponible.',
};
const touchDevice = 'ontouchstart' in window || navigator.maxTouchPoints > 0;
keyboardButton.hidden = !touchDevice;
function fitViewport() {
  document.documentElement.style.setProperty('--screen-height', `${Math.round(window.visualViewport?.height || innerHeight)}px`);
}
fitViewport();
window.addEventListener('resize', fitViewport);
window.visualViewport?.addEventListener('resize', fitViewport);
function remoteControl(id) {
  try { return desktop.contentDocument?.getElementById(id); } catch { return null; }
}
function syncControls() {
  if (stopped) return;
  const connected = desktop.contentDocument?.documentElement.classList.contains('noVNC_connected');
  tools.hidden = !connected;
  if (phase === 'ready') statusLabel.textContent = connected
    ? `${mode === 'fixture' ? 'Démo ouverte' : 'Connecte-toi ici'} · ${remainingMinutes} min restantes`
    : `Ouverture de l’écran distant… · ${remainingMinutes} min restantes`;
  const panning = remoteControl('noVNC_view_drag_button')?.classList.contains('noVNC_selected') === true;
  keyboardButton.setAttribute('aria-pressed', String(remoteControl('noVNC_keyboard_button')?.classList.contains('noVNC_selected') === true));
  panButton.setAttribute('aria-pressed', String(panning));
  panButton.textContent = panning ? 'Interagir' : 'Déplacer';
  hint.textContent = panning ? 'Glisse pour déplacer l’écran, puis touche Interagir.' : idleHint;
}
desktop.addEventListener('load', () => {
  remoteObserver?.disconnect();
  if (stopped || !mounted || !desktop.contentDocument) return;
  remoteObserver = new MutationObserver(syncControls);
  remoteObserver.observe(desktop.contentDocument.documentElement, { subtree: true, attributes: true, attributeFilter: ['class'] });
  syncControls();
});
for (const [button, id] of [[keyboardButton, 'noVNC_keyboard_button'], [panButton, 'noVNC_view_drag_button']]) {
  // Keep the real noVNC keyboard focused while a toolbar control is touched.
  button.addEventListener('pointerdown', event => event.preventDefault());
  button.addEventListener('click', () => {
    if (stopped) return;
    remoteControl(id)?.click();
    syncControls();
  });
}
async function request(path, options = {}) {
  const response = await fetch(path, { credentials: 'same-origin', cache: 'no-store', ...options });
  const result = await response.json();
  if (!response.ok) throw new Error(Object.hasOwn(errors, result?.error_code || result?.code) ? result.error_code || result.code : response.status === 401 ? 'ACCESS_REFUSED' : 'REQUEST_FAILED');
  return result;
}
function setMode(value) {
  if (!['fixture', 'provider'].includes(value)) throw new Error('REQUEST_FAILED');
  if (mode === value) return;
  mode = value;
  const fixture = mode === 'fixture';
  metricsLabel.hidden = !fixture;
  document.title = fixture ? 'Console de démonstration' : 'Connexion du robot';
  document.querySelector('#heading').textContent = fixture ? 'Test mobile' : 'Connexion du robot';
  desktop.title = fixture ? 'Navigateur de démonstration, page fictive' : 'Navigateur de connexion sécurisée';
  idleHint = fixture ? 'Page fictive · aucun envoi ni paiement.' : 'Connecte-toi dans le navigateur. Aucun envoi.';
  hint.textContent = idleHint;
}
function hideDesktop() {
  remoteObserver?.disconnect(); tools.hidden = true;
  desktop.removeAttribute('src'); desktop.hidden = true;
}
function finish(message) {
  stopped = true;
  hideDesktop(); closeButton.hidden = true;
  statusLabel.textContent = message;
}
async function poll() {
  if (stopped) return;
  try {
    const state = await request('/metrics');
    if (stopped) return;
    setMode(state.mode);
    closeButton.hidden = false;
    if (state.status === 'error') { finish(errors[state.error_code] || errors.REQUEST_FAILED); await request('/close', { method: 'POST' }).catch(() => {}); return; }
    if (state.status === 'connected') { finish('Connexion confirmée. Reviens dans l’administration : la session est synchronisée avec le serveur.'); return; }
    if (!['starting', 'ready', 'verifying'].includes(state.status)) throw new Error('REQUEST_FAILED');
    phase = state.status; remainingMinutes = Math.ceil(state.remaining_seconds / 60);
    statusLabel.textContent = state.status === 'ready'
      ? `Ouverture de l’écran distant… · ${remainingMinutes} min restantes`
      : state.status === 'verifying' ? 'Vérification et synchronisation de la connexion…' : 'Démarrage… Jusqu’à une minute sur le serveur gratuit.';
    if (state.status === 'verifying') hideDesktop();
    if (state.status === 'ready' && !mounted) {
      mounted = true;
      desktop.src = '/novnc/vnc.html?autoconnect=1&resize=off&view_clip=true&reconnect=0&path=websockify';
      desktop.hidden = false;
    }
    if (state.status === 'ready') syncControls();
    const bytes = Number(state.memory?.cgroup_current_bytes);
    metricsLabel.textContent = bytes ? `Mémoire : ${(bytes / 1048576).toFixed(0)} / 512 Mio` : 'Mesure mémoire disponible sur le serveur.';
    setTimeout(poll, 2000);
  } catch (error) { finish(errors[error.message] || 'Session fermée ou expirée. Reviens dans l’administration pour recommencer.'); }
}
closeButton.addEventListener('click', async () => {
  closeButton.disabled = true; stopped = true;
  try { await request('/close', { method: 'POST' }); finish(mode === 'fixture' ? 'Test terminé. Le navigateur distant est fermé.' : 'Connexion fermée. Tu peux revenir dans l’administration.'); }
  catch { finish('Connexion interrompue. La session se ferme automatiquement au plus tard après 10 minutes.'); }
});
(async () => {
  // Fragments never reach HTTP logs. Remove before loading any remote desktop.
  const fragment = new URLSearchParams(location.hash.slice(1));
  let token = fragment.get('token'), ticket = fragment.get('ticket');
  history.replaceState(null, '', location.pathname);
  try {
    if (ticket !== null) {
      if (token !== null || !/^[A-Za-z0-9_-]{43}$/.test(ticket)) throw new Error('INVALID');
      await request('/session', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ticket }) });
      ticket = null;
    } else if (token) {
      if (!/^[a-fA-F0-9]{64}$/.test(token) || token.length !== 64) throw new Error('INVALID');
      await request('/session', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
      token = null;
    } else { await request('/status'); }
    await poll();
  } catch (error) { token = null; ticket = null; finish(errors[error.message] || 'Accès privé. Ouvre la connexion depuis ton administration.'); }
})();
