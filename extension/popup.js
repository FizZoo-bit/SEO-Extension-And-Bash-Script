// popup.js
const input  = document.getElementById('token');
const status = document.getElementById('status');
const set = (msg, ok) => { status.textContent = msg; status.className = ok ? 'ok' : 'err'; };

chrome.storage.sync.get('dfs_token', r => {
  if (r.dfs_token) { input.value = r.dfs_token; set('✓ Token saved', true); }
  else set('No token saved', false);
});

document.getElementById('save').addEventListener('click', () => {
  const t = input.value.trim();
  if (t.length < 20) { set('Token too short — check it', false); return; }
  chrome.storage.sync.set({ dfs_token: t }, () => set('✓ Saved', true));
});

document.getElementById('clear').addEventListener('click', () => {
  chrome.storage.sync.remove('dfs_token', () => { input.value = ''; set('Cleared', false); });
});
