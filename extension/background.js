// background.js — API engine for ExpiredDomains Pro Helper

const MAX_RETRIES = 3;
const RETRY_MS = 2000;
const SPAM = /casino|poker|viagra|pharmacy|porn|gambling|slots|crypto|hack|torrent/i;

const getToken = () =>
  chrome.storage.sync.get('dfs_token').then(r => r.dfs_token || null);

const sleep = ms => new Promise(r => setTimeout(r, ms));

const quality = (dr, bl, spam) => {
  if (spam > 30)              return 'spam';
  if (dr >= 60 && bl >= 10000) return 'premium';
  if (dr >= 31 && bl >= 1000)  return 'good';
  if (dr >= 11 && bl >= 100)   return 'medium';
  return 'low';
};

async function fetchBacklinks(domain, token, attempt = 1) {
  try {
    const res = await fetch('https://api.dataforseo.com/v3/backlinks/summary/live', {
      method: 'POST',
      headers: { 'Authorization': `Basic ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify([{ target: domain, include_subdomains: true }])
    });
    const data = await res.json();
    if (data?.status_code !== 20000) throw new Error(data?.status_message || 'API error');
    const r = data.tasks[0].result[0];
    const dr = r.rank || 0, bl = r.backlinks || 0;
    return {
      domain, dr, bl,
      rd: r.referring_domains || 0,
      dofollow: r.backlinks_dofollow || 0,
      spam: r.backlinks_spam_score || 0,
      quality: quality(dr, bl, r.backlinks_spam_score || 0),
      error: null
    };
  } catch (e) {
    if (attempt < MAX_RETRIES) {
      await sleep(RETRY_MS);
      return fetchBacklinks(domain, token, attempt + 1);
    }
    return { domain, error: e.message, quality: 'unknown' };
  }
}

chrome.runtime.onMessage.addListener((msg, sender, respond) => {
  if (msg.type !== 'CHECK_DOMAIN') return;
  getToken().then(token => {
    if (!token) { respond({ error: 'No token. Click the extension icon to configure.' }); return; }
    fetchBacklinks(msg.domain, token).then(respond);
  });
  return true;
});
