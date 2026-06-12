// content_script.js — ExpiredDomains Pro Helper

const COLORS = {
  g:  '#6a1b9a', gl: '#f3e5f5', gb: '#ce93d8',  // google
  au: '#e65100', al: '#fff3e0', ab: '#ffcc80',  // authority
  bl: '#1b5e20', ll: '#e8f5e9', lb: '#a5d6a7',  // backlink
  w:  '#37474f', wl: '#eceff1', wb: '#cfd8dc',  // wayback
  tm: '#004d40', tl: '#e0f2f1', tb: '#80cbc4',  // trademark
  dr: '#1a237e', dl: '#e8eaf6', db: '#9fa8da',  // dataforseo
};

const QUALITY = {
  premium: { bg: '#e8f5e9', br: '#2e7d32' },
  good:    { bg: '#e3f2fd', br: '#1565c0' },
  medium:  { bg: '#fff8e1', br: '#f57f17' },
  low:     { bg: '#ffebee', br: '#b71c1c' },
  spam:    { bg: '#212121', br: '#000' },
  unknown: { bg: '#fafafa', br: '#9e9e9e' },
};

const TM = {
  de: 'https://register.dpma.de/DPMAregister/marke/einsteiger',
  uk: 'https://www.gov.uk/search-for-trademark',
  us: 'https://www.uspto.gov/trademarks/search',
  fr: 'https://data.inpi.fr/marques',
  eu: 'https://euipo.europa.eu/eSearch/',
};

const selected = new Map();

// ── Helpers ───────────────────────────────────────────────────────
const fmt = n => n >= 1e6 ? (n/1e6).toFixed(1)+'M' : n >= 1e3 ? (n/1e3).toFixed(1)+'K' : String(n||0);

const btn = (text, url, tc, bg, bc) => {
  const a = Object.assign(document.createElement('a'), { href: url, textContent: text, target: '_blank' });
  a.style.cssText = `margin-left:4px;padding:1px 5px;font-size:.78em;font-family:monospace;
    text-decoration:none;border-radius:3px;border:1px solid ${bc};display:inline-block;
    vertical-align:middle;line-height:1.5;color:${tc};background:${bg};cursor:pointer;white-space:nowrap`;
  a.addEventListener('click', e => e.stopPropagation());
  return a;
};

const badge = (label, val, tc, bg, bc) => {
  const s = document.createElement('span');
  s.style.cssText = `margin-left:4px;padding:1px 6px;font-size:.78em;font-family:monospace;
    border-radius:3px;border:1px solid ${bc};display:inline-block;vertical-align:middle;
    line-height:1.5;color:${tc};background:${bg};white-space:nowrap`;
  s.innerHTML = `<b>${label}</b>:${val}`;
  return s;
};

const spinner = () => {
  const s = document.createElement('span');
  s.className = 'edh-spin'; s.textContent = ' ⟳';
  s.style.cssText = 'font-size:.8em;color:#999;margin-left:4px;display:inline-block';
  return s;
};

const getDomain = link => {
  const c = link.cloneNode(true);
  c.querySelectorAll('*').forEach(e => e.remove());
  return c.textContent.trim().replace(/[^a-zA-Z0-9.\-]/g, '');
};

// ── Process cell ─────────────────────────────────────────────────
function processCell(cell) {
  if (cell.classList.contains('edh-done')) return;
  cell.classList.add('edh-done');

  const link = cell.querySelector('a.namelinks');
  if (!link) return;
  const domain = getDomain(link);
  if (!domain) return;

  const row = cell.closest('tr');
  const tld = domain.split('.').pop().toLowerCase();

  // Tool buttons
  const buttons = [
    btn('G',    `https://www.google.com/search?q=site:${domain}`,                           COLORS.g, COLORS.gl, COLORS.gb),
    btn('Au',   `https://ahrefs.com/website-authority-checker/?input=${domain}`,             COLORS.au,COLORS.al, COLORS.ab),
    btn('BL',   `https://ahrefs.com/backlink-checker/?input=${domain}&mode=subdomains`,      COLORS.bl,COLORS.ll, COLORS.lb),
    btn('G BL', `https://www.google.com/search?q="${domain}" -site:${domain}`,              COLORS.bl,COLORS.ll, COLORS.lb),
    btn('W',    `https://web.archive.org/web/*/${domain}`,                                   COLORS.w, COLORS.wl, COLORS.wb),
  ];
  if (TM[tld]) buttons.push(btn('TM', TM[tld], COLORS.tm, COLORS.tl, COLORS.tb));

  // Checkbox
  const cb = document.createElement('input');
  cb.type = 'checkbox';
  cb.style.cssText = 'margin-right:6px;cursor:pointer;width:13px;height:13px';
  cb.addEventListener('change', () => {
    selected[cb.checked ? 'set' : 'delete'](domain, cb.checked ? {} : undefined);
    updateCount();
  });

  const spin = spinner();
  const wrap = document.createElement('span');
  wrap.appendChild(spin);

  link.after(cb, ...buttons);
  cell.appendChild(wrap);

  // Fetch data
  chrome.runtime.sendMessage({ type: 'CHECK_DOMAIN', domain }, result => {
    spin.remove();
    if (!result || result.error) {
      wrap.appendChild(badge('ERR', result?.error || 'failed', '#495057', '#e9ecef', '#ced4da'));
      return;
    }

    wrap.appendChild(badge('DR', result.dr,          COLORS.dr, COLORS.dl, COLORS.db));
    wrap.appendChild(badge('BL', fmt(result.bl),     COLORS.bl, COLORS.ll, COLORS.lb));
    wrap.appendChild(badge('RD', fmt(result.rd),     COLORS.bl, COLORS.ll, COLORS.lb));
    if (result.spam > 10)
      wrap.appendChild(badge('SPAM', result.spam+'%', '#721c24', '#f8d7da', '#f5c6cb'));

    const q = QUALITY[result.quality] || QUALITY.unknown;
    if (row) { row.style.backgroundColor = q.bg; row.style.borderLeft = `4px solid ${q.br}`; }

    // Update checkbox with real data
    cb.addEventListener('change', () => {
      selected[cb.checked ? 'set' : 'delete'](domain, result);
      updateCount();
    });
  });
}

// ── Toolbar ───────────────────────────────────────────────────────
function buildToolbar() {
  const bar = document.createElement('div');
  bar.id = 'edh-bar';
  bar.style.cssText = 'position:fixed;bottom:20px;right:20px;background:#1a1a2e;color:#fff;' +
    'padding:10px 16px;border-radius:8px;z-index:99999;font-family:monospace;font-size:13px;' +
    'display:flex;align-items:center;gap:10px;border:1px solid #444';

  const count = Object.assign(document.createElement('span'), { id: 'edh-count', textContent: '0 selected' });

  const mkBtn = (label, color, fn) => {
    const b = document.createElement('button');
    b.textContent = label;
    b.style.cssText = `padding:5px 12px;background:${color};color:#fff;border:none;border-radius:4px;cursor:pointer;font-family:monospace;font-size:12px`;
    b.addEventListener('click', fn);
    return b;
  };

  bar.append(count,
    mkBtn('☑ Select Good+', '#1565c0', selectGood),
    mkBtn('⬇ Export CSV',   '#2e7d32', exportCSV),
    mkBtn('✕ Clear',        '#c62828', clearAll)
  );
  document.body.appendChild(bar);
}

const updateCount = () => {
  const el = document.getElementById('edh-count');
  if (el) el.textContent = `${selected.size} selected`;
};

function selectGood() {
  document.querySelectorAll('td.field_domain.edh-done').forEach(cell => {
    const row = cell.closest('tr');
    const q = row?.style.backgroundColor;
    const isGood = q === QUALITY.good.bg || q === QUALITY.premium.bg;
    const cb = cell.querySelector('input[type=checkbox]');
    const domain = getDomain(cell.querySelector('a.namelinks'));
    if (isGood && cb && domain) { cb.checked = true; selected.set(domain, {}); }
  });
  updateCount();
}

function clearAll() {
  selected.clear();
  document.querySelectorAll('td.field_domain input[type=checkbox]').forEach(cb => cb.checked = false);
  updateCount();
}

function exportCSV() {
  if (!selected.size) { alert('Select some domains first.'); return; }
  const rows = ['domain,rank,backlinks,ref_domains,spam,quality'];
  selected.forEach((d, domain) => {
    const clean = domain.replace(/[^a-zA-Z0-9.\-]/g, '').toLowerCase();
    rows.push([clean, d.dr||0, d.bl||0, d.rd||0, d.spam||0, d.quality||'unknown'].join(','));
  });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([rows.join('\n')], { type: 'text/csv' }));
  a.download = `domains_${new Date().toISOString().slice(0,10)}.csv`;
  a.click();
}

// ── Init & Observer ───────────────────────────────────────────────
const processPage = () => document.querySelectorAll('td.field_domain').forEach(processCell);

new MutationObserver(muts => {
  if (muts.some(m => [...m.addedNodes].some(n =>
    n.nodeName === 'TR' || n.nodeName === 'TABLE' || n.nodeName === 'TBODY' ||
    (n.nodeType === 1 && n.querySelector('tr,table,tbody'))
  ))) processPage();
}).observe(document.body, { childList: true, subtree: true });

buildToolbar();
processPage();
