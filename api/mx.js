// POST /api/mx  { "domains": ["example.com", ...] }  (max 50 per request)
// The browser splits big lists (up to 1000) into batches and calls this repeatedly.
const dns = require('node:dns').promises;
const net = require('node:net');
const tls = require('node:tls');

const MAX_PER_REQUEST = 50;
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$/i;

const PROVIDERS = [
  [/(^|\.)google(mail)?\.com$|(^|\.)googlemail\.com$/, 'Google Workspace'],
  [/(^|\.)outlook\.com$|(^|\.)protection\.outlook\.com$/, 'Microsoft 365'],
  [/(^|\.)pphosted\.com$/, 'Proofpoint'],
  [/(^|\.)mimecast\.com$/, 'Mimecast'],
  [/(^|\.)zoho\.(com|eu|in|com\.au)$/, 'Zoho'],
  [/(^|\.)protonmail\.ch$/, 'Proton'],
  [/(^|\.)messagingengine\.com$/, 'Fastmail'],
  [/(^|\.)mailgun\.org$/, 'Mailgun'],
  [/(^|\.)secureserver\.net$/, 'GoDaddy'],
  [/(^|\.)registrar-servers\.com$|(^|\.)privateemail\.com$/, 'Namecheap'],
  [/(^|\.)yahoodns\.net$/, 'Yahoo'],
  [/(^|\.)icloud\.com$/, 'iCloud'],
  [/(^|\.)barracudanetworks\.com$/, 'Barracuda'],
  [/(^|\.)improvmx\.com$/, 'ImprovMX'],
  [/(^|\.)forwardemail\.net$/, 'Forward Email'],
];

function detectProvider(hosts) {
  for (const h of hosts) {
    for (const [re, name] of PROVIDERS) if (re.test(h)) return name;
  }
  return '';
}


// Connect to the MX host on port 25, issue EHLO, and see whether STARTTLS is offered and completes.
function probeStartTls(host, port = 25, timeoutMs = 8000) {
  return new Promise((resolve) => {
    let settled = false, buf = '', stage = 'banner';
    const sock = net.connect({ host, port });
    const timer = setTimeout(() => done({ state: 'unreachable', error: 'Timed out' }), timeoutMs);
    function done(r) {
      if (settled) return;
      settled = true; clearTimeout(timer);
      try { sock.destroy(); } catch {}
      resolve(r);
    }
    sock.setEncoding('utf8');
    sock.on('error', (e) => done({ state: 'unreachable', error: e.code || e.message }));
    sock.on('close', () => done({ state: 'unreachable', error: 'Connection closed' }));
    sock.on('data', (chunk) => {
      if (stage === 'tls') return;
      buf += chunk;
      const lines = buf.split(/\r?\n/);
      if (lines[lines.length - 1] !== '') return;                 // wait for a full line
      const last = lines[lines.length - 2] || '';
      if (!/^\d{3}( |$)/.test(last)) return;                      // multi-line reply not finished
      const code = parseInt(last.slice(0, 3), 10), reply = buf;
      buf = '';
      if (stage === 'banner') {
        if (code !== 220) return done({ state: 'unreachable', error: 'Bad banner ' + code });
        stage = 'ehlo'; sock.write('EHLO mx-checker.example\r\n');
      } else if (stage === 'ehlo') {
        if (code !== 250) return done({ state: 'unreachable', error: 'EHLO rejected ' + code });
        if (!/^250[ -]STARTTLS\s*$/im.test(reply)) return done({ state: 'no_starttls' });
        stage = 'starttls'; sock.write('STARTTLS\r\n');
      } else if (stage === 'starttls') {
        if (code !== 220) return done({ state: 'no_starttls', error: 'STARTTLS rejected ' + code });
        stage = 'tls';
        sock.removeAllListeners('data');
        const t = tls.connect({ socket: sock, servername: host, rejectUnauthorized: false });
        t.once('secureConnect', () => done({
          state: 'ok',
          version: t.getProtocol() || '',
          certValid: t.authorized,
          certError: t.authorized ? '' : String(t.authorizationError || ''),
        }));
        t.once('error', (e) => done({ state: 'tls_failed', error: e.code || e.message }));
      }
    });
  });
}

// MTA-STS: DNS TXT record plus policy file over HTTPS (port 443, so it works on Vercel).
async function checkMtaSts(domain, resolver) {
  try {
    const txt = await resolver.resolveTxt('_mta-sts.' + domain);
    if (!txt.some((r) => r.join('').toLowerCase().startsWith('v=stsv1'))) return 'missing';
  } catch { return 'missing'; }
  try {
    const res = await fetch(`https://mta-sts.${domain}/.well-known/mta-sts.txt`, { redirect: 'manual', signal: AbortSignal.timeout(4000) });
    if (!res.ok) return 'invalid';
    const m = /^mode:\s*(\w+)/im.exec(await res.text());
    return m ? m[1].toLowerCase() : 'invalid';
  } catch { return 'invalid'; }
}

async function checkTls(records, domain, resolver) {
  const host = records[0].exchange;   // primary (lowest priority) MX
  const [probe, mtaSts] = await Promise.all([probeStartTls(host), checkMtaSts(domain, resolver)]);
  return { host, ...probe, mtaSts };
}

async function check(domain, resolver, opts = {}) {
  if (!DOMAIN_RE.test(domain)) return { domain, status: 'invalid', records: [], provider: '', error: 'Not a valid domain' };
  try {
    const raw = await resolver.resolveMx(domain);
    const records = raw
      .map((r) => ({ priority: r.priority, exchange: (r.exchange || '').toLowerCase().replace(/\.$/, '') }))
      .sort((a, b) => a.priority - b.priority);
    if (!records.length || (records.length === 1 && records[0].exchange === '')) {
      return { domain, status: 'none', records: [], provider: '', error: 'Null MX (domain does not accept mail)' };
    }
    const out = { domain, status: 'ok', records, provider: detectProvider(records.map((r) => r.exchange)), error: '' };
    if (opts.tls) out.tls = await checkTls(records, domain, resolver);
    return out;
  } catch (e) {
    if (e.code === 'ENODATA') return { domain, status: 'none', records: [], provider: '', error: 'No MX records' };
    if (e.code === 'ENOTFOUND') return { domain, status: 'nxdomain', records: [], provider: '', error: 'Domain does not exist' };
    return { domain, status: 'error', records: [], provider: '', error: e.code || e.message || 'Lookup failed' };
  }
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ error: 'Use POST' });

  let body = req.body;
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch { body = null; } }
  const list = body && Array.isArray(body.domains) ? body.domains : null;
  if (!list) return res.status(400).json({ error: 'Body must be {"domains": [...]}' });
  if (list.length > MAX_PER_REQUEST) return res.status(400).json({ error: `Max ${MAX_PER_REQUEST} domains per request` });

  const resolver = new dns.Resolver({ timeout: 3000, tries: 2 });
  const domains = list.map((d) => String(d).trim().toLowerCase());
  const results = await Promise.all(domains.map((d) => check(d, resolver, { tls: !!(body && body.tls) })));
  res.status(200).json({ results });
};
