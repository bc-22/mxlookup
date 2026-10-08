// POST /api/mx  { "domains": ["example.com", ...] }  (max 50 per request)
// The browser splits big lists (up to 1000) into batches and calls this repeatedly.
const dns = require('node:dns').promises;

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

async function check(domain, resolver) {
  if (!DOMAIN_RE.test(domain)) return { domain, status: 'invalid', records: [], provider: '', error: 'Not a valid domain' };
  try {
    const raw = await resolver.resolveMx(domain);
    const records = raw
      .map((r) => ({ priority: r.priority, exchange: (r.exchange || '').toLowerCase().replace(/\.$/, '') }))
      .sort((a, b) => a.priority - b.priority);
    if (!records.length || (records.length === 1 && records[0].exchange === '')) {
      return { domain, status: 'none', records: [], provider: '', error: 'Null MX (domain does not accept mail)' };
    }
    return { domain, status: 'ok', records, provider: detectProvider(records.map((r) => r.exchange)), error: '' };
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
  const results = await Promise.all(domains.map((d) => check(d, resolver)));
  res.status(200).json({ results });
};
