// Zero-dependency server: static files + small JSON API. Works on Railway with `npm start`.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'room.json');
const PUBLIC = path.join(__dirname, 'public');

const TTL_MS = 24 * 60 * 60 * 1000; // messages live 24 hours
const TOKEN_MS = 2 * 60 * 60 * 1000; // login lasts 2 hours (refresh asks key again anyway)
const WINDOW_MS = 15 * 60 * 1000;
const MAX_PER_IP = 5;
const MAX_ALL = 40;
const MIN_KEY = 4;

/* ---------- storage (one JSON file; only hashes + encrypted messages) ---------- */
fs.mkdirSync(DATA_DIR, { recursive: true });
let db = { keys: {}, ver: { A: 1, B: 1 }, secrets: {}, messages: [] };
try { db = { ...db, ...JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')) }; } catch { /* first run */ }

let saveTimer = null;
function flush() {
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DATA_FILE);
}
function save() { clearTimeout(saveTimer); saveTimer = setTimeout(flush, 300); }

db.secrets = db.secrets || {};
if (!db.secrets.token) db.secrets.token = crypto.randomBytes(32).toString('hex');
if (!db.secrets.enc) db.secrets.enc = crypto.randomBytes(32).toString('base64');
const TOKEN_SECRET = process.env.TOKEN_SECRET || db.secrets.token;
const ENC_KEY = Buffer.from(process.env.ENC_KEY || db.secrets.enc, 'base64');

/* ---------- keys ---------- */
const hashKey = (k, salt) => crypto.scryptSync(k, salt, 32).toString('hex');
function safeEqual(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function setKey(role, key) {
  const salt = crypto.randomBytes(16).toString('hex');
  db.keys[role] = { salt, hash: hashKey(key, salt) };
}
// First boot: turn CODE_A / CODE_B variables into hashes. Keys changed in the app win afterwards.
for (const r of ['A', 'B']) {
  const env = process.env['CODE_' + r];
  if (!db.keys[r] && env) setKey(r, env);
}
if (!db.keys.A || !db.keys.B) console.warn('Set CODE_A and CODE_B variables to create the two keys.');
flush();

function matchRole(code) {
  let found = null;
  for (const r of ['A', 'B']) {
    const k = db.keys[r];
    if (k && safeEqual(hashKey(code, k.salt), k.hash)) found = r; // always check both
  }
  return found;
}

/* ---------- tokens ---------- */
const mac = (body) => crypto.createHmac('sha256', TOKEN_SECRET).update(body).digest('base64url');
function sign(role) {
  const body = Buffer.from(JSON.stringify({ r: role, v: db.ver[role], exp: Date.now() + TOKEN_MS })).toString('base64url');
  return `${body}.${mac(body)}`;
}
function verify(req) {
  const h = req.headers.authorization || '';
  const [body, sig] = (h.startsWith('Bearer ') ? h.slice(7) : '').split('.');
  if (!body || !sig || !safeEqual(sig, mac(body))) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (!p || p.exp < Date.now() || !db.keys[p.r] || p.v !== db.ver[p.r]) return null;
    return p;
  } catch { return null; }
}

/* ---------- message encryption (AES-256-GCM) ---------- */
function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const ct = Buffer.concat([c.update(text, 'utf8'), c.final()]);
  return [iv, c.getAuthTag(), ct].map((b) => b.toString('base64')).join('.');
}
function decrypt(packed) {
  const [iv, tag, ct] = packed.split('.').map((s) => Buffer.from(s, 'base64'));
  const d = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
}
function prune() {
  const cutoff = Date.now() - TTL_MS;
  const before = db.messages.length;
  db.messages = db.messages.filter((m) => m.t > cutoff);
  if (db.messages.length !== before) save();
}

/* ---------- rate limit (login + key change) ---------- */
const hits = new Map();
let all = { n: 0, reset: 0 };
function limited(ip) {
  const now = Date.now();
  let h = hits.get(ip);
  if (!h || h.reset < now) { h = { n: 0, reset: now + WINDOW_MS }; hits.set(ip, h); }
  if (all.reset < now) all = { n: 0, reset: now + WINDOW_MS };
  h.n++; all.n++;
  return h.n > MAX_PER_IP || all.n > MAX_ALL;
}
const clientIp = (req) =>
  req.headers['x-real-ip'] || (req.headers['x-forwarded-for'] || '').split(',').pop().trim() || req.socket.remoteAddress || 'x';

setInterval(() => {
  prune();
  const now = Date.now();
  for (const [k, v] of hits) if (v.reset < now) hits.delete(k);
}, 60 * 1000).unref();

/* ---------- http helpers ---------- */
const SEC = {
  'Cache-Control': 'no-store',
  'X-Robots-Tag': 'noindex, nofollow, noarchive',
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Strict-Transport-Security': 'max-age=31536000',
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
};
function send(res, status, data) {
  res.writeHead(status, { ...SEC, 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(data));
}
function readJson(req) {
  return new Promise((resolve) => {
    let b = '';
    req.on('data', (c) => { b += c; if (b.length > 20000) { req.destroy(); resolve({}); } });
    req.on('end', () => { try { resolve(JSON.parse(b || '{}')); } catch { resolve({}); } });
    req.on('error', () => resolve({}));
  });
}
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.txt': 'text/plain; charset=utf-8' };
function serveStatic(req, res) {
  let p = decodeURIComponent(req.url.split('?')[0]);
  if (p === '/') p = '/index.html';
  const f = path.normalize(path.join(PUBLIC, p));
  if (!f.startsWith(PUBLIC + path.sep) || !fs.existsSync(f) || !fs.statSync(f).isFile()) {
    res.writeHead(404, { ...SEC, 'Content-Type': 'text/plain' });
    return res.end('Not found');
  }
  res.writeHead(200, { ...SEC, 'Content-Type': MIME[path.extname(f)] || 'application/octet-stream' });
  fs.createReadStream(f).pipe(res);
}

/* ---------- API ---------- */
const BAD_KEY = { error: "That key isn't valid." };
const routes = {
  'POST /api/login': async (req, res) => {
    if (!db.keys.A && !db.keys.B) return send(res, 503, { error: 'Not configured.' });
    const ip = clientIp(req);
    const { code } = await readJson(req);
    if (limited(ip)) return send(res, 429, { error: 'Too many attempts. Try again later.' });
    if (typeof code !== 'string' || !code || code.length > 100) return send(res, 401, BAD_KEY);
    const role = matchRole(code);
    if (!role) return send(res, 401, BAD_KEY);
    hits.delete(clientIp(req));
    send(res, 200, { token: sign(role), role });
  },

  'GET /api/messages': async (req, res) => {
    if (!verify(req)) return send(res, 401, { error: 'locked' });
    prune();
    const messages = [];
    for (const m of db.messages) {
      try { messages.push({ id: m.i, r: m.r, t: m.t, text: decrypt(m.c) }); } catch { /* skip */ }
    }
    send(res, 200, { messages });
  },

  'POST /api/send': async (req, res) => {
    const me = verify(req);
    if (!me) return send(res, 401, { error: 'locked' });
    const { text } = await readJson(req);
    const t = typeof text === 'string' ? text.trim() : '';
    if (!t || t.length > 2000) return send(res, 400, { error: 'Message must be 1 to 2000 characters.' });
    db.messages.push({ i: crypto.randomUUID(), r: me.r, t: Date.now(), c: encrypt(t) });
    if (db.messages.length > 5000) db.messages.splice(0, db.messages.length - 5000);
    save();
    send(res, 200, { ok: true });
  },

  'POST /api/clear': async (req, res) => {
    if (!verify(req)) return send(res, 401, { error: 'locked' });
    db.messages = [];
    save();
    send(res, 200, { ok: true });
  },

  'POST /api/change-key': async (req, res) => {
    const me = verify(req);
    if (!me) return send(res, 401, { error: 'locked' });
    if (limited(clientIp(req))) return send(res, 429, { error: 'Too many attempts. Try again later.' });
    const { current, next } = await readJson(req);
    if (typeof current !== 'string' || matchRole(current) !== me.r) return send(res, 403, { error: 'Current key is wrong.' });
    if (typeof next !== 'string' || next.length < MIN_KEY || next.length > 100) {
      return send(res, 400, { error: `New key must be ${MIN_KEY} to 100 characters.` });
    }
    const other = me.r === 'A' ? 'B' : 'A';
    const ok = db.keys[other];
    if (ok && safeEqual(hashKey(next, ok.salt), ok.hash)) return send(res, 400, { error: 'Choose a different key.' });
    setKey(me.r, next);
    db.ver[me.r] += 1; // signs out every other session of this user
    save();
    hits.delete(clientIp(req));
    send(res, 200, { token: sign(me.r) });
  },
};

http.createServer(async (req, res) => {
  try {
    const handler = routes[`${req.method} ${req.url.split('?')[0]}`];
    if (handler) return await handler(req, res);
    if (req.url.startsWith('/api/')) return send(res, 404, { error: 'Not found' });
    if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, { error: 'Method not allowed' });
    serveStatic(req, res);
  } catch (e) {
    console.error(e.message);
    if (!res.headersSent) send(res, 500, { error: 'Something went wrong' });
  }
}).listen(PORT, '0.0.0.0', () => console.log('Listening on ' + PORT));

for (const sig of ['SIGTERM', 'SIGINT']) process.on(sig, () => { try { flush(); } catch {} process.exit(0); });
