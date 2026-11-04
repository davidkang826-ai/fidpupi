const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const { Pool } = require('pg');

const scrypt = promisify(crypto.scrypt);
const PUBLIC = path.join(__dirname, 'public');
const TABS = ['feed', 'pee', 'poop'];
const COOKIE = 'fp_session';
const SESSION_DAYS = 365;

const url = process.env.DATABASE_URL;
const pool = new Pool({
  connectionString: url,
  ssl: url && !/railway\.internal|localhost|127\.0\.0\.1/.test(url) ? { rejectUnauthorized: false } : false,
});

async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      child_name TEXT NOT NULL,
      salt TEXT NOT NULL,
      pw_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS records (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      tab TEXT NOT NULL,
      ts BIGINT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS records_user_idx ON records(user_id, tab, ts DESC);
  `);
}

// ---------- helpers ----------
const TYPES = {
  '.html': 'text/html; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png',
  '.webmanifest': 'application/manifest+json', '.js': 'text/javascript', '.css': 'text/css',
};
const sha = s => crypto.createHash('sha256').update(s).digest('hex');

function send(res, status, obj, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers });
  res.end(JSON.stringify(obj));
}
function readJSON(req) {
  return new Promise((resolve, reject) => {
    let size = 0, chunks = [];
    req.on('data', c => { size += c.length; if (size > 20000) { reject(new Error('too big')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString() || '{}')); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}
function cookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('='); if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function sessionCookie(req, token, maxAgeSec) {
  const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
  return `${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSec}${secure}`;
}
async function currentUser(req) {
  const t = cookies(req)[COOKIE];
  if (!t) return null;
  const r = await pool.query(
    `SELECT u.id, u.email, u.child_name FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = $1 AND s.created_at > now() - interval '${SESSION_DAYS} days'`, [sha(t)]);
  return r.rows[0] || null;
}
async function startSession(req, res, userId, body) {
  const token = crypto.randomBytes(32).toString('hex');
  await pool.query('INSERT INTO sessions (token_hash, user_id) VALUES ($1, $2)', [sha(token), userId]);
  send(res, 200, body, { 'Set-Cookie': sessionCookie(req, token, SESSION_DAYS * 86400) });
}

// light brute-force guard: 10 auth attempts / 15 min / IP
const attempts = new Map();
function tooMany(req) {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  const now = Date.now();
  const a = attempts.get(ip);
  if (!a || a.reset < now) { attempts.set(ip, { n: 1, reset: now + 15 * 60000 }); return false; }
  a.n++; return a.n > 10;
}
setInterval(() => { const n = Date.now(); for (const [k, v] of attempts) if (v.reset < n) attempts.delete(k); }, 600000).unref();

// ---------- API ----------
async function api(req, res, pathname) {
  const method = req.method;

  if (pathname === '/api/signup' && method === 'POST') {
    if (tooMany(req)) return send(res, 429, { error: 'Too many tries. Please wait a few minutes.' });
    const b = await readJSON(req);
    const child = String(b.child || '').trim().slice(0, 40);
    const email = String(b.email || '').trim().toLowerCase();
    const pw = String(b.password || '');
    if (!child) return send(res, 400, { error: "Please enter your baby's name." });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 200) return send(res, 400, { error: 'Please enter a valid email.' });
    if (pw.length < 8 || pw.length > 200) return send(res, 400, { error: 'Password must be at least 8 characters.' });
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = (await scrypt(pw, salt, 64)).toString('hex');
    try {
      const r = await pool.query(
        'INSERT INTO users (email, child_name, salt, pw_hash) VALUES ($1, $2, $3, $4) RETURNING id',
        [email, child, salt, hash]);
      return startSession(req, res, r.rows[0].id, { child, email });
    } catch (e) {
      if (e.code === '23505') return send(res, 409, { error: 'That email already has an account. Try logging in.' });
      throw e;
    }
  }

  if (pathname === '/api/login' && method === 'POST') {
    if (tooMany(req)) return send(res, 429, { error: 'Too many tries. Please wait a few minutes.' });
    const b = await readJSON(req);
    const email = String(b.email || '').trim().toLowerCase();
    const pw = String(b.password || '').slice(0, 200);
    const r = await pool.query('SELECT id, child_name, salt, pw_hash FROM users WHERE email = $1', [email]);
    const u = r.rows[0];
    // always do the hash work so timing doesn't reveal whether the email exists
    const hash = await scrypt(pw, u ? u.salt : 'x'.repeat(32), 64);
    if (!u || !crypto.timingSafeEqual(hash, Buffer.from(u.pw_hash, 'hex'))) {
      return send(res, 401, { error: 'Wrong email or password.' });
    }
    return startSession(req, res, u.id, { child: u.child_name, email });
  }

  if (pathname === '/api/logout' && method === 'POST') {
    const t = cookies(req)[COOKIE];
    if (t) await pool.query('DELETE FROM sessions WHERE token_hash = $1', [sha(t)]);
    return send(res, 200, { ok: true }, { 'Set-Cookie': sessionCookie(req, '', 0) });
  }

  const user = await currentUser(req);
  if (!user) return send(res, 401, { error: 'Please log in.' });

  if (pathname === '/api/me' && method === 'GET') return send(res, 200, { child: user.child_name, email: user.email });

  if (pathname === '/api/records' && method === 'GET') {
    const r = await pool.query('SELECT id, tab, ts FROM records WHERE user_id = $1 ORDER BY ts DESC LIMIT 5000', [user.id]);
    const out = { feed: [], pee: [], poop: [] };
    r.rows.forEach(x => out[x.tab] && out[x.tab].push({ id: x.id, ts: Number(x.ts) }));
    return send(res, 200, out);
  }

  if (pathname === '/api/records' && method === 'POST') {
    const b = await readJSON(req);
    if (!TABS.includes(b.tab) || !/^[a-z0-9]{1,40}$/i.test(String(b.id)) || !Number.isSafeInteger(b.ts)) {
      return send(res, 400, { error: 'Bad record.' });
    }
    await pool.query('INSERT INTO records (id, user_id, tab, ts) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING',
      [b.id, user.id, b.tab, b.ts]);
    return send(res, 200, { ok: true });
  }

  const m = pathname.match(/^\/api\/records\/([a-z0-9]{1,40})$/i);
  if (m && method === 'PATCH') {
    const b = await readJSON(req);
    if (!Number.isSafeInteger(b.ts)) return send(res, 400, { error: 'Bad time.' });
    await pool.query('UPDATE records SET ts = $1 WHERE id = $2 AND user_id = $3', [b.ts, m[1], user.id]);
    return send(res, 200, { ok: true });
  }
  if (m && method === 'DELETE') {
    await pool.query('DELETE FROM records WHERE id = $1 AND user_id = $2', [m[1], user.id]);
    return send(res, 200, { ok: true });
  }

  return send(res, 404, { error: 'Not found' });
}

// ---------- server ----------
const server = http.createServer(async (req, res) => {
  try {
    let p = decodeURIComponent(req.url.split('?')[0]);
    if (p.startsWith('/api/')) return await api(req, res, p);
    if (p === '/') p = '/index.html';
    const file = path.join(PUBLIC, path.normalize(p));
    if (!file.startsWith(PUBLIC)) { res.writeHead(403); return res.end(); }
    fs.readFile(file, (err, data) => {
      if (err) { res.writeHead(404); return res.end('Not found'); }
      res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
      res.end(data);
    });
  } catch (e) {
    console.error(e);
    if (!res.headersSent) send(res, 500, { error: 'Something went wrong. Please try again.' });
  }
});

migrate().then(() => {
  server.listen(process.env.PORT || 3000, () => console.log('FidPuPi running'));
}).catch(e => { console.error('Migration failed', e); process.exit(1); });
