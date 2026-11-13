const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto'), { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);
let Pool = null; try { Pool = require('pg').Pool } catch (e) {}
const pool = process.env.DATABASE_URL && Pool ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 4 }) : null;
const DIR = process.env.DATA_DIR || __dirname, F = path.join(DIR, 'data.json'), MDIR = path.join(DIR, 'media');
const COLS = ['users', 'posts', 'stories', 'msgs', 'reports', 'tok'];
let D = { users: [], posts: [], stories: [], msgs: [], reports: [], tok: {} };
const TY = {}, RL = {}, last = {};
let VER = 0, dirty = false, timer = null, busy = false;

const id = () => crypto.randomBytes(8).toString('hex');
const S = (v, n) => String(v == null ? '' : v).slice(0, n);
const sha = s => crypto.createHash('sha256').update(String(s)).digest('hex');
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const ok = { ok: 1 }, TOO = { e: 'Trop de tentatives. Réessaie dans quelques minutes.', _c: 429 };
const NAME = /^[\p{L}\p{N}][\p{L}\p{N} ._'-]{1,28}[\p{L}\p{N}]$/u;
const IMG = /^data:(image\/(?:jpeg|png|webp|gif));base64,([A-Za-z0-9+\/]+={0,2})$/;
const VID = /^data:(video\/[\w.+-]+)(?:;[\w=.+-]+)*;base64,([A-Za-z0-9+\/]+={0,2})$/;
const PDF = /^data:(application\/pdf)(?:;[\w=.+-]+)*;base64,([A-Za-z0-9+\/]+={0,2})$/;
const AUD = /^data:(audio\/[\w.+-]+)(?:;[\w=.+-]+)*;base64,([A-Za-z0-9+\/]+={0,2})$/;
const ADM = (process.env.ADMINS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
const SEC = { 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer' };

const limit = (k, max, ms) => { const n = Date.now(); const r = RL[k] && RL[k].t > n ? RL[k] : (RL[k] = { t: n + ms, c: 0 }); return ++r.c > max };

const hashPw = async p => { const s = crypto.randomBytes(16); const h = await scrypt(p, s, 32); return 's1$' + s.toString('hex') + '$' + h.toString('hex') };
const checkPw = async (p, st) => { try { const [, s, h] = String(st).split('$'); const x = await scrypt(p, Buffer.from(s, 'hex'), 32); return crypto.timingSafeEqual(x, Buffer.from(h, 'hex')) } catch (e) { return false } };
const DUMMY = hashPw('dummy-password');

const UB = new Map(), UN = new Map(), PM = new Map(), CM = new Map(), UK = new Map();
const pk = (a, b) => a < b ? a + '|' + b : b + '|' + a;
function addMsg(m) { const k = pk(m.from, m.to); if (!CM.has(k)) CM.set(k, []); CM.get(k).push(m); for (const x of [m.from, m.to]) { if (!UK.has(x)) UK.set(x, new Set()); UK.get(x).add(k) } }
function reindex() { UB.clear(); UN.clear(); PM.clear(); CM.clear(); UK.clear(); D.users.forEach(u => { UB.set(u.id, u); UN.set(u.name.toLowerCase(), u) }); D.posts.forEach(p => PM.set(p.id, p)); D.msgs.forEach(addMsg) }

async function load() {
  if (pool) {
    await pool.query('CREATE TABLE IF NOT EXISTS kv(k text PRIMARY KEY, v text NOT NULL)');
    await pool.query('CREATE TABLE IF NOT EXISTS media(id text PRIMARY KEY, mime text NOT NULL, data bytea NOT NULL)');
    const r = await pool.query('SELECT k,v FROM kv');
    for (const row of r.rows) if (COLS.includes(row.k)) { D[row.k] = JSON.parse(row.v); last[row.k] = row.v }
    console.log('Base de données connectée');
  } else {
    try { const j = JSON.parse(fs.readFileSync(F)); for (const k of COLS) if (j[k]) D[k] = j[k] } catch (e) {}
  }
  reindex()
}
const save = () => { dirty = true; VER++; if (!timer) timer = setTimeout(flush, 2500) };
async function flush() {
  timer = null; if (!dirty || busy) return; dirty = false; busy = true;
  try {
    const now = Date.now(); for (const t in D.tok) if (D.tok[t].exp < now) delete D.tok[t];
    const ch = []; for (const k of COLS) { const s = JSON.stringify(D[k]); if (s !== last[k]) ch.push([k, s]) }
    if (pool) { for (const [k, s] of ch) { await pool.query('INSERT INTO kv(k,v) VALUES($1,$2) ON CONFLICT (k) DO UPDATE SET v=$2', [k, s]); last[k] = s } }
  } catch (e) { dirty = true }
  busy = false; if (dirty && !timer) timer = setTimeout(flush, 2500)
}

async function putMedia(du, kind, max) {
  if (typeof du !== 'string' || du.length > max) return null;
  let m = kind === 'audio' ? AUD.exec(du) : (kind === 'video' ? VID.exec(du) : (kind === 'pdf' ? PDF.exec(du) : IMG.exec(du)));
  if (!m) return null;
  const buf = Buffer.from(m[2], 'base64'), mid = crypto.randomBytes(12).toString('hex'), mime = m[1].toLowerCase();
  if (pool) await pool.query('INSERT INTO media(id,mime,data) VALUES($1,$2,$3)', [mid, mime, buf]);
  return mid
}
async function getMedia(mid) {
  if (pool) { const r = await pool.query('SELECT mime,data FROM media WHERE id=$1', [mid]); return r.rows[0] || null }
  return null
}

function newTok(uid) { const t = crypto.randomBytes(24).toString('hex'); D.tok[sha(t)] = { u: uid, exp: Date.now() + 60 * 864e5 }; save(); return t }
function auth(tk) { if (typeof tk !== 'string') return null; const r = D.tok[sha(tk)]; return r && r.exp > Date.now() ? UB.get(r.u) || null : null }

const pub = u => ({ id: u.id, name: u.name, filiere: u.filiere, bio: u.bio || '', v: ADM.includes(u.name.toLowerCase()), fol: D.users.reduce((a, x) => a + ((x.following || []).includes(u.id) ? 1 : 0), 0) });
const nm = i => (UB.get(i) || {}).name || '?';

const A = {
  reg: async (b, ip) => {
    const n = S(b.name, 40).trim(), p = S(b.pass, 200), sec = S(b.secret, 100).toLowerCase().trim();
    if (!NAME.test(n)) return { e: "Nom invalide" };
    if (UN.has(n.toLowerCase())) return { e: 'Ce nom existe déjà' };
    const u = { id: id(), name: n, filiere: S(b.filiere || 'Général', 40), pass: await hashPw(p), secret: await hashPw(sec), following: [], saved: [], blocked: [], at: Date.now() };
    D.users.push(u); UB.set(u.id, u); UN.set(n.toLowerCase(), u); save(); return { t: newTok(u.id) }
  },
  login: async (b) => {
    const n = S(b.name, 40).trim().toLowerCase(), u = UN.get(n);
    const good = await checkPw(S(b.pass, 200), u ? u.pass : await DUMMY);
    if (!u || !good) return { e: 'Nom ou mot de passe incorrect' };
    return { t: newTok(u.id) }
  }
};

const P = {
  me: u => ({ ...pub(u), following: u.following, saved: u.saved, blocked: u.blocked }),
  users: (u, b) => D.users.filter(x => x.id !== u.id).slice(0, 30).map(pub),
  feed: () => D.posts.slice(-40).reverse().map(p => ({ ...p, name: nm(p.by), com: [] })),
  stories: () => []
};

const srv = http.createServer((q, r) => {
  if (q.method === 'POST' && q.url.startsWith('/api/')) {
    let s = '';
    q.on('data', d => s += d);
    q.on('end', async () => {
      let o = { e: 'Erreur' };
      try {
        const b = JSON.parse(s || '{}'), n = q.url.slice(5);
        if (A[n]) o = await A[n](b);
        else { const u = auth(q.headers['x-token']); if (!u) { r.writeHead(401, SEC); return r.end('{}') } if (P[n]) o = await P[n](u, b); }
      } catch (e) {}
      r.writeHead(200, { 'Content-Type': 'application/json', ...SEC });
      r.end(JSON.stringify(o));
    });
    return;
  }

  // Envoi direct du fichier index.html
  const filePath = path.join(__dirname, 'public', 'index.html');
  fs.readFile(filePath, (err, content) => {
    if (err) {
      r.writeHead(404, { 'Content-Type': 'text/plain' });
      r.end('Erreur : index.html introuvable dans le dossier public');
    } else {
      r.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...SEC });
      r.end(content);
    }
  });
});

load().then(() => srv.listen(process.env.PORT || 3000, () => console.log('Serveur prêt')));
