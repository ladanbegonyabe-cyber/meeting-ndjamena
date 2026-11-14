const http = require('http'), crypto = require('crypto'), { promisify } = require('util');
const fs = require('fs'), path = require('path');
const scrypt = promisify(crypto.scrypt);
let Pool = null; try { Pool = require('pg').Pool } catch (e) {}
const pool = process.env.DATABASE_URL && Pool ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 4 }) : null;
const COLS = ['users', 'posts', 'stories', 'msgs', 'reports', 'tok', 'notifs'];
let D = { users: [], posts: [], stories: [], msgs: [], reports: [], tok: {}, notifs: [] };
let dirty = false, timer = null, busy = false;
const id = () => crypto.randomBytes(8).toString('hex');
const S = (v, n) => String(v == null ? '' : v).slice(0, n);
const sha = s => crypto.createHash('sha256').update(String(s)).digest('hex');
const NAME = /^[\p{L}\p{N}][\p{L}\p{N} ._'-]{1,28}[\p{L}\p{N}]$/u;
const ADM = (process.env.ADMINS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
const SEC = { 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer' };
const hashPw = async p => { const s = crypto.randomBytes(16); const h = await scrypt(p, s, 32); return 's1$' + s.toString('hex') + '$' + h.toString('hex') };
const checkPw = async (p, st) => { try { const [, s, h] = String(st).split('$'); const x = await scrypt(p, Buffer.from(s, 'hex'), 32); return crypto.timingSafeEqual(x, Buffer.from(h, 'hex')) } catch (e) { return false } };
const DUMMY = hashPw('dummy-password');
const UB = new Map(), UN = new Map(), PM = new Map(), CM = new Map(), UK = new Map();
const pk = (a, b) => a < b ? a + '|' + b : b + '|' + a;
function addMsg(m) { const k = pk(m.from, m.to); if (!CM.has(k)) CM.set(k, []); CM.get(k).push(m); for (const x of [m.from, m.to]) { if (!UK.has(x)) UK.set(x, new Set()); UK.get(x).add(k) } }
function reindex() { UB.clear(); UN.clear(); PM.clear(); CM.clear(); UK.clear(); D.users.forEach(u => { UB.set(u.id, u); UN.set(u.name.toLowerCase(), u) }); D.posts.forEach(p => PM.set(p.id, p)); D.msgs.forEach(addMsg); if(!D.notifs) D.notifs=[]; if(!D.reports) D.reports=[]; }
async function load() { if (pool) { await pool.query('CREATE TABLE IF NOT EXISTS kv(k text PRIMARY KEY, v text NOT NULL)'); const r = await pool.query('SELECT k,v FROM kv'); for (const row of r.rows) if (COLS.includes(row.k)) D[row.k] = JSON.parse(row.v); } if(!D.notifs) D.notifs=[]; if(!D.reports) D.reports=[]; reindex(); }
const save = () => { dirty = true; if (!timer) timer = setTimeout(flush, 2500) };
async function flush() { timer = null; if (!dirty || busy) return; dirty = false; busy = true; try { const now = Date.now(); for (const t in D.tok) if (D.tok[t].exp < now) delete D.tok[t]; if (pool) { for (const k of COLS) await pool.query('INSERT INTO kv(k,v) VALUES($1,$2) ON CONFLICT (k) DO UPDATE SET v=$2', [k, JSON.stringify(D[k])]); } } catch (e) { dirty = true } busy = false; if (dirty && !timer) timer = setTimeout(flush, 2500) }
function newTok(uid) { const t = crypto.randomBytes(24).toString('hex'); D.tok[sha(t)] = { u: uid, exp: Date.now() + 60 * 864e5 }; save(); return t }
function auth(tk) { if (typeof tk !== 'string') return null; const r = D.tok[sha(tk)]; return r && r.exp > Date.now() ? UB.get(r.u) || null : null }
const pub = u => ({ id: u.id, name: u.name, filiere: u.filiere, bio: u.bio || '', photo: u.photo || '', v: ADM.includes(u.name.toLowerCase()), fol: D.users.reduce((a, x) => a + ((x.following || []).includes(u.id) ? 1 : 0), 0), at: u.at||0 });
const nm = i => (UB.get(i) || {}).name || '?';
function pushNotif(to, from, type, postId, text){ if(to===from) return; D.notifs.push({id:id(), to, from, fromName: nm(from), fromPhoto:(UB.get(from)||{}).photo||'', type, postId: postId||'', text: text||'', seen:false, at: Date.now()}); D.notifs = D.notifs.slice(-500); save(); }
function hiddenCount(pid){ return (D.reports||[]).filter(r=>r.target===pid).length; }
const A = {
  reg: async (b) => { const n = S(b.name, 40).trim(), p = S(b.pass, 200), sec = S(b.secret, 100).toLowerCase().trim(); if (!NAME.test(n)) return { e: "Nom invalide" }; if (UN.has(n.toLowerCase())) return { e: 'Ce nom existe déjà' }; const u = { id: id(), name: n, filiere: S(b.filiere || 'Général', 40), pass: await hashPw(p), secret: await hashPw(sec), photo: '', following: [], saved: [], blocked: [], at: Date.now() }; D.users.push(u); UB.set(u.id, u); UN.set(n.toLowerCase(), u); save(); return { t: newTok(u.id) } },
  login: async (b) => { const n = S(b.name, 40).trim().toLowerCase(), u = UN.get(n); const good = await checkPw(S(b.pass, 200), u ? u.pass : await DUMMY); if (!u || !good) return { e: 'Nom ou mot de passe incorrect' }; return { t: newTok(u.id) } },
  reset: async (b) => { const n = S(b.name, 40).trim().toLowerCase(), u = UN.get(n); if (!u) return { e: 'Utilisateur introuvable' }; const goodSec = await checkPw(S(b.secret, 100).toLowerCase().trim(), u.secret); if (!goodSec) return { e: 'Réponse secrète incorrecte' }; u.pass = await hashPw(S(b.pass, 200)); save(); return { ok: 1 } }
};
const P = {
  me: u => ({ ...pub(u), following: u.following, saved: u.saved, blocked: u.blocked }),
  users: (u, b) => { const q = (b.q || '').toLowerCase(); return D.users.filter(x => x.id !== u.id && (!q || x.name.toLowerCase().includes(q))).slice(0, 30).map(pub) },
  user: (u, b) => UB.get(b.id) ? pub(UB.get(b.id)) : { e: 'Introuvable' },
  feed: (u, b) => { let posts = [...D.posts].filter(p=>hiddenCount(p.id)<3); if (b.type) posts = posts.filter(p => p.type === b.type); if (b.group) posts = posts.filter(p => p.group === b.group); if (b.by) posts = posts.filter(p => p.by === b.by); if (b.saved) posts = posts.filter(p => (u.saved || []).includes(p.id)); if (b.explore) posts = posts.sort((a,b)=> (b.likes||[]).length - (a.likes||[]).length); return posts.slice(-60).reverse().map(p => ({ ...p, name: p.anon?'Anonyme 👻':nm(p.by), photo: p.anon?'':(UB.get(p.by)||{}).photo||'', com: p.com || [] })); },
  explore: (u, b) => { let posts=[...D.posts].filter(p=>hiddenCount(p.id)<3).sort((a,b)=> ((b.likes||[]).length*2 + (b.com||[]).length) - ((a.likes||[]).length*2 + (a.com||[]).length)); if(b.type) posts=posts.filter(p=>p.type===b.type); return posts.slice(0,30).map(p=>({...p, name:p.anon?'Anonyme 👻':nm(p.by), photo:p.anon?'':(UB.get(p.by)||{}).photo||'', com:p.com||[]})); },
  fiches: (u, b) => { let posts=[...D.posts].filter(p=>p.type==='cours' && hiddenCount(p.id)<3); return posts.slice(-30).reverse().map(p=>({...p, name:p.anon?'Anonyme':nm(p.by), photo:(UB.get(p.by)||{}).photo||'', com:p.com||[]})); },
  leaderboard: (u) => { const scores={}; D.users.forEach(x=>scores[x.id]={id:x.id,name:x.name,photo:x.photo||'',filiere:x.filiere,pts:0,posts:0}); D.posts.forEach(p=>{ if(scores[p.by]){ scores[p.by].posts++; scores[p.by].pts+=10; scores[p.by].pts+=(p.likes||[]).length*2; scores[p.by].pts+=(p.com||[]).length*3; } }); return Object.values(scores).sort((a,b)=>b.pts-a.pts).slice(0,10); },
  stories: () => D.stories.filter(s => s.at > Date.now() - 864e5).map(s => ({ ...s, name: nm(s.by), photo: (UB.get(s.by)||{}).photo||''})),
  post: (u, b) => { const p = { id: id(), by: u.id, type: S(b.type, 20), text: S(b.text, 2000), date: S(b.date, 50), img: b.img || '', group: S(b.group, 40), price: S(b.price, 20), wa: S(b.wa, 30), anon: !!b.anon, participants: [], best: '', ratings: [], opts: (b.opts || []).slice(0, 5).map(t => ({ t: S(t, 100), v: [] })), likes: [], com: [], at: Date.now() }; D.posts.push(p); PM.set(p.id, p); save(); return { ok: 1 }; },
  delpost: (u, b) => { const p = PM.get(b.id); if (!p) return { e: 'Introuvable' }; const isAdmin = ADM.includes(u.name.toLowerCase()); if (p.by !== u.id && !isAdmin) return { e: 'Non autorisé' }; D.posts = D.posts.filter(x => x.id !== b.id); PM.delete(b.id); save(); return { ok: 1 }; },
  like: (u, b) => { const p = PM.get(b.id); if (!p) return { e: '' }; const i = p.likes.indexOf(u.id); if (i >= 0) p.likes.splice(i, 1); else { p.likes.push(u.id); pushNotif(p.by, u.id, 'like', p.id, 'a aimé ta publication'); } save(); return { ok: 1 } },
  save: (u, b) => { const i = u.saved.indexOf(b.id); if (i >= 0) u.saved.splice(i, 1); else u.saved.push(b.id); save(); return { ok: 1 } },
  comment: (u, b) => { const p = PM.get(b.id); if (!p) return { e: '' }; p.com.push({ id: id(), by: u.id, name: u.name, photo: u.photo||'', text: S(b.text, 500), at: Date.now() }); pushNotif(p.by, u.id, 'comment', p.id, S(b.text, 80)); save(); return { ok: 1 } },
  markbest: (u, b) => { const p = PM.get(b.id); if(!p || p.by!==u.id) return {e:'Non autorisé'}; p.best = b.cid; save(); return {ok:1} },
  participate: (u, b) => { const p = PM.get(b.id); if(!p) return {e:''}; if(!p.participants) p.participants=[]; const i=p.participants.indexOf(u.id); if(i>=0) p.participants.splice(i,1); else p.participants.push(u.id); save(); return {ok:1} },
  rate: (u, b) => { const p = PM.get(b.id); if(!p) return {e:''}; if(!p.ratings) p.ratings=[]; p.ratings = p.ratings.filter(r=>r.by!==u.id); p.ratings.push({by:u.id, v: Math.max(1,Math.min(5,Number(b.v)||5))}); save(); return {ok:1} },
  report: (u, b) => { D.reports.push({id:id(), target:b.target, why:S(b.why,200), by:u.id, at:Date.now()}); save(); return {ok:1, count: hiddenCount(b.target)} },
  story: (u, b) => { D.stories.push({ id: id(), by: u.id, text: S(b.text, 300), img: b.img || '', at: Date.now() }); save(); return { ok: 1 } },
  vote: (u, b) => { const p = PM.get(b.id); if (!p || !p.opts[b.i]) return { e: '' }; p.opts.forEach(o => { const idx = o.v.indexOf(u.id); if (idx >= 0) o.v.splice(idx, 1); }); p.opts[b.i].v.push(u.id); save(); return { ok: 1 } },
  notifs: (u) => { const list = (D.notifs||[]).filter(n=>n.to===u.id).slice(-30).reverse(); return { list, un: list.filter(n=>!n.seen).length }; },
  notif_read: (u) => { (D.notifs||[]).forEach(n=>{ if(n.to===u.id) n.seen=true; }); save(); return { ok: 1 }; },
  chats: (u) => { const set = UK.get(u.id) || new Set(), res = []; for (const k of set) { const msgs = CM.get(k) || [], lastMsg = msgs[msgs.length - 1]; if (!lastMsg) continue; const peerId = lastMsg.from === u.id ? lastMsg.to : lastMsg.from, peer = UB.get(peerId); if (peer) res.push({ id: peer.id, name: peer.name, photo: peer.photo||'', last: lastMsg.img ? '📎 Média' : (lastMsg.text || 'Média'), un: msgs.filter(m => m.to === u.id && !m.seen).length }); } return res; },
  convo: (u, b) => { const k = pk(u.id, b.with), msgs = CM.get(k) || []; msgs.forEach(m => { if (m.to === u.id) m.seen = true; }); save(); return { m: msgs, ty: false } },
  send: (u, b) => { const m = { id: id(), from: u.id, to: b.to, text: S(b.text, 1000), img: String(b.img||'').slice(0, 2000000), audio: b.audio || '', ref: S(b.ref, 100), seen: false, at: Date.now() }; D.msgs.push(m); addMsg(m); save(); return { ok: 1 } },
  follow: (u, b) => { const i = u.following.indexOf(b.id); if (i >= 0) u.following.splice(i, 1); else { u.following.push(b.id); pushNotif(b.id, u.id, 'follow', '', 's’est abonné(e) à toi'); } save(); return { ok: 1 } },
  bio: (u, b) => { u.bio = S(b.bio, 200); u.filiere = S(b.filiere || u.filiere, 40); save(); return { ok: 1 } },
  pass: async (u, b) => { if (!await checkPw(S(b.old, 200), u.pass)) return { e: 'Ancien mot de passe incorrect' }; u.pass = await hashPw(S(b.pass, 200)); save(); return { ok: 1 } },
  photo: (u, b) => { u.photo = String(b.img||'').slice(0, 500000); save(); return { ok: 1 } },
  poll: () => ({ un: 0, sig: 0, last: null }),
  logout: (u, b, h) => { const tk = h['x-token']; if (tk) delete D.tok[sha(tk)]; save(); return { ok: 1 } }
};
function getHTML(){ try { return fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8'); } catch(e){ return '<h1>public/index.html introuvable</h1>'; } }
const srv = http.createServer((q, r) => {
  if (q.method === 'POST' && q.url.startsWith('/api/')) {
    let s = ''; q.on('data', d => s += d); q.on('end', async () => { let o = { e: 'Erreur' }; try { const b = JSON.parse(s || '{}'), n = q.url.slice(5); if (A[n]) o = await A[n](b); else { const u = auth(q.headers['x-token']); if (!u) { r.writeHead(401, SEC); return r.end('{}') } if (P[n]) o = await P[n](u, b); } } catch (e) {} r.writeHead(200, { 'Content-Type': 'application/json', ...SEC }); r.end(JSON.stringify(o)); }); return;
  }
  if (q.url.startsWith('/photo/')) { const uid = q.url.split('/')[2].split('?')[0]; const u = UB.get(uid); if (u && u.photo) { const m = u.photo.match(/^data:(image\/\w+);base64,(.+)$/); if (m) { r.writeHead(200, { 'Content-Type': m[1] }); return r.end(Buffer.from(m[2], 'base64')); } } r.writeHead(404); return r.end(''); }
  r.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...SEC }); r.end(getHTML());
});
load().then(() => srv.listen(process.env.PORT || 3000, () => console.log('Serveur prêt')));
