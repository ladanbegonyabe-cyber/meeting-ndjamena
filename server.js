const http = require('http'), crypto = require('crypto'), { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);
let Pool = null; try { Pool = require('pg').Pool } catch (e) {}
const pool = process.env.DATABASE_URL && Pool ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 4 }) : null;
const COLS = ['users', 'posts', 'stories', 'msgs', 'reports', 'tok'];
let D = { users: [], posts: [], stories: [], msgs: [], reports: [], tok: {} };
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
function reindex() { UB.clear(); UN.clear(); PM.clear(); CM.clear(); UK.clear(); D.users.forEach(u => { UB.set(u.id, u); UN.set(u.name.toLowerCase(), u) }); D.posts.forEach(p => PM.set(p.id, p)); D.msgs.forEach(addMsg) }

async function load() {
  if (pool) {
    await pool.query('CREATE TABLE IF NOT EXISTS kv(k text PRIMARY KEY, v text NOT NULL)');
    const r = await pool.query('SELECT k,v FROM kv');
    for (const row of r.rows) if (COLS.includes(row.k)) D[row.k] = JSON.parse(row.v);
  }
  reindex();
}

const save = () => { dirty = true; if (!timer) timer = setTimeout(flush, 2500) };
async function flush() {
  timer = null; if (!dirty || busy) return; dirty = false; busy = true;
  try {
    const now = Date.now(); for (const t in D.tok) if (D.tok[t].exp < now) delete D.tok[t];
    if (pool) { for (const k of COLS) await pool.query('INSERT INTO kv(k,v) VALUES($1,$2) ON CONFLICT (k) DO UPDATE SET v=$2', [k, JSON.stringify(D[k])]); }
  } catch (e) { dirty = true }
  busy = false; if (dirty && !timer) timer = setTimeout(flush, 2500)
}

function newTok(uid) { const t = crypto.randomBytes(24).toString('hex'); D.tok[sha(t)] = { u: uid, exp: Date.now() + 60 * 864e5 }; save(); return t }
function auth(tk) { if (typeof tk !== 'string') return null; const r = D.tok[sha(tk)]; return r && r.exp > Date.now() ? UB.get(r.u) || null : null }

const pub = u => ({ id: u.id, name: u.name, filiere: u.filiere, bio: u.bio || '', v: ADM.includes(u.name.toLowerCase()), fol: D.users.reduce((a, x) => a + ((x.following || []).includes(u.id) ? 1 : 0), 0) });
const nm = i => (UB.get(i) || {}).name || '?';

const A = {
  reg: async (b) => {
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
  },
  reset: async (b) => {
    const n = S(b.name, 40).trim().toLowerCase(), u = UN.get(n);
    if (!u) return { e: 'Utilisateur introuvable' };
    const goodSec = await checkPw(S(b.secret, 100).toLowerCase().trim(), u.secret);
    if (!goodSec) return { e: 'Réponse secrète incorrecte' };
    u.pass = await hashPw(S(b.pass, 200)); save(); return { ok: 1 }
  }
};

const P = {
  me: u => ({ ...pub(u), following: u.following, saved: u.saved, blocked: u.blocked }),
  users: (u, b) => { const q = (b.q || '').toLowerCase(); return D.users.filter(x => x.id !== u.id && (!q || x.name.toLowerCase().includes(q))).slice(0, 30).map(pub) },
  user: (u, b) => UB.get(b.id) ? pub(UB.get(b.id)) : { e: 'Introuvable' },
  feed: (u, b) => {
    let posts = [...D.posts];
    if (b.type) posts = posts.filter(p => p.type === b.type);
    if (b.group) posts = posts.filter(p => p.group === b.group);
    if (b.by) posts = posts.filter(p => p.by === b.by);
    if (b.saved) posts = posts.filter(p => (u.saved || []).includes(p.id));
    return posts.slice(-40).reverse().map(p => ({ ...p, name: nm(p.by), com: p.com || [] }));
  },
  stories: () => D.stories.filter(s => s.at > Date.now() - 864e5).map(s => ({ ...s, name: nm(s.by)})),
  post: (u, b) => {
    const p = { id: id(), by: u.id, type: S(b.type, 20), text: S(b.text, 2000), date: S(b.date, 50), img: b.img || '', group: S(b.group, 40), opts: (b.opts || []).slice(0, 5).map(t => ({ t: S(t, 100), v: [] })), likes: [], com: [], at: Date.now() };
    D.posts.push(p); PM.set(p.id, p); save(); return { ok: 1 };
  },
  like: (u, b) => { const p = PM.get(b.id); if (!p) return { e: '' }; const i = p.likes.indexOf(u.id); if (i >= 0) p.likes.splice(i, 1); else p.likes.push(u.id); save(); return { ok: 1 } },
  save: (u, b) => { const i = u.saved.indexOf(b.id); if (i >= 0) u.saved.splice(i, 1); else u.saved.push(b.id); save(); return { ok: 1 } },
  comment: (u, b) => { const p = PM.get(b.id); if (!p) return { e: '' }; p.com.push({ id: id(), by: u.id, name: u.name, text: S(b.text, 500), at: Date.now() }); save(); return { ok: 1 } },
  story: (u, b) => { D.stories.push({ id: id(), by: u.id, text: S(b.text, 300), img: b.img || '', at: Date.now() }); save(); return { ok: 1 } },
  vote: (u, b) => { const p = PM.get(b.id); if (!p || !p.opts[b.i]) return { e: '' }; p.opts.forEach(o => { const idx = o.v.indexOf(u.id); if (idx >= 0) o.v.splice(idx, 1); }); p.opts[b.i].v.push(u.id); save(); return { ok: 1 } },
  chats: (u) => {
    const set = UK.get(u.id) || new Set(), res = [];
    for (const k of set) {
      const msgs = CM.get(k) || [], lastMsg = msgs[msgs.length - 1];
      if (!lastMsg) continue;
      const peerId = lastMsg.from === u.id ? lastMsg.to : lastMsg.from, peer = UB.get(peerId);
      if (peer) res.push({ id: peer.id, name: peer.name, last: lastMsg.text || 'Média', un: msgs.filter(m => m.to === u.id && !m.seen).length });
    }
    return res;
  },
  convo: (u, b) => { const k = pk(u.id, b.with), msgs = CM.get(k) || []; msgs.forEach(m => { if (m.to === u.id) m.seen = true; }); save(); return { m: msgs, ty: false } },
  send: (u, b) => { const m = { id: id(), from: u.id, to: b.to, text: S(b.text, 1000), audio: b.audio || '', ref: S(b.ref, 100), seen: false, at: Date.now() }; D.msgs.push(m); addMsg(m); save(); return { ok: 1 } },
  follow: (u, b) => { const i = u.following.indexOf(b.id); if (i >= 0) u.following.splice(i, 1); else u.following.push(b.id); save(); return { ok: 1 } },
  bio: (u, b) => { u.bio = S(b.bio, 200); u.filiere = S(b.filiere || u.filiere, 40); save(); return { ok: 1 } },
  pass: async (u, b) => { if (!await checkPw(S(b.old, 200), u.pass)) return { e: 'Ancien mot de passe incorrect' }; u.pass = await hashPw(S(b.pass, 200)); save(); return { ok: 1 } },
  photo: () => ({ ok: 1 }),
  poll: () => ({ un: 0, sig: 0, last: null }),
  logout: (u, b, h) => { const tk = h['x-token']; if (tk) delete D.tok[sha(tk)]; save(); return { ok: 1 } }
};

const HTML = `<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="theme-color" content="#d6ecff"><title>Meeting University of N'djamena</title>
<style>
:root{--bg:#d6ecff;--card:#ffffff;--line:#b9d9f5;--t:#10224a;--mut:#5b6f99;--g:linear-gradient(135deg,#2f6bff,#8a4dff)}
*{box-sizing:border-box;margin:0;-webkit-tap-highlight-color:transparent}
body{background:var(--bg);color:var(--t);font:16px/1.4 system-ui,sans-serif;padding-bottom:72px}
button,input,textarea,select{font:inherit;color:inherit}
input,textarea,select{width:100%;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:12px;margin:5px 0}
.btn{background:var(--g);border:0;border-radius:14px;padding:12px 18px;font-weight:700;cursor:pointer}
.ghost{background:none;border:1px solid var(--line);border-radius:12px;padding:6px 12px;cursor:pointer}
.w{max-width:560px;margin:auto;padding:12px}
.card{background:var(--card);border-radius:20px;padding:14px;margin:12px 0}
.mut{color:var(--mut);font-size:14px}.row{display:flex;gap:10px;align-items:center}.sp{flex:1}
h1,h2{font-weight:800}
.av{width:44px;height:44px;border-radius:50%;background:var(--g);display:grid;place-items:center;font-weight:800;flex:none}
nav{position:fixed;bottom:0;left:0;right:0;background:#ffffff;border-top:1px solid var(--line);display:flex;padding-bottom:env(safe-area-inset-bottom)}
nav button{flex:1;background:none;border:0;padding:12px 0;position:relative;color:var(--mut);display:flex;justify-content:center}
nav button.on{color:#a78bff}
.dot{position:absolute;top:6px;right:22%;background:#ff4d6d;font-size:12px;border-radius:10px;padding:0 6px;color:#fff}
.chips{display:flex;gap:8px;overflow-x:auto;padding:4px 0}.chips button{white-space:nowrap;background:var(--card);border:1px solid var(--line);border-radius:20px;padding:8px 14px;cursor:pointer}.chips .on{background:var(--g);border:0}
.st{display:flex;gap:12px;overflow-x:auto;padding:6px 0}.st div{text-align:center;font-size:12px;flex:none;width:68px}.st .av{width:62px;height:62px;border:3px solid #8a4dff;font-size:22px}
.ic{background:none;border:0;cursor:pointer;padding:6px 8px;color:var(--mut);display:inline-flex;align-items:center}.ic.on{color:#ff5c8a}.vk{display:inline-grid;place-items:center;width:15px;height:15px;border-radius:50%;background:#3b8bff;color:#fff;font-size:10px;vertical-align:middle}
.post img,.post video,.big{width:100%;border-radius:16px;margin:8px 0}
.b{max-width:78%;padding:9px 13px;border-radius:18px;margin:5px 0;background:var(--card)}.me{margin-left:auto;background:var(--g)}
.tag{background:var(--line);border-radius:10px;padding:2px 8px;font-size:12px}
.bar{background:var(--line);border-radius:10px;overflow:hidden;margin:5px 0;position:relative;padding:8px}.bar i{position:absolute;inset:0 auto 0 0;background:#3b4bd8;opacity:.6}.bar span{position:relative}
#toast{position:fixed;top:12px;left:50%;transform:translateX(-50%);background:var(--g);padding:10px 18px;border-radius:20px;display:none;z-index:10;color:#fff}
.btn,.chips .on,.me,.av{color:#fff}
.card{box-shadow:0 2px 12px #4f8fd622}nav{box-shadow:0 -2px 12px #4f8fd622}
</style></head><body><div id="toast"></div><div id="app"></div>
<script>
var reg=false;
const $=s=>document.querySelector(s),E=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let tok=localStorage.t||'',me,view='home',F={type:'',group:'',saved:0},cur=null,un=0;
const api=async(n,b={})=>{const r=await fetch('/api/'+n,{method:'POST',headers:{'Content-Type':'application/json','x-token':tok},body:JSON.stringify(b)});if(r.status===401){localStorage.t=tok='';me=null;render();return{}}return await r.json()};
const toast=m=>{const t=$('#toast');t.textContent=m;t.style.display='block';setTimeout(()=>t.style.display='none',2500)};
const ago=t=>{const m=(Date.now()-t)/6e4|0;return m<1?"à l'instant":m<60?m+' min':(m/1440|0)+' j'};
const av=(n,id)=> \`<div class="av">\${E(n[0]||'?').toUpperCase()}</div>\`;
const vb=v=>v?' <span class="vk">✓</span>':'';
function nav(){return \`<nav>\${['home','search','new','msg','me'].map(v=>\`<button class="\${view===v?'on':''}" onclick="go('\${v}')">\${v}</button>\`).join('')}</nav>\`}
function go(v,c){view=v;cur=c||null;render()}
async function render(){
if(!tok){$('#app').innerHTML=\`<div class="w"><h1 style="margin-top:40px;font-size:26px">Meeting University</h1><div class="card"><input id="n" placeholder="Nom complet">\${reg?'<input id="f" placeholder="Filière"><input id="s" placeholder="Réponse secrète">':''}<input id="p" type="password" placeholder="Mot de passe"><button class="btn" style="width:100%;margin-top:8px" onclick="auth()">\${reg?'Créer mon compte':'Se connecter'}</button><p class="mut" style="margin-top:12px" onclick="reg=!reg;render()"><u>\${reg?'J\'ai déjà un compte':'Créer un compte'}</u></p></div></div>\`;return}
if(!me){me=await api('me');if(!me||!me.id){me=null;return}}
let h='';if(view==='home')h=await home();else if(view==='search')h=searchV();else if(view==='new')h=newV();else if(view==='msg')h=cur?await convo():await chats();else h=await prof(cur||me.id);
$('#app').innerHTML=\`<div class="w">\${h}</div>\`+nav();
}
async function auth(){const r=await api(window.reg?'reg':'login',{name:$('#n').value,pass:$('#p').value,filiere:$('#f')?.value,secret:$('#s')?.value});if(r.e)return toast(r.e);localStorage.t=tok=r.t;me=null;render()}
async function home(){const ps=await api('feed',{type:F.type,group:F.group,saved:F.saved});return \`<h2>Accueil</h2>\${ps.map(p=>\`<div class="card"><b>\${E(p.name)}</b><p>\${E(p.text)}</p></div>\`).join('')||'<p class="mut card">Aucune publication</p>'}\`}
function searchV(){return \`<h2>Recherche</h2><input placeholder="Rechercher..." oninput="srch(this.value)"><div id="r"></div>\`}
async function srch(q){if(!q)return $('#r').innerHTML='';const u=await api('users',{q});$('#r').innerHTML=u.map(x=>\`<div class="card" onclick="go('me','\${x.id}')">\${E(x.name)}</div>\`).join('')}
function newV(){return \`<h2>Publier</h2><div class="card"><textarea id="tx" rows="4" placeholder="Écris ici..."></textarea><button class="btn" onclick="pub()">Publier</button></div>\`}
async function pub(){await api('post',{text:$('#tx').value});toast('Publié');go('home')}
async function chats(){return \`<h2>Messages</h2><p class="mut">Bientôt disponible</p>\`}
async function convo(){return \`<h2>Discussion</h2><button onclick="go('msg')">Retour</button>\`}
async function prof(i){const u=i===me.id?me:await api('user',{id:i});return \`<div class="card"><h2>\${E(u.name)}</h2><p>\${E(u.filiere)}</p><button class="ghost" onclick="api('logout').then(()=>{localStorage.t='';tok='';me=null;render()})">Déconnexion</button></div>\`}
render();
</script></body></html>`;

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
  r.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...SEC });
  r.end(HTML);
});

load().then(() => srv.listen(process.env.PORT || 3000, () => console.log('Serveur prêt')));
