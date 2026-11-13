const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto'),zlib=require('zlib'),{promisify}=require('util');
const scrypt=promisify(crypto.scrypt);
let Pool=null;try{Pool=require('pg').Pool}catch(e){}
const pool=process.env.DATABASE_URL&&Pool?new Pool({connectionString:process.env.DATABASE_URL,ssl:{rejectUnauthorized:false},max:4}):null;
const DIR=process.env.DATA_DIR||__dirname,F=path.join(DIR,'data.json'),MDIR=path.join(DIR,'media');
const COLS=['users','posts','stories','msgs','reports','tok'];
let D={users:[],posts:[],stories:[],msgs:[],reports:[],tok:{}};
const TY={},RL={},last={};
let VER=0,dirty=false,timer=null,busy=false;

/* ---------- Utilitaires ---------- */
const id=()=>crypto.randomBytes(8).toString('hex');
const S=(v,n)=>String(v==null?'':v).slice(0,n);
const sha=s=>crypto.createHash('sha256').update(String(s)).digest('hex');
const has=(o,k)=>Object.prototype.hasOwnProperty.call(o,k);
const ok={ok:1},TOO={e:'Trop de tentatives. Réessaie dans quelques minutes.',_c:429};
const NAME=/^[\p{L}\p{N}][\p{L}\p{N} ._'-]{1,28}[\p{L}\p{N}]$/u;
const IMG=/^data:(image\/(?:jpeg|png|webp|gif));base64,([A-Za-z0-9+\/]+={0,2})$/;
const AUD=/^data:(audio\/[\w.+-]+)(?:;[\w=.+-]+)*;base64,([A-Za-z0-9+\/]+={0,2})$/;
const ADM=(process.env.ADMINS||'').split(',').map(s=>s.trim().toLowerCase()).filter(Boolean);
const SEC={'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Strict-Transport-Security':'max-age=31536000','Permissions-Policy':'camera=(self), microphone=(self), geolocation=()'};

/* Limiteur de requêtes (anti force brute / spam) */
const limit=(k,max,ms)=>{const n=Date.now();const r=RL[k]&&RL[k].t>n?RL[k]:(RL[k]={t:n+ms,c:0});return ++r.c>max};
setInterval(()=>{const n=Date.now();for(const k in RL)if(RL[k].t<n)delete RL[k];for(const k in TY)if(TY[k]<n-1e4)delete TY[k]},6e4).unref();

/* ---------- Mots de passe (scrypt + sel unique) ---------- */
const hashPw=async p=>{const s=crypto.randomBytes(16);const h=await scrypt(p,s,32);return 's1$'+s.toString('hex')+'$'+h.toString('hex')};
const checkPw=async(p,st)=>{try{const[,s,h]=String(st).split('$');const x=await scrypt(p,Buffer.from(s,'hex'),32);return crypto.timingSafeEqual(x,Buffer.from(h,'hex'))}catch(e){return false}};
const DUMMY=hashPw('dummy-password');

/* ---------- Index en mémoire (rapidité) ---------- */
const UB=new Map(),UN=new Map(),PM=new Map(),CM=new Map(),UK=new Map();
const pk=(a,b)=>a<b?a+'|'+b:b+'|'+a;
function addMsg(m){const k=pk(m.from,m.to);if(!CM.has(k))CM.set(k,[]);CM.get(k).push(m);for(const x of[m.from,m.to]){if(!UK.has(x))UK.set(x,new Set());UK.get(x).add(k)}}
function reindex(){UB.clear();UN.clear();PM.clear();CM.clear();UK.clear();
D.users.forEach(u=>{UB.set(u.id,u);UN.set(u.name.toLowerCase(),u)});D.posts.forEach(p=>PM.set(p.id,p));D.msgs.forEach(addMsg)}

/* ---------- Sauvegarde (PostgreSQL ou fichier) ---------- */
async function load(){
if(pool){
await pool.query('CREATE TABLE IF NOT EXISTS kv(k text PRIMARY KEY, v text NOT NULL)');
await pool.query('CREATE TABLE IF NOT EXISTS media(id text PRIMARY KEY, mime text NOT NULL, data bytea NOT NULL)');
const r=await pool.query('SELECT k,v FROM kv');
for(const row of r.rows)if(COLS.includes(row.k)){D[row.k]=JSON.parse(row.v);last[row.k]=row.v}
console.log('Base de données connectée');
}else{
console.log('ATTENTION : DATABASE_URL absente, sauvegarde dans un fichier (données perdues sur Render gratuit)');
try{const j=JSON.parse(fs.readFileSync(F));for(const k of COLS)if(j[k])D[k]=j[k]}catch(e){}
}
reindex()}
const save=()=>{dirty=true;VER++;if(!timer)timer=setTimeout(flush,2500)};
async function flush(){timer=null;if(!dirty||busy)return;dirty=false;busy=true;
try{const now=Date.now();for(const t in D.tok)if(D.tok[t].exp<now)delete D.tok[t];
if(D.reports.length>2000)D.reports=D.reports.slice(-1000);
const ch=[];for(const k of COLS){const s=JSON.stringify(D[k]);if(s!==last[k])ch.push([k,s])}
if(pool){for(const[k,s]of ch){await pool.query('INSERT INTO kv(k,v) VALUES($1,$2) ON CONFLICT (k) DO UPDATE SET v=$2',[k,s]);last[k]=s}}
else if(ch.length){const o={};for(const k of COLS)o[k]=D[k];await fs.promises.writeFile(F,JSON.stringify(o));for(const[k,s]of ch)last[k]=s}
}catch(e){dirty=true;console.error('Erreur sauvegarde:',e.message)}
busy=false;if(dirty&&!timer)timer=setTimeout(flush,2500)}
process.on('SIGTERM',async()=>{try{while(busy)await new Promise(r=>setTimeout(r,50));dirty=true;await flush()}catch(e){}process.exit(0)});

/* ---------- Médias (images / audio stockés à part, servis avec cache) ---------- */
async function putMedia(du,kind,max){
if(typeof du!=='string'||du.length>max)return null;
const m=(kind==='audio'?AUD:IMG).exec(du);if(!m)return null;
const buf=Buffer.from(m[2],'base64'),mid=crypto.randomBytes(12).toString('hex'),mime=m[1].toLowerCase();
if(pool)await pool.query('INSERT INTO media(id,mime,data) VALUES($1,$2,$3)',[mid,mime,buf]);
else{fs.mkdirSync(MDIR,{recursive:true});fs.writeFileSync(path.join(MDIR,mid),buf);fs.writeFileSync(path.join(MDIR,mid+'.mime'),mime)}
return mid}
async function getMedia(mid){
if(pool){const r=await pool.query('SELECT mime,data FROM media WHERE id=$1',[mid]);return r.rows[0]||null}
try{return{mime:fs.readFileSync(path.join(MDIR,mid+'.mime'),'utf8'),data:fs.readFileSync(path.join(MDIR,mid))}}catch(e){return null}}
function delMedia(x){x=String(x||'');if(x.startsWith('/m/'))x=x.slice(3);if(!/^[a-f0-9]{24}$/.test(x))return;
if(pool)pool.query('DELETE FROM media WHERE id=$1',[x]).catch(()=>{});
else{fs.unlink(path.join(MDIR,x),()=>{});fs.unlink(path.join(MDIR,x+'.mime'),()=>{})}}

/* ---------- Sessions (jetons stockés hachés, expiration 60 jours) ---------- */
function newTok(uid){const t=crypto.randomBytes(24).toString('hex');D.tok[sha(t)]={u:uid,exp:Date.now()+60*864e5};
const mine=Object.entries(D.tok).filter(([,r])=>r.u===uid).sort((a,b)=>a[1].exp-b[1].exp);
while(mine.length>8)delete D.tok[mine.shift()[0]];save();return t}
function revoke(uid,keep){for(const h in D.tok)if(D.tok[h].u===uid&&h!==keep)delete D.tok[h]}
function auth(tk){if(typeof tk!=='string'||tk.length>80)return null;const r=D.tok[sha(tk)];return r&&r.exp>Date.now()?UB.get(r.u)||null:null}

/* ---------- Données publiques ---------- */
const pub=u=>({id:u.id,name:u.name,filiere:u.filiere,bio:u.bio||'',v:ADM.includes(u.name.toLowerCase()),fol:D.users.reduce((a,x)=>a+((x.following||[]).includes(u.id)?1:0),0)});
const nm=i=>(UB.get(i)||{}).name||'?';
function inbox(u){let un=0,lastm=null;
for(const k of(UK.get(u.id)||[])){const a=CM.get(k)||[];for(let i=a.length-1;i>=0;i--){const m=a[i];if(m.to===u.id&&!m.seen&&!u.blocked.includes(m.from)){un++;if(!lastm||m.at>=lastm.at)lastm=m}}}
return{un,last:lastm?{name:nm(lastm.from),text:lastm.audio?'🎤 Message vocal':lastm.text}:null}}
const PC={};

/* ---------- Routes publiques ---------- */
const A={
reg:async(b,ip)=>{
if(limit('reg:'+ip,8,36e5))return TOO;
const n=S(b.name,40).trim(),p=S(b.pass,200),sec=S(b.secret,100).toLowerCase().trim();
if(!NAME.test(n))return{e:"Nom invalide (3 à 30 caractères : lettres, chiffres, espaces, . _ - ')"};
if(p.length<6||!sec)return{e:'Mot de passe (6+ caractères) et réponse secrète requis'};
if(UN.has(n.toLowerCase()))return{e:'Ce nom existe déjà'};
const u={id:id(),name:n,filiere:S(b.filiere||'Général',40).trim()||'Général',pass:await hashPw(p),secret:await hashPw(sec),following:[],saved:[],blocked:[],at:Date.now()};
if(UN.has(n.toLowerCase()))return{e:'Ce nom existe déjà'};
D.users.push(u);UB.set(u.id,u);UN.set(n.toLowerCase(),u);return{t:newTok(u.id)}},
login:async(b,ip)=>{
const n=S(b.name,40).trim().toLowerCase();
if(limit('li:'+ip,30,9e5)||limit('ln:'+n,10,9e5))return TOO;
const u=UN.get(n);
const good=await checkPw(S(b.pass,200),u?u.pass:await DUMMY);
if(!u||!good)return{e:'Nom ou mot de passe incorrect'};
return{t:newTok(u.id)}},
reset:async(b,ip)=>{
const n=S(b.name,40).trim().toLowerCase(),p=S(b.pass,200);
if(limit('rs:'+ip,10,36e5)||limit('rn:'+n,5,36e5))return TOO;
const u=UN.get(n);
const good=await checkPw(S(b.secret,100).toLowerCase().trim(),u?u.secret:await DUMMY);
if(!u||!good||p.length<6)return{e:'Informations incorrectes'};
u.pass=await hashPw(p);revoke(u.id);save();return ok}};

/* ---------- Routes connectées ---------- */
const WR=new Set(['post','story','send','comment','report','photo']);
const P={
photo:async(u,b)=>{const m=await putMedia(b.img,'image',4e5);if(!m)return{e:'Image invalide ou trop lourde'};const old=u.photo;u.photo=m;if(old)delMedia(old);save();return ok},
me:u=>({...pub(u),following:u.following,saved:u.saved,blocked:u.blocked}),
logout:(u,b,tk)=>{delete D.tok[sha(tk)];save();return ok},
pass:async(u,b,tk)=>{const np=S(b.pass,200);if(!(await checkPw(S(b.old,200),u.pass))||np.length<6)return{e:'Ancien mot de passe incorrect ou nouveau trop court (6 minimum)'};u.pass=await hashPw(np);revoke(u.id,sha(tk));save();return ok},
bio:(u,b)=>{u.bio=S(b.bio,200);u.filiere=S(b.filiere||u.filiere,40);save();return ok},
users:(u,b)=>{const q=S(b.q,50).toLowerCase();return D.users.filter(x=>x.id!==u.id&&!u.blocked.includes(x.id)&&!(x.blocked||[]).includes(u.id)&&(x.name+' '+x.filiere).toLowerCase().includes(q)).slice(0,30).map(pub)},
user:(u,b)=>{const x=UB.get(S(b.id,40));return x?{...pub(x),posts:D.posts.reduce((a,p)=>a+(p.by===x.id?1:0),0)}:{e:'Introuvable'}},
follow:(u,b)=>{const t=S(b.id,40);if(!UB.has(t)||t===u.id)return ok;const i=u.following.indexOf(t);i<0?u.following.push(t):u.following.splice(i,1);save();return ok},
block:(u,b)=>{const t=S(b.id,40);if(UB.has(t)&&t!==u.id&&!u.blocked.includes(t)){u.blocked.push(t);const i=u.following.indexOf(t);if(i>=0)u.following.splice(i,1);save()}return ok},
report:(u,b)=>{D.reports.push({by:u.id,at:Date.now(),id:S(b.target||b.id,40),type:S(b.type,40),why:S(b.why||b.reason||b.text,300)});save();return ok},
post:async(u,b)=>{
const text=S(b.text,2000);if(!text.trim()&&!b.img)return{e:'Vide'};
let img='';if(b.img){const m=await putMedia(b.img,'image',2e6);if(!m)return{e:'Image invalide ou trop lourde'};img='/m/'+m}
const type=/^[\w-]{1,20}$/.test(b.type||'')?b.type:'post';
const p={id:id(),by:u.id,type,text,img,at:Date.now(),likes:[],com:[],group:S(b.group,40),date:S(b.date,40),opts:(Array.isArray(b.opts)?b.opts:[]).map(t=>S(t,60)).filter(t=>t.trim()).slice(0,6).map(t=>({t,v:[]}))};
D.posts.push(p);PM.set(p.id,p);save();return ok},
feed:(u,b)=>{const q=S(b.q,60).toLowerCase(),out=[];
for(let i=D.posts.length-1;i>=0&&out.length<40;i--){const p=D.posts[i];
if(u.blocked.includes(p.by)||(b.type&&p.type!==b.type)||(b.group&&p.group!==b.group)||(b.saved&&!u.saved.includes(p.id))||(b.by&&p.by!==b.by))continue;
if(q&&!(p.text+nm(p.by)).toLowerCase().includes(q))continue;
out.push({...p,name:nm(p.by),com:p.com.map(c=>({...c,name:nm(c.by)}))})}
return out},
like:(u,b)=>{const p=PM.get(S(b.id,40));if(p){const i=p.likes.indexOf(u.id);i<0?p.likes.push(u.id):p.likes.splice(i,1);save()}return ok},
comment:(u,b)=>{const p=PM.get(S(b.id,40)),t=S(b.text,500);if(p&&t.trim()&&p.com.length<500){p.com.push({by:u.id,text:t,at:Date.now()});save()}return ok},
save:(u,b)=>{const t=S(b.id,40);if(!PM.has(t))return ok;const i=u.saved.indexOf(t);i<0?u.saved.push(t):u.saved.splice(i,1);save();return ok},
vote:(u,b)=>{const p=PM.get(S(b.id,40));if(p&&Number.isInteger(b.i)&&p.opts[b.i]&&!p.opts.some(o=>o.v.includes(u.id))){p.opts[b.i].v.push(u.id);save()}return ok},
story:async(u,b)=>{
const text=S(b.text,200);if(!text.trim()&&!b.img)return{e:'Vide'};
let img='';if(b.img){const m=await putMedia(b.img,'image',2e6);if(!m)return{e:'Image invalide ou trop lourde'};img='/m/'+m}
D.stories.push({id:id(),by:u.id,text,img,at:Date.now()});save();return ok},
stories:u=>{const c=Date.now()-864e5;const old=D.stories.filter(s=>s.at<=c);
if(old.length){old.forEach(s=>s.img&&delMedia(s.img));D.stories=D.stories.filter(s=>s.at>c);save()}
return D.stories.filter(s=>!u.blocked.includes(s.by)).sort((a,b)=>b.at-a.at).map(s=>({...s,name:nm(s.by)}))},
send:async(u,b)=>{
const to=S(b.to,40),w=UB.get(to);if(!w||w===u)return{e:'Destinataire introuvable'};
if(w.blocked.includes(u.id)||u.blocked.includes(to))return{e:'Message impossible'};
const text=S(b.text,2000);let audio='';
if(b.audio){const m=await putMedia(b.audio,'audio',3e6);if(!m)return{e:'Message vocal invalide ou trop long'};audio='/m/'+m}
if(!text.trim()&&!audio)return{e:'Vide'};
const m={id:id(),from:u.id,to,text,audio,ref:S(b.ref,80),at:Date.now(),seen:0};D.msgs.push(m);addMsg(m);save();return ok},
convo:(u,b)=>{const w=S(b.with,40),a=CM.get(pk(u.id,w))||[];let ch=false;
a.forEach(m=>{if(m.from===w&&m.to===u.id&&!m.seen){m.seen=1;ch=true}});if(ch)save();
return{ty:TY[w+'>'+u.id]>Date.now()-4e3,m:a.slice(-150)}},
chats:u=>{const o=[];
for(const k of(UK.get(u.id)||[])){const a=CM.get(k)||[];if(!a.length)continue;const l=a[a.length-1],w=l.from===u.id?l.to:l.from;if(u.blocked.includes(w))continue;
o.push({id:w,name:nm(w),last:l.audio?'🎤 Message vocal':l.text,at:l.at,un:a.reduce((n,m)=>n+(m.to===u.id&&!m.seen?1:0),0)})}
return o.sort((a,b)=>b.at-a.at)},
typing:(u,b)=>{TY[u.id+'>'+S(b.to,40)]=Date.now();return ok},
poll:u=>{let c=PC[u.id];if(!c||c.ver!==VER)c=PC[u.id]={ver:VER,...inbox(u)};
const now=Date.now(),ty=Object.keys(TY).filter(k=>k.endsWith('>'+u.id)&&TY[k]>now-4e3).length;
return{sig:VER+'.'+ty,un:c.un,st:D.stories.filter(s=>s.at>now-864e5).length,last:c.last}}};

/* ---------- Réponses HTTP ---------- */
const Z=(q,r,type,body,code=200,extra={})=>{
const h={'Content-Type':type,'Cache-Control':'no-cache','Vary':'Accept-Encoding',...SEC,...extra};
body=Buffer.isBuffer(body)?body:Buffer.from(body);
if(body.length>600&&/gzip/.test(q.headers['accept-encoding']||'')){zlib.gzip(body,{level:1},(e,z)=>{if(e){r.writeHead(code,h);return r.end(body)}h['Content-Encoding']='gzip';r.writeHead(code,h);r.end(z)})}
else{r.writeHead(code,h);r.end(body)}};
let INDEX;try{INDEX=fs.readFileSync(path.join(__dirname,'public','index.html'))}catch(e){INDEX=Buffer.from('Erreur')}
const INDEXGZ=zlib.gzipSync(INDEX,{level:9}),ETAG='W/"'+sha(INDEX).slice(0,16)+'"';

const srv=http.createServer((q,r)=>{
const ip=String(q.headers['cf-connecting-ip']||(q.headers['x-forwarded-for']||'').split(',')[0]||q.socket.remoteAddress||'').trim();
if(q.url==='/health'){r.writeHead(200,{'Content-Type':'text/plain','Cache-Control':'no-store'});return r.end('ok')}
if(q.method==='POST'&&q.url.startsWith('/api/')){
if(limit('ip:'+ip,600,6e4))return Z(q,r,'application/json','{"e":"Trop de requêtes"}',429);
let s='',big=false;
q.on('data',d=>{if(big)return;s+=d;if(s.length>4e6){big=true;r.writeHead(413,SEC);r.end();q.destroy()}});
q.on('end',async()=>{if(big)return;let o;
try{const b=JSON.parse(s||'{}');if(!b||typeof b!=='object'||Array.isArray(b))throw 0;const n=q.url.slice(5).split('?')[0];
if(has(A,n))o=await A[n](b,ip);
else{const tk=q.headers['x-token'],u=auth(tk);if(!u)return Z(q,r,'application/json','{}',401);
if(!has(P,n))o={e:'?'};else if(WR.has(n)&&limit('w:'+u.id,40,6e4))o=TOO;else o=await P[n](u,b,tk)}
}catch(e){o={e:'Erreur'}}
let c=200;if(o&&o._c){c=o._c;delete o._c}
Z(q,r,'application/json',JSON.stringify(o===undefined?{}:o),c)});return}
if(q.url.startsWith('/m/')){
const mid=q.url.slice(3).split('?')[0];if(!/^[a-f0-9]{24}$/.test(mid)){r.writeHead(404);return r.end()}
getMedia(mid).then(m=>{if(!m){r.writeHead(404);return r.end()}
const L=m.data.length,h={'Content-Type':m.mime,'Accept-Ranges':'bytes','Cache-Control':'public,max-age=31536000,immutable',...SEC};
const g=/^bytes=(\d*)-(\d*)$/.exec(q.headers.range||'');
if(g&&(g[1]||g[2])){let a=g[1]?+g[1]:L-+g[2],e=g[1]&&g[2]?Math.min(+g[2],L-1):L-1;if(a<0)a=0;
if(a>e||a>=L){r.writeHead(416,{'Content-Range':'bytes */'+L});return r.end()}
r.writeHead(206,{...h,'Content-Range':'bytes '+a+'-'+e+'/'+L,'Content-Length':e-a+1});return r.end(m.data.subarray(a,e+1))}
r.writeHead(200,{...h,'Content-Length':L});r.end(m.data)}).catch(()=>{r.writeHead(500);r.end()});return}
if(q.url.startsWith('/photo/')){
const x=UB.get(q.url.slice(7).split('?')[0]);
if(!x||!x.photo){r.writeHead(404);return r.end()}
getMedia(x.photo).then(m=>{if(!m){r.writeHead(404);return r.end()}r.writeHead(200,{'Content-Type':m.mime,'Content-Length':m.data.length,'Cache-Control':'public,max-age=300',...SEC});r.end(m.data)}).catch(()=>{r.writeHead(500);r.end()});return}
if(q.headers['if-none-match']===ETAG){r.writeHead(304,{ETag:ETAG,...SEC});return r.end()}
const gz=/gzip/.test(q.headers['accept-encoding']||'');
r.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-cache',ETag:ETAG,'Vary':'Accept-Encoding',...(gz?{'Content-Encoding':'gzip'}:{}),...SEC});
r.end(gz?INDEXGZ:INDEX)});
srv.keepAliveTimeout=65e3;srv.headersTimeout=66e3;

load().then(()=>srv.listen(process.env.PORT||3000,()=>console.log('Serveur prêt'))).catch(e=>{console.error('Impossible de démarrer :',e.message);process.exit(1)});
