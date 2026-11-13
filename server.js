const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto'),zlib=require('zlib');
const DIR=process.env.DATA_DIR||__dirname,F=path.join(DIR,'data.json');
let D={users:[],posts:[],stories:[],msgs:[],tok:{},typing:{}};
try{D=Object.assign(D,JSON.parse(fs.readFileSync(F)))}catch(e){}
let T;const save=()=>{clearTimeout(T);T=setTimeout(()=>fs.writeFile(F,JSON.stringify(D),()=>{}),400)};
const id=()=>crypto.randomBytes(6).toString('hex');
const H=p=>crypto.createHash('sha256').update('mun'+p).digest('hex');
const ADM=(process.env.ADMINS||'').split(',').map(s=>s.trim().toLowerCase());
const pub=u=>({id:u.id,name:u.name,filiere:u.filiere,bio:u.bio||'',v:ADM.includes(u.name.toLowerCase()),fol:D.users.filter(x=>(x.following||[]).includes(u.id)).length});
const nm=i=>(D.users.find(u=>u.id===i)||{}).name||'?';
const A={
reg:(b)=>{const n=(b.name||'').trim();if(n.length<3||(b.pass||'').length<4||!b.secret)return{e:'Nom (3+), mot de passe (4+) et réponse secrète requis'};
if(D.users.some(u=>u.name.toLowerCase()===n.toLowerCase()))return{e:'Ce nom existe déjà'};
const u={id:id(),name:n,filiere:(b.filiere||'Général').trim(),pass:H(b.pass),secret:H((b.secret||'').toLowerCase().trim()),following:[],saved:[],blocked:[]};D.users.push(u);const t=id();D.tok[t]=u.id;save();return{t}},
login:(b)=>{const u=D.users.find(u=>u.name.toLowerCase()===(b.name||'').trim().toLowerCase()&&u.pass===H(b.pass));if(!u)return{e:'Nom ou mot de passe incorrect'};const t=id();D.tok[t]=u.id;save();return{t}},
reset:(b)=>{const u=D.users.find(u=>u.name.toLowerCase()===(b.name||'').trim().toLowerCase());if(!u||u.secret!==H((b.secret||'').toLowerCase().trim())||(b.pass||'').length<4)return{e:'Informations incorrectes'};u.pass=H(b.pass);save();return{ok:1}}};
const P={
photo:(u,b)=>{if(!/^data:image\/(jpeg|png|webp);base64,/.test(b.img||'')||b.img.length>300000)return{e:'Image invalide ou trop lourde'};u.photo=b.img;save();return{ok:1}},
me:u=>({...pub(u),following:u.following,saved:u.saved,blocked:u.blocked}),
pass:(u,b)=>{if(u.pass!==H(b.old)||(b.pass||'').length<4)return{e:'Ancien mot de passe incorrect ou nouveau trop court'};u.pass=H(b.pass);save();return{ok:1}},
bio:(u,b)=>{u.bio=(b.bio||'').slice(0,200);u.filiere=(b.filiere||u.filiere).slice(0,40);save();return{ok:1}},
users:(u,b)=>{const q=(b.q||'').toLowerCase();return D.users.filter(x=>x.id!==u.id&&!u.blocked.includes(x.id)&&(x.name+' '+x.filiere).toLowerCase().includes(q)).slice(0,30).map(pub)},
user:(u,b)=>{const x=D.users.find(x=>x.id===b.id);return x?{...pub(x),posts:D.posts.filter(p=>p.by===x.id).length}:{e:'Introuvable'}},
follow:(u,b)=>{const i=u.following.indexOf(b.id);i<0?u.following.push(b.id):u.following.splice(i,1);save();return{ok:1}},
block:(u,b)=>{if(!u.blocked.includes(b.id))u.blocked.push(b.id);save();return{ok:1}},
report:(u,b)=>{(D.reports=D.reports||[]).push({by:u.id,...b,at:Date.now()});save();return{ok:1}},
post:(u,b)=>{if(!(b.text||'').trim()&&!b.img)return{e:'Vide'};const p={id:id(),by:u.id,type:b.type||'post',text:(b.text||'').slice(0,2000),img:b.img||'',at:Date.now(),likes:[],com:[],group:b.group||'',date:b.date||'',opts:(b.opts||[]).slice(0,6).map(t=>({t:String(t).slice(0,60),v:[]}))};D.posts.push(p);save();return{ok:1}},
feed:(u,b)=>{const q=(b.q||'').toLowerCase();return D.posts.filter(p=>!u.blocked.includes(p.by)&&(!b.type||p.type===b.type)&&(!b.group||p.group===b.group)&&(!b.saved||u.saved.includes(p.id))&&(!b.by||p.by===b.by)&&(!q||(p.text+nm(p.by)).toLowerCase().includes(q))).sort((a,c)=>c.at-a.at).slice(0,40).map(p=>({...p,name:nm(p.by),com:p.com.map(c=>({...c,name:nm(c.by)}))}))},
like:(u,b)=>{const p=D.posts.find(p=>p.id===b.id);if(p){const i=p.likes.indexOf(u.id);i<0?p.likes.push(u.id):p.likes.splice(i,1);save()}return{ok:1}},
comment:(u,b)=>{const p=D.posts.find(p=>p.id===b.id);if(p&&(b.text||'').trim()){p.com.push({by:u.id,text:b.text.slice(0,500),at:Date.now()});save()}return{ok:1}},
save:(u,b)=>{const i=u.saved.indexOf(b.id);i<0?u.saved.push(b.id):u.saved.splice(i,1);save();return{ok:1}},
vote:(u,b)=>{const p=D.posts.find(p=>p.id===b.id);if(p&&p.opts[b.i]&&!p.opts.some(o=>o.v.includes(u.id))){p.opts[b.i].v.push(u.id);save()}return{ok:1}},
story:(u,b)=>{if(!(b.text||'').trim()&&!b.img)return{e:'Vide'};D.stories.push({id:id(),by:u.id,text:(b.text||'').slice(0,200),img:b.img||'',at:Date.now()});save();return{ok:1}},
stories:(u)=>{const c=Date.now()-864e5;D.stories=D.stories.filter(s=>s.at>c);return D.stories.filter(s=>!u.blocked.includes(s.by)).sort((a,b)=>b.at-a.at).map(s=>({...s,name:nm(s.by)}))},
send:(u,b)=>{if(!(b.text||'').trim()&&!b.audio)return{e:'Vide'};D.msgs.push({id:id(),from:u.id,to:b.to,text:(b.text||'').slice(0,2000),audio:b.audio||'',ref:(b.ref||'').slice(0,80),at:Date.now(),seen:0});save();return{ok:1}},
convo:(u,b)=>{D.msgs.forEach(m=>{if(m.from===b.with&&m.to===u.id&&!m.seen)m.seen=1});save();const ty=D.typing[b.with+'>'+u.id]>Date.now()-4e3;return{ty,m:D.msgs.filter(m=>(m.from===u.id&&m.to===b.with)||(m.from===b.with&&m.to===u.id)).slice(-150)}},
chats:(u)=>{const o={};D.msgs.filter(m=>m.from===u.id||m.to===u.id).forEach(m=>{const w=m.from===u.id?m.to:m.from;if(u.blocked.includes(w))return;const c=o[w]||(o[w]={id:w,name:nm(w),last:'',at:0,un:0});if(m.at>=c.at){c.at=m.at;c.last=m.audio?'🎤 Message vocal':m.text}if(m.to===u.id&&!m.seen)c.un++});return Object.values(o).sort((a,b)=>b.at-a.at)},
typing:(u,b)=>{D.typing[u.id+'>'+b.to]=Date.now();return{ok:1}},
poll:(u)=>({sig:[D.posts.length,D.stories.length,D.msgs.length,D.msgs.filter(m=>m.from===u.id&&m.seen).length,D.posts.reduce((a,p)=>a+p.likes.length+p.com.length,0),Object.keys(D.typing).filter(k=>k.endsWith('>'+u.id)&&D.typing[k]>Date.now()-4e3).length].join('.'),un:D.msgs.filter(m=>m.to===u.id&&!m.seen&&!u.blocked.includes(m.from)).length,st:D.stories.filter(s=>s.at>Date.now()-864e5).length,last:D.msgs.filter(m=>m.to===u.id&&!m.seen).slice(-1).map(m=>({name:nm(m.from),text:m.audio?'🎤 Message vocal':m.text}))[0]||null})};
const Z=(q,r,type,body)=>{const h={'Content-Type':type,'Cache-Control':'no-cache'};if(/gzip/.test(q.headers['accept-encoding']||'')){h['Content-Encoding']='gzip';r.writeHead(200,h);r.end(zlib.gzipSync(body,{level:1}))}else{r.writeHead(200,h);r.end(body)}};
http.createServer((q,r)=>{
if(q.method==='POST'&&q.url.startsWith('/api/')){let s='';q.on('data',d=>{s+=d;if(s.length>6e6)q.destroy()});q.on('end',()=>{let o;try{const b=JSON.parse(s||'{}'),n=q.url.slice(5);
if(A[n])o=A[n](b);else{const u=D.users.find(x=>x.id===D.tok[q.headers['x-token']]);if(!u){r.writeHead(401);return r.end('{}')}o=P[n]?P[n](u,b):{e:'?'}}}catch(e){o={e:'Erreur'}}
Z(q,r,'application/json',JSON.stringify(o))});return}
if(q.method==='GET'&&q.url.startsWith('/photo/')){const x=D.users.find(x=>x.id===q.url.slice(7).split('?')[0]),m=x&&x.photo&&x.photo.match(/^data:(image\/\w+);base64,(.*)$/);if(!m){r.writeHead(404);return r.end()}r.writeHead(200,{'Content-Type':m[1],'Cache-Control':'public,max-age=60'});return r.end(Buffer.from(m[2],'base64'))}
fs.readFile(path.join(__dirname,'public','index.html'),(e,d)=>Z(q,r,'text/html; charset=utf-8',d||'Erreur'))
}).listen(process.env.PORT||3000);
