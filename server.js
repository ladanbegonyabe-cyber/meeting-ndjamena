const express = require('express');
const path = require('path');
const fs = require('fs');
const app = express();

app.use(express.json({limit:'10mb'}));
app.use(express.urlencoded({extended:true, limit:'10mb'}));
app.use(express.static(path.join(__dirname,'public')));

// ===== BASE DE DONNÉES SIMPLE (fichier + mémoire) =====
let DB_FILE = path.join(__dirname,'db.json');
let USERS = []; // {id, name, pass, secret, filiere, bio}
let POSTS = []; // {id, by, name, text, type, group, price, wa, anon, img, likes:[], com:[], reports:[]}
let MSGS = [];  // {from, fromName, to, text, time}
let CALLS = {}; // {to: {type, kind, from, fromName, time}}
let TOKENS = {}; // token -> userId

function load(){
  try{
    if(fs.existsSync(DB_FILE)){
      let d = JSON.parse(fs.readFileSync(DB_FILE,'utf8'));
      USERS = d.USERS||[]; POSTS = d.POSTS||[]; MSGS = d.MSGS||[];
    }
  }catch(e){ console.log('load err', e.message); }
}
function save(){
  try{ fs.writeFileSync(DB_FILE, JSON.stringify({USERS,POSTS,MSGS})); }catch(e){}
}
load();
setInterval(save, 10000);

function authed(req){
  let t = req.headers['x-token'] || req.body.token || '';
  if(!t || !TOKENS[t]) return null;
  let id = TOKENS[t];
  return USERS.find(u=>u.id===id) || null;
}
function makeId(){ return Date.now().toString(36) + Math.random().toString(36).slice(2,7); }
function cleanUser(u){ return {id:u.id, name:u.name, filiere:u.filiere||'Général', bio:u.bio||''}; }

// ===== AUTH =====
app.post('/api/reg', (req,res)=>{
  let name = String(req.body.name||'').trim();
  let pass = String(req.body.pass||'');
  let secret = String(req.body.secret||'').trim();
  let filiere = String(req.body.filiere||'Général');
  if(!name || !pass || !secret) return res.json({e:'Remplis nom + mot de passe + réponse secrète'});
  if(pass.length < 4) return res.json({e:'Mot de passe trop court (min 4 caractères)'});
  if(USERS.find(u=>u.name.toLowerCase()===name.toLowerCase())) return res.json({e:'Ce nom existe déjà, choisis un autre ou connecte-toi'});
  let id = makeId();
  let u = {id, name, pass, secret: secret.toLowerCase(), filiere, bio:''};
  USERS.push(u);
  let t = makeId()+makeId();
  TOKENS[t]=id;
  save();
  res.json({t, user: cleanUser(u)});
});

app.post('/api/login', (req,res)=>{
  let name = String(req.body.name||'').trim();
  let pass = String(req.body.pass||'');
  let u = USERS.find(x=>x.name.toLowerCase()===name.toLowerCase());
  if(!u) return res.json({e:'Nom introuvable. Crée un compte.'});
  if(u.pass !== pass) return res.json({e:'Mot de passe incorrect'});
  let t = makeId()+makeId();
  TOKENS[t]=u.id;
  res.json({t, user: cleanUser(u)});
});

app.post('/api/reset', (req,res)=>{
  let name = String(req.body.name||'').trim();
  let secret = String(req.body.secret||'').trim().toLowerCase();
  let pass = String(req.body.pass||'');
  let u = USERS.find(x=>x.name.toLowerCase()===name.toLowerCase());
  if(!u) return res.json({e:'Nom introuvable'});
  if(u.secret !== secret) return res.json({e:'Réponse secrète incorrecte'});
  if(!pass) return res.json({e:'Mets un nouveau mot de passe'});
  u.pass = pass;
  save();
  res.json({ok:1});
});

app.post('/api/me', (req,res)=>{
  let u = authed(req);
  if(!u) return res.status(401).json({e:'non connecté'});
  res.json(cleanUser(u));
});

// ===== FEED / POSTS =====
app.post('/api/feed', (req,res)=>{
  let u = authed(req);
  if(!u) return res.status(401).json({e:'non connecté'});
  let by = req.body.by;
  let list = [...POSTS].reverse();
  if(by) list = list.filter(p=>p.by===by);
  res.json(list.map(p=>({
    id:p.id, by:p.by, name:p.name, text:p.text, type:p.type, group:p.group,
    price:p.price||'', wa:p.wa||'', anon:!!p.anon, img:p.img||'',
    likes:p.likes||[], com:p.com||[]
  })));
});

app.post('/api/post', (req,res)=>{
  let u = authed(req);
  if(!u) return res.status(401).json({e:'non connecté'});
  let text = String(req.body.text||'').trim().slice(0,3000);
  if(!text) return res.json({e:'Écris quelque chose'});
  let p = {
    id: makeId(), by:u.id, name:u.name, text,
    type: String(req.body.type||'post'),
    group: String(req.body.group||u.filiere||'Général'),
    price: String(req.body.price||''),
    wa: String(req.body.wa||''),
    anon: !!req.body.anon,
    img: String(req.body.img||''),
    likes:[], com:[], reports:[]
  };
  POSTS.push(p);
  if(POSTS.length>2000) POSTS = POSTS.slice(-2000);
  save();
  res.json({ok:1, id:p.id});
});

app.post('/api/like', (req,res)=>{
  let u = authed(req);
  if(!u) return res.status(401).json({e:'non connecté'});
  let p = POSTS.find(x=>x.id===String(req.body.id));
  if(!p) return res.json({e:'Post introuvable'});
  p.likes = p.likes||[];
  let i = p.likes.indexOf(u.id);
  if(i>=0) p.likes.splice(i,1); else p.likes.push(u.id);
  save();
  res.json({ok:1, likes:p.likes.length});
});

app.post('/api/comment', (req,res)=>{
  let u = authed(req);
  if(!u) return res.status(401).json({e:'non connecté'});
  let p = POSTS.find(x=>x.id===String(req.body.id));
  if(!p) return res.json({e:'Post introuvable'});
  let text = String(req.body.text||'').trim().slice(0,500);
  if(!text) return res.json({e:'Écris ton commentaire'});
  p.com = p.com||[];
  p.com.push({name:u.name, text, time:Date.now()});
  save();
  res.json({ok:1});
});

app.post('/api/delpost', (req,res)=>{
  let u = authed(req);
  if(!u) return res.status(401).json({e:'non connecté'});
  let idx = POSTS.findIndex(x=>x.id===String(req.body.id) && x.by===u.id);
  if(idx<0) return res.json({e:'Tu ne peux pas supprimer ce post'});
  POSTS.splice(idx,1);
  save();
  res.json({ok:1});
});

app.post('/api/report', (req,res)=>{
  let u = authed(req);
  if(!u) return res.status(401).json({e:'non connecté'});
  let p = POSTS.find(x=>x.id===String(req.body.target));
  if(!p) return res.json({e:'Post introuvable'});
  p.reports = p.reports||[];
  if(!p.reports.includes(u.id)) p.reports.push(u.id);
  let count = p.reports.length;
  if(count>=3){
    POSTS = POSTS.filter(x=>x.id!==p.id);
  }
  save();
  res.json({ok:1, count});
});

// ===== PROFIL / USERS / CLASSEMENT =====
app.post('/api/bio', (req,res)=>{
  let u = authed(req);
  if(!u) return res.status(401).json({e:'non connecté'});
  if(req.body.bio!==undefined) u.bio = String(req.body.bio).slice(0,300);
  if(req.body.filiere) u.filiere = String(req.body.filiere);
  save();
  res.json({ok:1, user:cleanUser(u)});
});

app.post('/api/users', (req,res)=>{
  let u = authed(req);
  if(!u) return res.status(401).json({e:'non connecté'});
  let q = String(req.body.q||'').toLowerCase().trim();
  let list = USERS.map(cleanUser);
  if(q) list = list.filter(x=>x.name.toLowerCase().includes(q));
  res.json(list.slice(0,50));
});

app.post('/api/leaderboard', (req,res)=>{
  let u = authed(req);
  if(!u) return res.status(401).json({e:'non connecté'});
  // Points : 3 pts par post + 1 pt par like reçu + 1 pt par commentaire reçu
  let scores = USERS.map(user=>{
    let myPosts = POSTS.filter(p=>p.by===user.id);
    let likesRecus = myPosts.reduce((s,p)=>s+(p.likes||[]).length,0);
    let comRecus = myPosts.reduce((s,p)=>s+(p.com||[]).length,0);
    let pts = myPosts.length*3 + likesRecus + comRecus;
    return {id:user.id, name:user.name, filiere:user.filiere||'Général', pts};
  });
  scores.sort((a,b)=>b.pts-a.pts);
  res.json(scores.slice(0,20));
});

// ===== MESSAGERIE + APPELS VOCAL / VIDÉO =====
app.post('/api/msgs', (req,res)=>{
  let u = authed(req);
  if(!u) return res.status(401).json({e:'non connecté'});
  let other = String(req.body.with||'');
  res.json(MSGS.filter(m=> (m.from===u.id && m.to===other) || (m.from===other && m.to===u.id)).slice(-100));
});

app.post('/api/sendmsg', (req,res)=>{
  let u = authed(req);
  if(!u) return res.status(401).json({e:'non connecté'});
  let to = String(req.body.to||'');
  let text = String(req.body.text||'').slice(0,1000).trim();
  if(!to || !text) return res.json({e:'Message vide'});
  MSGS.push({from:u.id, fromName:u.name, to, text, time:new Date().toLocaleTimeString('fr-FR',{hour:'2-digit',minute:'2-digit'})});
  if(MSGS.length>2000) MSGS = MSGS.slice(-2000);
  save();
  res.json({ok:1});
});

app.post('/api/call_signal', (req,res)=>{
  let u = authed(req);
  if(!u) return res.status(401).json({e:'non connecté'});
  let to = String(req.body.to||'');
  CALLS[to] = {type:req.body.type, kind:req.body.kind||'audio', from:u.id, fromName:u.name, time:Date.now()};
  res.json({ok:1});
});

app.post('/api/call_poll', (req,res)=>{
  let u = authed(req);
  if(!u) return res.status(401).json({e:'non connecté'});
  let c = CALLS[u.id];
  if(c && Date.now()-c.time < 60000){ delete CALLS[u.id]; return res.json(c); }
  res.json({});
});

// ===== PAGE D'ACCUEIL =====
app.get('*', (req,res)=>{
  res.sendFile(path.join(__dirname,'public','index.html'));
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, ()=> console.log('Meeting en ligne sur port ' + PORT));
 
