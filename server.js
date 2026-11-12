const express = require('express'), multer = require('multer'), bcrypt = require('bcryptjs'),
  jwt = require('jsonwebtoken'), Database = require('better-sqlite3'), path = require('path'), fs = require('fs');

const SECRET = process.env.JWT_SECRET || 'changez-moi-en-production';
const PORT = process.env.PORT || 3000;
fs.mkdirSync('uploads', { recursive: true });

const db = new Database('meeting.db');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, pass TEXT,
  faculty TEXT, level TEXT, phone TEXT, bio TEXT, avatar TEXT);
CREATE TABLE IF NOT EXISTS posts(id INTEGER PRIMARY KEY, uid INTEGER, text TEXT, media TEXT, type TEXT, ts INTEGER);
CREATE TABLE IF NOT EXISTS msgs(id INTEGER PRIMARY KEY, frm INTEGER, too INTEGER, text TEXT, ts INTEGER);`);

const up = multer({
  storage: multer.diskStorage({
    destination: 'uploads',
    filename: (r, f, cb) => cb(null, Date.now() + '-' + Math.random().toString(36).slice(2) + path.extname(f.originalname).toLowerCase())
  }),
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (r, f, cb) => cb(null, /^(image|video)\//.test(f.mimetype))
});

const app = express();
app.use(express.json());
app.use('/uploads', express.static('uploads'));
app.use(express.static('public'));

const auth = (req, res, next) => {
  try { req.uid = jwt.verify((req.headers.authorization || '').slice(7), SECRET).id; next(); }
  catch { res.status(401).json({ error: 'Non connecté' }); }
};
const token = u => jwt.sign({ id: u.id }, SECRET, { expiresIn: '30d' });
const pub = u => ({ id: u.id, name: u.name, faculty: u.faculty, level: u.level, bio: u.bio, avatar: u.avatar });
const priv = u => ({ ...pub(u), email: u.email, phone: u.phone });
const url = f => (f ? '/uploads/' + f.filename : null);

app.post('/api/register', up.single('avatar'), (req, res) => {
  const { name, email, password, faculty, level, phone, bio } = req.body;
  if (!name || !email || !password || password.length < 6)
    return res.status(400).json({ error: 'Nom, email et mot de passe (6 caractères min.) requis' });
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email.toLowerCase()))
    return res.status(400).json({ error: 'Cet email est déjà utilisé' });
  const r = db.prepare('INSERT INTO users(name,email,pass,faculty,level,phone,bio,avatar) VALUES(?,?,?,?,?,?,?,?)')
    .run(name, email.toLowerCase(), bcrypt.hashSync(password, 10), faculty || '', level || '', phone || '', bio || '', url(req.file));
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(r.lastInsertRowid);
  res.json({ token: token(u), me: priv(u) });
});

app.post('/api/login', (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE email=?').get((req.body.email || '').toLowerCase());
  if (!u || !bcrypt.compareSync(req.body.password || '', u.pass))
    return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
  res.json({ token: token(u), me: priv(u) });
});

app.get('/api/me', auth, (req, res) => res.json(priv(db.prepare('SELECT * FROM users WHERE id=?').get(req.uid))));
app.put('/api/me', auth, up.single('avatar'), (req, res) => {
  const o = db.prepare('SELECT * FROM users WHERE id=?').get(req.uid), b = req.body;
  db.prepare('UPDATE users SET name=?,faculty=?,level=?,phone=?,bio=?,avatar=? WHERE id=?')
    .run(b.name || o.name, b.faculty ?? o.faculty, b.level ?? o.level, b.phone ?? o.phone, b.bio ?? o.bio, url(req.file) || o.avatar, req.uid);
  res.json(priv(db.prepare('SELECT * FROM users WHERE id=?').get(req.uid)));
});
app.get('/api/users', auth, (req, res) =>
  res.json(db.prepare('SELECT * FROM users WHERE id!=? ORDER BY name').all(req.uid).map(pub)));

app.get('/api/posts', auth, (req, res) =>
  res.json(db.prepare(`SELECT p.*, u.name, u.faculty, u.avatar FROM posts p JOIN users u ON u.id=p.uid ORDER BY p.ts DESC LIMIT 100`).all()));
app.post('/api/posts', auth, up.single('media'), (req, res) => {
  const text = (req.body.text || '').trim();
  if (!text && !req.file) return res.status(400).json({ error: 'Publication vide' });
  const type = req.file ? (req.file.mimetype.startsWith('video') ? 'video' : 'image') : null;
  db.prepare('INSERT INTO posts(uid,text,media,type,ts) VALUES(?,?,?,?,?)').run(req.uid, text, url(req.file), type, Date.now());
  res.json({ ok: true });
});
app.delete('/api/posts/:id', auth, (req, res) => {
  db.prepare('DELETE FROM posts WHERE id=? AND uid=?').run(req.params.id, req.uid);
  res.json({ ok: true });
});

app.get('/api/msgs/:id', auth, (req, res) =>
  res.json(db.prepare('SELECT * FROM msgs WHERE (frm=? AND too=?) OR (frm=? AND too=?) ORDER BY ts').all(req.uid, req.params.id, req.params.id, req.uid)));
app.post('/api/msgs/:id', auth, (req, res) => {
  const t = (req.body.text || '').trim();
  if (!t) return res.status(400).json({ error: 'Message vide' });
  db.prepare('INSERT INTO msgs(frm,too,text,ts) VALUES(?,?,?,?)').run(req.uid, req.params.id, t, Date.now());
  res.json({ ok: true });
});

app.use((err, req, res, next) => res.status(400).json({ error: err.message }));
app.listen(PORT, () => console.log(`Meeting University of N'djamena → http://localhost:${PORT}`));
