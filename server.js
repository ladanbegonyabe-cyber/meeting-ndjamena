const express = require('express'), multer = require('multer'), bcrypt = require('bcryptjs'),
  jwt = require('jsonwebtoken'), pg = require('pg'), cloudinary = require('cloudinary').v2;

pg.types.setTypeParser(20, Number);

const SECRET = process.env.JWT_SECRET || 'changez-moi-en-production';
const PORT = process.env.PORT || 3000;
const db = new pg.Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 10 });
const Q = (s, p) => db.query(s, p).then(r => r.rows);

const up = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 30 * 1024 * 1024 },
  fileFilter: (r, f, cb) => cb(null, /^(image|video)\//.test(f.mimetype))
});
const store = f => new Promise((ok, ko) => {
  if (!f) return ok(null);
  cloudinary.uploader.upload_stream({ resource_type: 'auto', folder: 'meeting' },
    (e, r) => e ? ko(e) : ok(r.secure_url)).end(f.buffer);
});

const app = express();
app.use(express.json());
app.use(express.static('public'));

const h = fn => (req, res, next) => fn(req, res).catch(next);
const auth = (req, res, next) => {
  try { req.uid = jwt.verify((req.headers.authorization || '').slice(7), SECRET).id; next(); }
  catch { res.status(401).json({ error: 'Non connecté' }); }
};
const token = u => jwt.sign({ id: u.id }, SECRET, { expiresIn: '30d' });
const pub = u => ({ id: u.id, name: u.name, faculty: u.faculty, level: u.level, bio: u.bio, avatar: u.avatar });
const priv = u => ({ ...pub(u), email: u.email, phone: u.phone });
const user = async id => (await Q('SELECT * FROM users WHERE id=$1', [id]))[0];
const num = v => { const n = parseInt(v, 10); if (isNaN(n)) throw new Error('Identifiant invalide'); return n; };

app.post('/api/register', up.single('avatar'), h(async (req, res) => {
  const { name, email, password, faculty, level, phone, bio } = req.body;
  if (!name || !email || !password || password.length < 6)
    return res.status(400).json({ error: 'Nom, email et mot de passe (6 caractères min.) requis' });
  if ((await Q('SELECT 1 FROM users WHERE email=$1', [email.toLowerCase()])).length)
    return res.status(400).json({ error: 'Cet email est déjà utilisé' });
  const avatar = await store(req.file);
  const [u] = await Q(`INSERT INTO users(name,email,pass,faculty,level,phone,bio,avatar)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
    [name, email.toLowerCase(), bcrypt.hashSync(password, 10), faculty || '', level || '', phone || '', bio || '', avatar]);
  res.json({ token: token(u), me: priv(u) });
}));

app.post('/api/login', h(async (req, res) => {
  const [u] = await Q('SELECT * FROM users WHERE email=$1', [(req.body.email || '').toLowerCase()]);
  if (!u || !bcrypt.compareSync(req.body.password || '', u.pass))
    return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
  res.json({ token: token(u), me: priv(u) });
}));

app.get('/api/me', auth, h(async (req, res) => res.json(priv(await user(req.uid)))));
app.put('/api/me', auth, up.single('avatar'), h(async (req, res) => {
  const o = await user(req.uid), b = req.body, av = await store(req.file);
  const [u] = await Q('UPDATE users SET name=$1,faculty=$2,level=$3,phone=$4,bio=$5,avatar=$6 WHERE id=$7 RETURNING *',
    [b.name || o.name, b.faculty ?? o.faculty, b.level ?? o.level, b.phone ?? o.phone, b.bio ?? o.bio, av || o.avatar, req.uid]);
  res.json(priv(u));
}));
app.post('/api/password', auth, h(async (req, res) => {
  const { old, new: nw } = req.body, u = await user(req.uid);
  if (!bcrypt.compareSync(old || '', u.pass)) return res.status(400).json({ error: 'Ancien mot de passe incorrect' });
  if (!nw || nw.length < 6) return res.status(400).json({ error: 'Nouveau mot de passe : 6 caractères min.' });
  await Q('UPDATE users SET pass=$1 WHERE id=$2', [bcrypt.hashSync(nw, 10), req.uid]);
  res.json({ ok: true });
}));

app.get('/api/users', auth, h(async (req, res) => {
  const s = '%' + (req.query.q || '') + '%';
  res.json((await Q(`SELECT u.*, (SELECT count(*) FROM msgs m WHERE m.frm=u.id AND m.too=$1 AND NOT m.seen) AS unread
    FROM users u WHERE u.id!=$1 AND (u.name ILIKE $2 OR u.faculty ILIKE $2)
    ORDER BY unread DESC, u.name LIMIT 50`, [req.uid, s])).map(u => ({ ...pub(u), unread: u.unread })));
}));
app.get('/api/users/:id', auth, h(async (req, res) => {
  const u = await user(num(req.params.id));
  u ? res.json(pub(u)) : res.status(404).json({ error: 'Étudiant introuvable' });
}));

app.get('/api/posts', auth, h(async (req, res) => {
  res.json(await Q(`SELECT p.*, u.name, u.faculty, u.avatar,
    (SELECT count(*) FROM likes WHERE pid=p.id) AS likes,
    EXISTS(SELECT 1 FROM likes WHERE pid=p.id AND uid=$1) AS liked,
    (SELECT count(*) FROM comments WHERE pid=p.id) AS ncom
    FROM posts p JOIN users u ON u.id=p.uid WHERE p.ts<$2 ORDER BY p.ts DESC LIMIT 20`,
    [req.uid, Number(req.query.before) || 9e15]));
}));
app.post('/api/posts', auth, up.single('media'), h(async (req, res) => {
  const text = (req.body.text || '').trim();
  if (!text && !req.file) return res.status(400).json({ error: 'Publication vide' });
  const type = req.file ? (req.file.mimetype.startsWith('video') ? 'video' : 'image') : null;
  await Q('INSERT INTO posts(uid,text,media,type,ts) VALUES($1,$2,$3,$4,$5)', [req.uid, text, await store(req.file), type, Date.now()]);
  res.json({ ok: true });
}));
app.delete('/api/posts/:id', auth, h(async (req, res) => {
  const id = num(req.params.id);
  if ((await Q('DELETE FROM posts WHERE id=$1 AND uid=$2 RETURNING id', [id, req.uid])).length) {
    await Q('DELETE FROM likes WHERE pid=$1', [id]);
    await Q('DELETE FROM comments WHERE pid=$1', [id]);
  }
  res.json({ ok: true });
}));
app.post('/api/posts/:id/like', auth, h(async (req, res) => {
  const id = num(req.params.id);
  const del = await Q('DELETE FROM likes WHERE pid=$1 AND uid=$2 RETURNING pid', [id, req.uid]);
  if (!del.length) await Q('INSERT INTO likes(pid,uid) VALUES($1,$2) ON CONFLICT DO NOTHING', [id, req.uid]);
  const [c] = await Q('SELECT count(*) AS n FROM likes WHERE pid=$1', [id]);
  res.json({ liked: !del.length, n: c.n });
}));
app.get('/api/posts/:id/comments', auth, h(async (req, res) => {
  res.json(await Q(`SELECT c.*, u.name FROM comments c JOIN users u ON u.id=c.uid WHERE c.pid=$1 ORDER BY c.ts LIMIT 200`, [num(req.params.id)]));
}));
app.post('/api/posts/:id/comments', auth, h(async (req, res) => {
  const t = (req.body.text || '').trim();
  if (!t) return res.status(400).json({ error: 'Commentaire vide' });
  await Q('INSERT INTO comments(pid,uid,text,ts) VALUES($1,$2,$3,$4)', [num(req.params.id), req.uid, t, Date.now()]);
  res.json({ ok: true });
}));

app.get('/api/unread', auth, h(async (req, res) => {
  const [c] = await Q('SELECT count(*) AS n FROM msgs WHERE too=$1 AND NOT seen', [req.uid]);
  const [last] = await Q(`SELECT u.name, m.text FROM msgs m JOIN users u ON u.id=m.frm
    WHERE m.too=$1 AND NOT m.seen ORDER BY m.ts DESC LIMIT 1`, [req.uid]);
  res.json({ n: c.n, last: last || null });
}));
app.get('/api/msgs/:id', auth, h(async (req, res) => {
  const id = num(req.params.id);
  await Q('UPDATE msgs SET seen=true WHERE frm=$1 AND too=$2 AND NOT seen', [id, req.uid]);
  res.json(await Q(`SELECT * FROM (SELECT * FROM msgs WHERE (frm=$1 AND too=$2) OR (frm=$2 AND too=$1)
    ORDER BY ts DESC LIMIT 200) x ORDER BY ts`, [req.uid, id]));
}));
app.post('/api/msgs/:id', auth, h(async (req, res) => {
  const t = (req.body.text || '').trim();
  if (!t) return res.status(400).json({ error: 'Message vide' });
  await Q('INSERT INTO msgs(frm,too,text,ts) VALUES($1,$2,$3,$4)', [req.uid, num(req.params.id), t, Date.now()]);
  res.json({ ok: true });
}));

app.use((err, req, res, next) => { console.error(err); res.status(400).json({ error: err.message }); });

(async () => {
  await db.query(`
  CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY, name TEXT, email TEXT UNIQUE, pass TEXT,
    faculty TEXT DEFAULT '', level TEXT DEFAULT '', phone TEXT DEFAULT '', bio TEXT DEFAULT '', avatar TEXT);
  CREATE TABLE IF NOT EXISTS posts(id SERIAL PRIMARY KEY, uid INT, text TEXT, media TEXT, type TEXT, ts BIGINT);
  CREATE TABLE IF NOT EXISTS likes(pid INT, uid INT, PRIMARY KEY(pid, uid));
  CREATE TABLE IF NOT EXISTS comments(id SERIAL PRIMARY KEY, pid INT, uid INT, text TEXT, ts BIGINT);
  CREATE TABLE IF NOT EXISTS msgs(id SERIAL PRIMARY KEY, frm INT, too INT, text TEXT, ts BIGINT, seen BOOLEAN DEFAULT false);
  CREATE INDEX IF NOT EXISTS i_posts ON posts(ts);
  CREATE INDEX IF NOT EXISTS i_msgs ON msgs(frm, too);
  CREATE INDEX IF NOT EXISTS i_com ON comments(pid);`);
  app.listen(PORT, () => console.log(`Meeting University of N'djamena → port ${PORT}`));
})().catch(e => { console.error('Base de données inaccessible :', e.message); process.exit(1); });
