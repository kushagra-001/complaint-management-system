// Complaint Management System - Express + MongoDB (Mongoose) + JWT auth
const express = require('express'), mongoose = require('mongoose'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'), path = require('path');
const SECRET = process.env.JWT_SECRET || 'dev-only-secret-change-me', Schema = mongoose.Schema, OID = Schema.Types.ObjectId;
const User = mongoose.model('User', new Schema({ uid: { type: String, unique: true }, name: String, email: { type: String, unique: true, lowercase: true }, phone: String, pw: String, role: { type: String, enum: ['citizen', 'officer', 'admin'] }, dept: String }, { timestamps: true }));
const Complaint = mongoose.model('Complaint', new Schema({ id: { type: String, unique: true }, user: { type: OID, ref: 'User' }, title: String, cat: String, prio: { type: String, default: 'Normal' }, desc: String, img: String, status: { type: String, default: 'Pending' }, officer: { type: OID, ref: 'User' }, dept: String, res: String, proof: String, rating: Number, fb: String, hist: [{ t: Date, s: String, n: String }] }, { timestamps: true, id: false }));
const Notif = mongoose.model('Notif', new Schema({ user: OID, msg: String, read: { type: Boolean, default: false } }, { timestamps: true }));
const Meta = mongoose.model('Meta', new Schema({ _id: String, depts: [String], cats: [String] }));
const Counter = mongoose.model('Counter', new Schema({ _id: String, n: Number }));
const nextId = async (k, base) => base + (await Counter.findByIdAndUpdate(k, { $inc: { n: 1 } }, { new: true, upsert: true })).n;
const note = (user, msg) => Notif.create({ user, msg });
const wrap = f => (req, res, next) => Promise.resolve(f(req, res, next)).catch(e => { console.error(e); res.status(500).json({ error: 'Server error' }); });
const bad = (res, m, c = 400) => res.status(c).json({ error: m });
const sign = u => jwt.sign({ id: u._id }, SECRET, { expiresIn: '8h' });
const pub = u => ({ id: u._id, uid: u.uid, name: u.name, email: u.email, phone: u.phone, role: u.role, dept: u.dept });
const auth = (...roles) => wrap(async (req, res, next) => {
  try { const p = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET); req.user = await User.findById(p.id); } catch { req.user = null; }
  if (!req.user) return bad(res, 'Please log in again', 401);
  if (roles.length && !roles.includes(req.user.role)) return bad(res, 'Not allowed for your role', 403);
  next();
});
const shape = c => ({ id: c.id, title: c.title, cat: c.cat, prio: c.prio, desc: c.desc, img: c.img, status: c.status, dept: c.dept, res: c.res, proof: c.proof, rating: c.rating, fb: c.fb, hist: c.hist, date: c.createdAt, user: c.user && { name: c.user.name, uid: c.user.uid, email: c.user.email }, officer: c.officer && { _id: c.officer._id, name: c.officer.name, dept: c.officer.dept } });
const pop = q => q.populate('user', 'name uid email').populate('officer', 'name dept');
const addHist = (c, s, n) => { c.status = s; c.hist.push({ t: new Date(), s, n }); };
const ok5 = s => !s || s.length < 600000; // attachments stored as data URLs (~450 KB image)

const app = express(); app.use(express.json({ limit: '2mb' }));

// ---------- AUTH ----------
app.post('/api/auth/register', wrap(async (req, res) => {
  const { name, email, phone, password } = req.body;
  if (!name || !/^\S+@\S+\.\S+$/.test(email || '') || (password || '').length < 6) return bad(res, 'Enter name, valid email and a password of 6+ characters');
  if (await User.findOne({ email: email.toLowerCase() })) return bad(res, 'Email already registered');
  const u = await User.create({ uid: await nextId('user', 'USR-'), name, email, phone, pw: await bcrypt.hash(password, 10), role: 'citizen' });
  res.json({ token: sign(u), user: pub(u) });
}));
app.post('/api/auth/login', wrap(async (req, res) => { // login with email OR user ID (e.g. USR-1001)
  const { login = '', password = '', role } = req.body, l = String(login).trim();
  const u = await User.findOne({ $or: [{ email: l.toLowerCase() }, { uid: l.toUpperCase() }] });
  if (!u || !(await bcrypt.compare(password, u.pw))) return bad(res, 'Wrong ID/email or password', 401);
  if (role && u.role !== role) return bad(res, `This account is a ${u.role}. Select the "${u.role[0].toUpperCase() + u.role.slice(1)}" tab to sign in.`, 403);
  res.json({ token: sign(u), user: pub(u) });
}));
app.get('/api/health', (req, res) => res.json({ ok: true, db: mongoose.connection.readyState === 1 }));
app.get('/api/me', auth(), (req, res) => res.json(pub(req.user)));
app.put('/api/me', auth(), wrap(async (req, res) => {
  const { name, phone, password } = req.body, u = req.user;
  if (name) u.name = name; if (phone !== undefined) u.phone = phone;
  if (password) { if (password.length < 6) return bad(res, 'Password needs 6+ characters'); u.pw = await bcrypt.hash(password, 10); }
  await u.save(); res.json(pub(u));
}));

// ---------- PUBLIC TRACKING (limited info, no login) ----------
app.get('/api/track/:id', wrap(async (req, res) => {
  const c = await Complaint.findOne({ id: req.params.id.toUpperCase() });
  if (!c) return bad(res, 'No complaint found with that ID', 404);
  res.json({ id: c.id, title: c.title, cat: c.cat, status: c.status, dept: c.dept, date: c.createdAt, hist: c.hist.map(h => ({ t: h.t, s: h.s })) });
}));

// ---------- META (categories / departments) ----------
app.get('/api/meta', auth(), wrap(async (req, res) => res.json(await Meta.findById('cfg'))));
app.put('/api/meta', auth('admin'), wrap(async (req, res) => {
  const clean = a => [...new Set((a || []).map(x => String(x).trim()).filter(Boolean))];
  res.json(await Meta.findByIdAndUpdate('cfg', { depts: clean(req.body.depts), cats: clean(req.body.cats) }, { new: true }));
}));

// ---------- COMPLAINTS ----------
app.post('/api/complaints', auth('citizen'), wrap(async (req, res) => {
  const { title, cat, prio, desc, img } = req.body;
  if (!title || !desc) return bad(res, 'Title and description are required');
  if (!ok5(img)) return bad(res, 'Attachment too large');
  const c = await Complaint.create({ id: await nextId('complaint', 'CMP-'), user: req.user._id, title, cat, prio: ['Normal', 'High', 'Urgent'].includes(prio) ? prio : 'Normal', desc, img, hist: [{ t: new Date(), s: 'Pending', n: 'Complaint submitted' }] });
  for (const a of await User.find({ role: 'admin' })) await note(a._id, `New complaint ${c.id}: ${c.title}`);
  await note(req.user._id, `Your complaint ${c.id} was received`);
  res.json({ id: c.id });
}));
app.get('/api/complaints', auth(), wrap(async (req, res) => {
  const r = req.user.role, q = r === 'citizen' ? { user: req.user._id } : r === 'officer' ? { officer: req.user._id } : {};
  res.json((await pop(Complaint.find(q)).sort({ createdAt: -1 })).map(shape));
}));
const mineOrAll = async (req, res) => {
  const c = await pop(Complaint.findOne({ id: req.params.id.toUpperCase() }));
  if (!c) return bad(res, 'Complaint not found', 404), null;
  const r = req.user.role, own = c.user && String(c.user._id) === String(req.user._id), asg = c.officer && String(c.officer._id) === String(req.user._id);
  if (r === 'admin' || (r === 'citizen' && own) || (r === 'officer' && asg)) return c;
  bad(res, 'Not your complaint', 403); return null;
};
app.get('/api/complaints/:id', auth(), wrap(async (req, res) => { const c = await mineOrAll(req, res); if (c) res.json(shape(c)); }));
app.patch('/api/complaints/:id/assign', auth('admin'), wrap(async (req, res) => {
  const c = await Complaint.findOne({ id: req.params.id }); if (!c) return bad(res, 'Not found', 404);
  if (['Normal', 'High', 'Urgent'].includes(req.body.prio)) c.prio = req.body.prio;
  if (req.body.officer) {
    const o = await User.findOne({ _id: req.body.officer, role: 'officer' }); if (!o) return bad(res, 'Officer not found');
    if (String(c.officer) !== String(o._id)) { c.officer = o._id; c.dept = o.dept; if (c.status !== 'Resolved') addHist(c, 'Assigned', `Assigned to ${o.name} (${o.dept})`); await note(o._id, `${c.id} assigned to you`); await note(c.user, `${c.id} was assigned to ${o.dept} department`); }
  }
  await c.save(); res.json({ ok: true });
}));
app.patch('/api/complaints/:id/status', auth('officer'), wrap(async (req, res) => {
  const c = await Complaint.findOne({ id: req.params.id, officer: req.user._id }); if (!c) return bad(res, 'Not assigned to you', 403);
  const { status, note: n, proof } = req.body;
  if (!['Accepted', 'In Progress', 'Resolved'].includes(status)) return bad(res, 'Invalid status');
  if (c.status === 'Resolved') return bad(res, 'Already resolved');
  if (status === 'Resolved') { if (!n) return bad(res, 'Add resolution details'); c.res = n; }
  if (proof) { if (!ok5(proof)) return bad(res, 'Proof too large'); c.proof = proof; }
  addHist(c, status, n || (status === 'Accepted' ? 'Officer accepted the complaint' : 'Status updated'));
  await c.save(); await note(c.user, `${c.id} is now ${status}`); res.json({ ok: true });
}));
app.post('/api/complaints/:id/rate', auth('citizen'), wrap(async (req, res) => {
  const c = await Complaint.findOne({ id: req.params.id, user: req.user._id });
  if (!c || c.status !== 'Resolved' || c.rating) return bad(res, 'Cannot rate this complaint');
  c.rating = Math.min(5, Math.max(1, +req.body.rating || 5)); c.fb = req.body.fb; await c.save(); res.json({ ok: true });
}));

// ---------- NOTIFICATIONS ----------
app.get('/api/notifs', auth(), wrap(async (req, res) => {
  const n = await Notif.find({ user: req.user._id }).sort({ createdAt: -1 }).limit(100);
  if (req.query.read) await Notif.updateMany({ user: req.user._id, read: false }, { read: true });
  res.json({ unread: await Notif.countDocuments({ user: req.user._id, read: false }), items: n.map(x => ({ msg: x.msg, t: x.createdAt, read: x.read })) });
}));
app.post('/api/notify', auth('admin'), wrap(async (req, res) => {
  const { to, msg } = req.body; if (!msg) return bad(res, 'Message required');
  const us = await User.find(['citizen', 'officer'].includes(to) ? { role: to } : { _id: to });
  for (const u of us) await note(u._id, '📢 ' + msg); res.json({ sent: us.length });
}));

// ---------- ADMIN: USERS & REPORTS ----------
app.get('/api/users', auth('admin'), wrap(async (req, res) => res.json((await User.find().sort({ createdAt: 1 })).map(pub))));
app.post('/api/users', auth('admin'), wrap(async (req, res) => {
  const { name, email, password, dept } = req.body;
  if (!name || !email || (password || '').length < 6 || !dept) return bad(res, 'Fill all fields (password 6+ chars)');
  if (await User.findOne({ email: email.toLowerCase() })) return bad(res, 'Email already exists');
  res.json(pub(await User.create({ uid: await nextId('officer', 'OFF-'), name, email, dept, pw: await bcrypt.hash(password, 10), role: 'officer' })));
}));
app.delete('/api/users/:id', auth('admin'), wrap(async (req, res) => {
  if (String(req.user._id) === req.params.id) return bad(res, 'You cannot delete yourself');
  await Complaint.updateMany({ officer: req.params.id, status: { $ne: 'Resolved' } }, { $unset: { officer: 1 }, status: 'Pending' });
  await User.findByIdAndDelete(req.params.id); res.json({ ok: true });
}));

// ---------- STATIC + START ----------
app.use(express.static(path.join(__dirname, 'public')));
async function seed() {
  if (!(await Meta.findById('cfg'))) await Meta.create({ _id: 'cfg', depts: ['Roads', 'Water', 'Electricity', 'Sanitation'], cats: ['Road Damage', 'Water Supply', 'Power Cut', 'Garbage', 'Other'] });
  for (const [name, email, pw, role, dept, k, b] of [['System Admin', 'admin@cms.com', 'admin123', 'admin', null, 'admin', 'ADM-'], ['Officer Rao', 'officer@cms.com', 'officer123', 'officer', 'Roads', 'officer', 'OFF-'], ['Amit Sharma', 'citizen@cms.com', 'citizen123', 'citizen', null, 'user', 'USR-']])
    if (!(await User.findOne({ email }))) await User.create({ uid: await nextId(k, b), name, email, dept, role, pw: await bcrypt.hash(pw, 10) });
  console.log('Seeded demo users (see README)');
}
mongoose.connect(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/cms').then(seed).then(() => app.listen(process.env.PORT || 3000, () => console.log('CMS running on http://localhost:' + (process.env.PORT || 3000))))
  .catch(e => { console.error('\nCould not start: ' + e.message + '\nIs MongoDB running? Start it, or set MONGO_URI (MongoDB Atlas) and try again.\n'); process.exit(1); });
