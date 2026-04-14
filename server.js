const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'bitribut-agc-secret-2026';

// ============================================================
//  DATABASE SETUP
// ============================================================
const dbPath = process.env.DATABASE_PATH || path.join(__dirname, 'bitribut.db');
const db = new Database(dbPath);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS parceiros (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    cpfcnpj TEXT DEFAULT '',
    phone TEXT DEFAULT '',
    email TEXT DEFAULT '',
    default_comm REAL DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS instituicoes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    comm_bitribut REAL DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS propostas (
    id TEXT PRIMARY KEY,
    client_name TEXT NOT NULL,
    client_cpfcnpj TEXT DEFAULT '',
    client_phone TEXT DEFAULT '',
    client_email TEXT DEFAULT '',
    loan_type TEXT DEFAULT '',
    institution TEXT DEFAULT '',
    instituicao_id TEXT DEFAULT '',
    loan_value REAL DEFAULT 0,
    status TEXT DEFAULT 'Prospecção',
    partner_id TEXT DEFAULT '',
    partner_comm REAL DEFAULT 0,
    bitribut_comm REAL DEFAULT 0,
    partner_comm_value REAL DEFAULT 0,
    bitribut_comm_value REAL DEFAULT 0,
    total_comm_value REAL DEFAULT 0,
    notes TEXT DEFAULT '',
    created_by TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  );
`);

// Add columns to existing databases (safe migrations)
try { db.exec(`ALTER TABLE propostas ADD COLUMN instituicao_id TEXT DEFAULT ''`); } catch(e) {}
try { db.exec(`ALTER TABLE propostas ADD COLUMN inst_comm REAL DEFAULT 0`); } catch(e) {}
try { db.exec(`ALTER TABLE propostas ADD COLUMN inst_comm_value REAL DEFAULT 0`); } catch(e) {}

// Create default admin if not exists
const adminExists = db.prepare('SELECT id FROM users WHERE email = ?').get('admin@bitribut.com.br');
if (!adminExists) {
  const hash = bcrypt.hashSync('Bitribut@2026', 10);
  db.prepare('INSERT INTO users (id, name, email, password, role) VALUES (?, ?, ?, ?, ?)')
    .run('admin-001', 'Administrador', 'admin@bitribut.com.br', hash, 'admin');
  console.log('✅ Usuário admin criado: admin@bitribut.com.br / Bitribut@2026');
}

// ============================================================
//  MIDDLEWARE
// ============================================================
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

function uid() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2);
}

function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token não fornecido' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Sessão expirada. Faça login novamente.' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Acesso restrito ao administrador' });
  next();
}

// ============================================================
//  AUTH ROUTES
// ============================================================
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'E-mail e senha são obrigatórios' });

  const user = db.prepare('SELECT * FROM users WHERE email = ? AND active = 1').get(email.toLowerCase().trim());
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'E-mail ou senha incorretos' });
  }

  const token = jwt.sign(
    { id: user.id, email: user.email, name: user.name, role: user.role },
    JWT_SECRET,
    { expiresIn: '12h' }
  );

  res.json({
    token,
    user: { id: user.id, name: user.name, email: user.email, role: user.role }
  });
});

app.post('/api/auth/change-password', auth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!bcrypt.compareSync(currentPassword, user.password)) {
    return res.status(400).json({ error: 'Senha atual incorreta' });
  }
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: 'Nova senha deve ter pelo menos 6 caracteres' });
  }
  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hash, req.user.id);
  res.json({ ok: true, message: 'Senha alterada com sucesso' });
});

app.get('/api/auth/me', auth, (req, res) => {
  const user = db.prepare('SELECT id, name, email, role FROM users WHERE id = ?').get(req.user.id);
  res.json(user);
});

// ============================================================
//  USERS (Admin only)
// ============================================================
app.get('/api/users', auth, adminOnly, (req, res) => {
  const users = db.prepare('SELECT id, name, email, role, active, created_at FROM users ORDER BY name').all();
  res.json(users);
});

app.post('/api/users', auth, adminOnly, (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Nome e e-mail são obrigatórios' });

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase().trim());
  if (existing) return res.status(400).json({ error: 'E-mail já cadastrado' });

  const id = uid();
  const hash = bcrypt.hashSync(password || 'Bitribut@2026', 10);
  db.prepare('INSERT INTO users (id, name, email, password, role) VALUES (?, ?, ?, ?, ?)')
    .run(id, name, email.toLowerCase().trim(), hash, role || 'user');

  res.json({ id, name, email: email.toLowerCase().trim(), role: role || 'user', active: 1 });
});

app.put('/api/users/:id', auth, adminOnly, (req, res) => {
  const { name, email, role, active, password } = req.body;
  if (password && password.length > 0) {
    const hash = bcrypt.hashSync(password, 10);
    db.prepare('UPDATE users SET name=?, email=?, role=?, active=?, password=? WHERE id=?')
      .run(name, email.toLowerCase().trim(), role, active ? 1 : 0, hash, req.params.id);
  } else {
    db.prepare('UPDATE users SET name=?, email=?, role=?, active=? WHERE id=?')
      .run(name, email.toLowerCase().trim(), role, active ? 1 : 0, req.params.id);
  }
  res.json({ ok: true });
});

app.delete('/api/users/:id', auth, adminOnly, (req, res) => {
  if (req.params.id === req.user.id) {
    return res.status(400).json({ error: 'Você não pode excluir sua própria conta' });
  }
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ============================================================
//  PARCEIROS
// ============================================================
app.get('/api/parceiros', auth, (req, res) => {
  res.json(db.prepare('SELECT * FROM parceiros ORDER BY name').all());
});

app.post('/api/parceiros', auth, (req, res) => {
  const { name, cpfcnpj, phone, email, defaultComm } = req.body;
  if (!name) return res.status(400).json({ error: 'Nome é obrigatório' });
  const id = uid();
  db.prepare('INSERT INTO parceiros (id, name, cpfcnpj, phone, email, default_comm) VALUES (?,?,?,?,?,?)')
    .run(id, name, cpfcnpj || '', phone || '', email || '', defaultComm || 0);
  res.json({ id, name, cpfcnpj: cpfcnpj || '', phone: phone || '', email: email || '', default_comm: defaultComm || 0 });
});

app.put('/api/parceiros/:id', auth, (req, res) => {
  const { name, cpfcnpj, phone, email, defaultComm } = req.body;
  db.prepare('UPDATE parceiros SET name=?, cpfcnpj=?, phone=?, email=?, default_comm=? WHERE id=?')
    .run(name, cpfcnpj || '', phone || '', email || '', defaultComm || 0, req.params.id);
  res.json({ ok: true });
});

app.delete('/api/parceiros/:id', auth, (req, res) => {
  db.prepare('DELETE FROM parceiros WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ============================================================
//  INSTITUICOES
// ============================================================
app.get('/api/instituicoes', auth, (req, res) => {
  res.json(db.prepare('SELECT * FROM instituicoes ORDER BY name').all());
});

app.post('/api/instituicoes', auth, (req, res) => {
  const { name, commBitribut } = req.body;
  if (!name) return res.status(400).json({ error: 'Nome é obrigatório' });
  const id = uid();
  db.prepare('INSERT INTO instituicoes (id, name, comm_bitribut) VALUES (?,?,?)')
    .run(id, name, commBitribut || 0);
  res.json({ id, name, comm_bitribut: commBitribut || 0 });
});

app.put('/api/instituicoes/:id', auth, (req, res) => {
  const { name, commBitribut } = req.body;
  db.prepare('UPDATE instituicoes SET name=?, comm_bitribut=? WHERE id=?')
    .run(name, commBitribut || 0, req.params.id);
  res.json({ ok: true });
});

app.delete('/api/instituicoes/:id', auth, (req, res) => {
  db.prepare('DELETE FROM instituicoes WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ============================================================
//  PROPOSTAS
// ============================================================
app.get('/api/propostas', auth, (req, res) => {
  res.json(db.prepare('SELECT * FROM propostas ORDER BY created_at DESC').all());
});

app.post('/api/propostas', auth, (req, res) => {
  const p = req.body;
  const id = uid();
  const now = new Date().toISOString();
  db.prepare(`INSERT INTO propostas
    (id,client_name,client_cpfcnpj,client_phone,client_email,loan_type,institution,instituicao_id,
     loan_value,status,partner_id,partner_comm,bitribut_comm,inst_comm,partner_comm_value,
     bitribut_comm_value,inst_comm_value,total_comm_value,notes,created_by,created_at,updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(id, p.clientName, p.clientCpfCnpj || '', p.clientPhone || '', p.clientEmail || '',
      p.loanType || '', p.institution || '', p.instituicaoId || '',
      p.loanValue || 0, p.status || 'Prospecção',
      p.partnerId || '', p.partnerComm || 0, p.bitributComm || 0, p.instComm || 0,
      p.partnerCommValue || 0, p.bitributCommValue || 0, p.instCommValue || 0, p.totalCommValue || 0,
      p.notes || '', req.user.id, now, now);
  res.json({ id });
});

app.put('/api/propostas/:id', auth, (req, res) => {
  const p = req.body;
  const now = new Date().toISOString();
  db.prepare(`UPDATE propostas SET
    client_name=?,client_cpfcnpj=?,client_phone=?,client_email=?,loan_type=?,institution=?,instituicao_id=?,
    loan_value=?,status=?,partner_id=?,partner_comm=?,bitribut_comm=?,inst_comm=?,partner_comm_value=?,
    bitribut_comm_value=?,inst_comm_value=?,total_comm_value=?,notes=?,updated_at=? WHERE id=?`)
    .run(p.clientName, p.clientCpfCnpj || '', p.clientPhone || '', p.clientEmail || '',
      p.loanType || '', p.institution || '', p.instituicaoId || '',
      p.loanValue || 0, p.status,
      p.partnerId || '', p.partnerComm || 0, p.bitributComm || 0, p.instComm || 0,
      p.partnerCommValue || 0, p.bitributCommValue || 0, p.instCommValue || 0, p.totalCommValue || 0,
      p.notes || '', now, req.params.id);
  res.json({ ok: true });
});

app.delete('/api/propostas/:id', auth, (req, res) => {
  db.prepare('DELETE FROM propostas WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ============================================================
//  START SERVER
// ============================================================
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🚀 AGC Bitribut - Sistema rodando!`);
  console.log(`🌐 Acesse: http://localhost:${PORT}`);
  console.log(`\n👤 Login inicial:`);
  console.log(`   E-mail: admin@bitribut.com.br`);
  console.log(`   Senha:  Bitribut@2026\n`);
});
