const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

const app = express();
app.use(cors({ origin: 'https://funny-taffy-da7027.netlify.app' }));
app.use(express.json({ limit: '1mb' }));
app.use(helmet({ contentSecurityPolicy: false }));
app.set('trust proxy', 1);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Demasiadas tentativas. Aguarde 15 minutos.' },
  standardHeaders: true, legacyHeaders: false
});

const JWT_SECRET = process.env.JWT_SECRET || 'producao-secret-2024-change-me';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || null; // Set 64-char hex key in env
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Helper: run query and return rows
const q = (sql, params = []) => pool.query(sql, params).then(r => r.rows);
const q1 = (sql, params = []) => pool.query(sql, params).then(r => r.rows[0] || null);

// Sanitize DB errors — não expor detalhes internos ao cliente
function dbErr(e) {
  console.error('DB error:', e.message);
  if (e.code === '23505') return 'Já existe um registo com estes dados (duplicado).';
  if (e.code === '23503') return 'Não é possível eliminar: existem registos dependentes.';
  if (e.code === '23502') return 'Campo obrigatório em falta.';
  return 'Erro interno do servidor. Tente novamente.';
}

async function logAudit(action, entityType, entityId, userInfo, details = {}) {
  try {
    await pool.query(
      'INSERT INTO audit_log(action,entity_type,entity_id,user_id,user_name,user_role,details) VALUES($1,$2,$3,$4,$5,$6,$7)',
      [action, entityType||null, entityId||null, userInfo?.id||null, userInfo?.name||userInfo?.role||null, userInfo?.role||null, JSON.stringify(details)]
    );
  } catch(e) { console.error('Audit log error:', e.message); }
}

function encrypt(text) {
  if (!ENCRYPTION_KEY || !text) return null;
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY.padEnd(64,'0').slice(0,64), 'hex'), iv);
  const enc = Buffer.concat([cipher.update(String(text)), cipher.final()]);
  return iv.toString('hex') + ':' + enc.toString('hex');
}
function decrypt(text) {
  if (!ENCRYPTION_KEY || !text) return text;
  try {
    const parts = text.split(':');
    if (parts.length < 2) return text; // not encrypted yet
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY.padEnd(64,'0').slice(0,64), 'hex'), Buffer.from(parts[0],'hex'));
    return Buffer.concat([decipher.update(Buffer.from(parts[1],'hex')), decipher.final()]).toString();
  } catch(e) { return null; }
}

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS machines (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      type TEXT NOT NULL CHECK(type IN ('extrusao','injecao')),
      has_weighing INTEGER DEFAULT 0,
      active INTEGER DEFAULT 1,
      notes TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS operators (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      number TEXT NOT NULL UNIQUE,
      pin_hash TEXT NOT NULL,
      pin_plain TEXT,
      role TEXT DEFAULT 'operator',
      active INTEGER DEFAULT 1,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS refs (
      id SERIAL PRIMARY KEY,
      code TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      machine_type TEXT NOT NULL CHECK(machine_type IN ('extrusao','injecao')),
      raw_material TEXT,
      weight_per_ml REAL,
      weight_per_piece REAL,
      notes TEXT,
      active INTEGER DEFAULT 1,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS colors (
      id SERIAL PRIMARY KEY,
      code TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      hex_color TEXT DEFAULT '#6B7280',
      active INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS stoppage_codes (
      id SERIAL PRIMARY KEY,
      code TEXT NOT NULL UNIQUE,
      description TEXT NOT NULL,
      category TEXT DEFAULT 'Geral',
      active INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS production_orders (
      id SERIAL PRIMARY KEY,
      order_number TEXT NOT NULL UNIQUE,
      reference_id INTEGER REFERENCES refs(id),
      color_id INTEGER REFERENCES colors(id),
      machine_id INTEGER REFERENCES machines(id),
      quantity REAL,
      unit TEXT DEFAULT 'pecas' CHECK(unit IN ('atados','metros','pecas')),
      mp_phases TEXT DEFAULT '[]',
      status TEXT DEFAULT 'active' CHECK(status IN ('pending','active','completed','cancelled')),
      notes TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS shifts (
      id SERIAL PRIMARY KEY,
      order_id INTEGER REFERENCES production_orders(id),
      operator_id INTEGER REFERENCES operators(id),
      machine_id INTEGER REFERENCES machines(id),
      shift_number INTEGER NOT NULL CHECK(shift_number IN (1,2,3)),
      date TEXT NOT NULL,
      start_time TEXT,
      end_time TEXT,
      status TEXT DEFAULT 'open' CHECK(status IN ('open','closed')),
      notes TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS production_entries (
      id SERIAL PRIMARY KEY,
      shift_id INTEGER NOT NULL REFERENCES shifts(id),
      color TEXT,
      rolls_bundles REAL DEFAULT 0,
      meters_pieces REAL DEFAULT 0,
      rejected REAL DEFAULT 0,
      active_cavities INTEGER,
      counter REAL,
      pieces_ok REAL DEFAULT 0,
      pieces_rejected REAL DEFAULT 0,
      finishing TEXT,
      notes TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS weighing_records (
      id SERIAL PRIMARY KEY,
      shift_id INTEGER NOT NULL REFERENCES shifts(id),
      rolo_number INTEGER,
      weight_kg REAL NOT NULL,
      notes TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS stoppages (
      id SERIAL PRIMARY KEY,
      shift_id INTEGER NOT NULL REFERENCES shifts(id),
      stoppage_code_id INTEGER REFERENCES stoppage_codes(id),
      duration_minutes INTEGER NOT NULL DEFAULT 0,
      notes TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id SERIAL PRIMARY KEY,
      action TEXT NOT NULL,
      entity_type TEXT,
      entity_id INTEGER,
      user_id INTEGER,
      user_name TEXT,
      user_role TEXT,
      details TEXT DEFAULT '{}',
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS app_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_shifts_date ON shifts(date);
    CREATE INDEX IF NOT EXISTS idx_shifts_machine_date ON shifts(machine_id,date);
    CREATE INDEX IF NOT EXISTS idx_shifts_status ON shifts(status);
    CREATE INDEX IF NOT EXISTS idx_entries_shift ON production_entries(shift_id);
    CREATE INDEX IF NOT EXISTS idx_stoppages_shift ON stoppages(shift_id);
    CREATE INDEX IF NOT EXISTS idx_weighing_shift ON weighing_records(shift_id);
    CREATE INDEX IF NOT EXISTS idx_operators_number ON operators(number);
    CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
  `);

  await pool.query('ALTER TABLE operators ADD COLUMN IF NOT EXISTS pin_plain TEXT');
  await pool.query("ALTER TABLE operators ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'operator'");
  // Colunas adicionadas em v2 — seguras de executar repetidamente
  await pool.query('ALTER TABLE production_entries ADD COLUMN IF NOT EXISTS start_time TEXT');
  await pool.query('ALTER TABLE production_entries ADD COLUMN IF NOT EXISTS end_time TEXT');
  await pool.query('ALTER TABLE production_entries ADD COLUMN IF NOT EXISTS validated BOOLEAN DEFAULT FALSE');

  // Migrate plain PINs to encrypted storage if ENCRYPTION_KEY is set
  if (ENCRYPTION_KEY) {
    const unenc = await q("SELECT id,pin_plain FROM operators WHERE pin_plain IS NOT NULL AND pin_plain NOT LIKE '%:%'");
    for (const op of unenc) {
      await pool.query('UPDATE operators SET pin_plain=$1 WHERE id=$2', [encrypt(op.pin_plain), op.id]);
    }
    if (unenc.length > 0) console.log(`Encrypted ${unenc.length} operator PINs`);
  }

  // Seed admin password hash if not yet stored
  const pwdSetting = await q1("SELECT value FROM app_settings WHERE key='admin_password_hash'");
  if (!pwdSetting) {
    const hash = bcrypt.hashSync(ADMIN_PASSWORD, 10);
    await pool.query("INSERT INTO app_settings(key,value) VALUES('admin_password_hash',$1)", [hash]);
  }

  const { rows } = await pool.query('SELECT COUNT(*) as c FROM machines');
  if (parseInt(rows[0].c) === 0) {
    await pool.query(`
      INSERT INTO machines (name,type,has_weighing) VALUES
        ('Extrusao 1','extrusao',0),
        ('Extrusao 2','extrusao',1),
        ('Extrusao 3','extrusao',0),
        ('Injecao 1','injecao',0),
        ('Injecao 2','injecao',0),
        ('Injecao 3','injecao',0)
    `);
    await pool.query(`
      INSERT INTO stoppage_codes (code,description,category) VALUES
        ('01','Mudanca de cor','Producao'),
        ('02','Mudanca de referencia','Producao'),
        ('03','Regulacao / Afinacao','Producao'),
        ('04','Avaria mecanica','Avaria'),
        ('05','Avaria eletrica','Avaria'),
        ('06','Limpeza de maquina','Manutencao'),
        ('07','Manutencao preventiva','Manutencao'),
        ('08','Falta de materia-prima','Material'),
        ('09','Pausa / Intervalo','Pessoal'),
        ('10','Falta de energia','Infraestrutura'),
        ('11','Troca de molde','Producao'),
        ('99','Outros','Geral')
    `);
    const pin_hash = bcrypt.hashSync('1234', 10);
    await pool.query(
      'INSERT INTO operators (name,number,pin_hash,pin_plain,role) VALUES ($1,$2,$3,$4,$5)',
      ['Operador Demo', '001', pin_hash, '1234', 'operator']
    );
    console.log('Base de dados inicializada com dados de exemplo');
  }
}

function auth(req, res, next) {
  const token = req.headers.authorization && req.headers.authorization.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Sem autorizacao' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch(e) { res.status(401).json({ error: 'Token invalido' }); }
}
function admin(req, res, next) {
  const token = req.headers.authorization && req.headers.authorization.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Sem autorizacao' });
  try {
    const u = jwt.verify(token, JWT_SECRET);
    if (u.role !== 'admin') return res.status(403).json({ error: 'Sem permissao' });
    req.user = u; next();
  } catch(e) { res.status(401).json({ error: 'Token invalido' }); }
}

app.get('/api/auth/me', auth, (req, res) => res.json(req.user));

// MACHINES
app.get('/api/machines', async (req, res) => {
  try { res.json(await q('SELECT * FROM machines WHERE active=1 ORDER BY type,name')); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/machines', admin, async (req, res) => {
  try {
    const b = req.body;
    const r = await q1('INSERT INTO machines(name,type,has_weighing,notes) VALUES($1,$2,$3,$4) RETURNING id',
      [b.name, b.type, b.has_weighing?1:0, b.notes||null]);
    res.json({ id: r.id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/machines/:id', admin, async (req, res) => {
  try {
    const b = req.body;
    await pool.query('UPDATE machines SET name=$1,type=$2,has_weighing=$3,notes=$4,active=$5 WHERE id=$6',
      [b.name, b.type, b.has_weighing?1:0, b.notes||null, b.active?1:0, req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// OPERATORS
app.get('/api/operators/public', async (req, res) => {
  try { res.json(await q('SELECT id,name,number,role FROM operators WHERE active=1 ORDER BY name')); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/operators', admin, async (req, res) => {
  try { const ops = await q('SELECT id,name,number,role,pin_plain,active,created_at FROM operators ORDER BY name');
    // PIN mascarado: mostra apenas '****' — nunca expor PINs em texto claro via API
    res.json(ops.map(o=>({...o, pin: o.pin_plain ? '****' : null, pin_plain:undefined}))); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/operators', admin, async (req, res) => {
  try {
    const b = req.body;
    const r = await q1('INSERT INTO operators(name,number,pin_hash,pin_plain,role) VALUES($1,$2,$3,$4,$5) RETURNING id',
      [b.name, b.number, bcrypt.hashSync(String(b.pin), 10), encrypt(String(b.pin)), b.role||'operator']);
    await logAudit('OPERATOR_CREATE', 'operator', r.id, req.user, { name: b.name, number: b.number });
    res.json({ id: r.id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/operators/:id', admin, async (req, res) => {
  try {
    const b = req.body;
    if (b.pin) {
      await pool.query('UPDATE operators SET name=$1,number=$2,pin_hash=$3,pin_plain=$4,role=$5,active=$6 WHERE id=$7',
        [b.name, b.number, bcrypt.hashSync(String(b.pin),10), encrypt(String(b.pin)), b.role||'operator', b.active?1:0, req.params.id]);
    } else {
      await pool.query('UPDATE operators SET name=$1,number=$2,role=$3,active=$4 WHERE id=$5',
        [b.name, b.number, b.role||'operator', b.active?1:0, req.params.id]);
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/operators/:id', admin, async (req, res) => {
  try {
    const id = req.params.id;
    const shifts = await q1('SELECT COUNT(*) as n FROM shifts WHERE operator_id=$1', [id]);
    const entries = await q1('SELECT COUNT(pe.id) as n FROM production_entries pe JOIN shifts s ON pe.shift_id=s.id WHERE s.operator_id=$1', [id]);
    if (req.query.dry_run) return res.json({ shifts: Number(shifts.n), entries: Number(entries.n) });
    await pool.query('DELETE FROM stoppages WHERE shift_id IN (SELECT id FROM shifts WHERE operator_id=$1)', [id]);
    await pool.query('DELETE FROM weighing_records WHERE shift_id IN (SELECT id FROM shifts WHERE operator_id=$1)', [id]);
    await pool.query('DELETE FROM production_entries WHERE shift_id IN (SELECT id FROM shifts WHERE operator_id=$1)', [id]);
    await pool.query('DELETE FROM shifts WHERE operator_id=$1', [id]);
    await pool.query('DELETE FROM operators WHERE id=$1', [id]);
    await logAudit('OPERATOR_DELETE', 'operator', Number(id), req.user);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// REFERENCES
app.get('/api/references', auth, async (req, res) => {
  try {
    const mt = req.query.machine_type;
    if (mt) {
      res.json(await q('SELECT * FROM refs WHERE active=1 AND machine_type=$1 ORDER BY code', [mt]));
    } else {
      res.json(await q('SELECT * FROM refs WHERE active=1 ORDER BY code'));
    }
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/references', admin, async (req, res) => {
  try {
    const b = req.body;
    const r = await q1('INSERT INTO refs(code,name,machine_type,raw_material,weight_per_ml,weight_per_piece,notes) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id',
      [b.code, b.name, b.machine_type, b.raw_material||null, b.weight_per_ml||null, b.weight_per_piece||null, b.notes||null]);
    res.json({ id: r.id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/references/:id', admin, async (req, res) => {
  try {
    const b = req.body;
    await pool.query('UPDATE refs SET code=$1,name=$2,machine_type=$3,raw_material=$4,weight_per_ml=$5,weight_per_piece=$6,notes=$7,active=$8 WHERE id=$9',
      [b.code, b.name, b.machine_type, b.raw_material||null, b.weight_per_ml||null, b.weight_per_piece||null, b.notes||null, b.active?1:0, req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/references/:id', admin, async (req, res) => {
  try {
    const id = req.params.id;
    const orders = await q1('SELECT COUNT(*) as n FROM production_orders WHERE reference_id=$1', [id]);
    const shifts = await q1('SELECT COUNT(*) as n FROM shifts WHERE order_id IN (SELECT id FROM production_orders WHERE reference_id=$1)', [id]);
    const entries = await q1('SELECT COUNT(pe.id) as n FROM production_entries pe JOIN shifts s ON pe.shift_id=s.id JOIN production_orders po ON s.order_id=po.id WHERE po.reference_id=$1', [id]);
    if (req.query.dry_run) return res.json({ orders: Number(orders.n), shifts: Number(shifts.n), entries: Number(entries.n) });
    await pool.query('DELETE FROM stoppages WHERE shift_id IN (SELECT s.id FROM shifts s JOIN production_orders po ON s.order_id=po.id WHERE po.reference_id=$1)', [id]);
    await pool.query('DELETE FROM weighing_records WHERE shift_id IN (SELECT s.id FROM shifts s JOIN production_orders po ON s.order_id=po.id WHERE po.reference_id=$1)', [id]);
    await pool.query('DELETE FROM production_entries WHERE shift_id IN (SELECT s.id FROM shifts s JOIN production_orders po ON s.order_id=po.id WHERE po.reference_id=$1)', [id]);
    await pool.query('DELETE FROM shifts WHERE order_id IN (SELECT id FROM production_orders WHERE reference_id=$1)', [id]);
    await pool.query('DELETE FROM production_orders WHERE reference_id=$1', [id]);
    await pool.query('DELETE FROM refs WHERE id=$1', [id]);
    await logAudit('REFERENCE_DELETE', 'reference', Number(id), req.user);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/machines/:id', admin, async (req, res) => {
  try {
    const id = req.params.id;
    const shifts = await q1('SELECT COUNT(*) as n FROM shifts WHERE machine_id=$1', [id]);
    const entries = await q1('SELECT COUNT(pe.id) as n FROM production_entries pe JOIN shifts s ON pe.shift_id=s.id WHERE s.machine_id=$1', [id]);
    const orders = await q1('SELECT COUNT(*) as n FROM production_orders WHERE machine_id=$1', [id]);
    if (req.query.dry_run) return res.json({ shifts: Number(shifts.n), entries: Number(entries.n), orders: Number(orders.n) });
    await pool.query('DELETE FROM stoppages WHERE shift_id IN (SELECT id FROM shifts WHERE machine_id=$1)', [id]);
    await pool.query('DELETE FROM weighing_records WHERE shift_id IN (SELECT id FROM shifts WHERE machine_id=$1)', [id]);
    await pool.query('DELETE FROM production_entries WHERE shift_id IN (SELECT id FROM shifts WHERE machine_id=$1)', [id]);
    await pool.query('DELETE FROM shifts WHERE machine_id=$1', [id]);
    await pool.query('UPDATE production_orders SET machine_id=NULL WHERE machine_id=$1', [id]);
    await pool.query('DELETE FROM machines WHERE id=$1', [id]);
    await logAudit('MACHINE_DELETE', 'machine', Number(id), req.user);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// COLORS
app.get('/api/colors', auth, async (req, res) => {
  try { res.json(await q('SELECT * FROM colors WHERE active=1 ORDER BY name')); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/colors', admin, async (req, res) => {
  try {
    const b = req.body;
    const r = await q1('INSERT INTO colors(code,name,hex_color) VALUES($1,$2,$3) RETURNING id',
      [b.code, b.name, b.hex_color||'#6B7280']);
    res.json({ id: r.id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/colors/:id', admin, async (req, res) => {
  try {
    const b = req.body;
    await pool.query('UPDATE colors SET code=$1,name=$2,hex_color=$3,active=$4 WHERE id=$5',
      [b.code, b.name, b.hex_color, b.active?1:0, req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/colors/:id', admin, async (req, res) => {
  try {
    const id = req.params.id;
    const orders = await q1('SELECT COUNT(*) as n FROM production_orders WHERE color_id=$1', [id]);
    if (req.query.dry_run) return res.json({ orders: Number(orders.n) });
    await pool.query('UPDATE production_orders SET color_id=NULL WHERE color_id=$1', [id]);
    await pool.query('DELETE FROM colors WHERE id=$1', [id]);
    await logAudit('COLOR_DELETE', 'color', Number(id), req.user);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// STOPPAGE CODES
app.get('/api/stoppage-codes', auth, async (req, res) => {
  try { res.json(await q('SELECT * FROM stoppage_codes WHERE active=1 ORDER BY code')); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/stoppage-codes', admin, async (req, res) => {
  try {
    const b = req.body;
    const r = await q1('INSERT INTO stoppage_codes(code,description,category) VALUES($1,$2,$3) RETURNING id',
      [b.code, b.description, b.category||'Geral']);
    res.json({ id: r.id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/stoppage-codes/:id', admin, async (req, res) => {
  try {
    const b = req.body;
    await pool.query('UPDATE stoppage_codes SET code=$1,description=$2,category=$3,active=$4 WHERE id=$5',
      [b.code, b.description, b.category, b.active?1:0, req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/stoppage-codes/:id', admin, async (req, res) => {
  try {
    const id = req.params.id;
    const stoppages = await q1('SELECT COUNT(*) as n FROM stoppages WHERE stoppage_code_id=$1', [id]);
    if (req.query.dry_run) return res.json({ stoppages: Number(stoppages.n) });
    await pool.query('DELETE FROM stoppages WHERE stoppage_code_id=$1', [id]);
    await pool.query('DELETE FROM stoppage_codes WHERE id=$1', [id]);
    await logAudit('STOPCODE_DELETE', 'stoppage_code', Number(id), req.user);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ORDERS
const ORDER_COLS = `po.*,r.code as ref_code,r.name as ref_name,r.weight_per_ml,r.weight_per_piece,
  r.raw_material as ref_raw_material,c.name as color_name,c.hex_color,c.code as color_code,
  m.name as machine_name,m.type as machine_type,m.has_weighing
  FROM production_orders po
  LEFT JOIN refs r ON po.reference_id=r.id
  LEFT JOIN colors c ON po.color_id=c.id
  LEFT JOIN machines m ON po.machine_id=m.id`;

app.get('/api/orders', auth, async (req, res) => {
  try {
    let sql = 'SELECT ' + ORDER_COLS + ' WHERE 1=1';
    const p = [];
    if (req.query.status) { sql += ` AND po.status=$${p.length+1}`; p.push(req.query.status); }
    if (req.query.machine_id) { sql += ` AND po.machine_id=$${p.length+1}`; p.push(req.query.machine_id); }
    sql += ' ORDER BY po.created_at DESC';
    res.json(await q(sql, p));
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/orders/:id', auth, async (req, res) => {
  try {
    const o = await q1('SELECT ' + ORDER_COLS + ' WHERE po.id=$1', [req.params.id]);
    if (!o) return res.status(404).json({ error: 'Ordem nao encontrada' });
    res.json(o);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/orders/:id/history', auth, async (req, res) => {
  try {
    const shifts = await q(`
      SELECT s.id,s.date,s.shift_number,s.start_time,s.end_time,s.status,
        op.name as operator_name,
        COALESCE(SUM(pe.rolls_bundles),0) as total_rolls,
        COALESCE(SUM(pe.meters_pieces),0) as total_meters,
        COALESCE(SUM(pe.pieces_ok),0) as total_pieces_ok,
        COALESCE(SUM(pe.rejected+pe.pieces_rejected),0) as total_rejected
      FROM shifts s
      LEFT JOIN operators op ON s.operator_id=op.id
      LEFT JOIN production_entries pe ON pe.shift_id=s.id
      WHERE s.order_id=$1
      GROUP BY s.id,op.name ORDER BY s.date DESC,s.shift_number
    `, [req.params.id]);
    const totals = shifts.reduce((acc,s)=>({
      total_meters: acc.total_meters+(Number(s.total_meters)||0),
      total_pieces_ok: acc.total_pieces_ok+(Number(s.total_pieces_ok)||0),
      total_rolls: acc.total_rolls+(Number(s.total_rolls)||0),
      total_rejected: acc.total_rejected+(Number(s.total_rejected)||0)
    }), {total_meters:0,total_pieces_ok:0,total_rolls:0,total_rejected:0});
    res.json({ shifts, totals });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/orders/:id', admin, async (req, res) => {
  try {
    const id = req.params.id;
    const shifts = await q1('SELECT COUNT(*) as n FROM shifts WHERE order_id=$1', [id]);
    const entries = await q1('SELECT COUNT(pe.id) as n FROM production_entries pe JOIN shifts s ON pe.shift_id=s.id WHERE s.order_id=$1', [id]);
    if (req.query.dry_run) return res.json({ shifts: Number(shifts.n), entries: Number(entries.n) });
    await pool.query('DELETE FROM stoppages WHERE shift_id IN (SELECT id FROM shifts WHERE order_id=$1)', [id]);
    await pool.query('DELETE FROM weighing_records WHERE shift_id IN (SELECT id FROM shifts WHERE order_id=$1)', [id]);
    await pool.query('DELETE FROM production_entries WHERE shift_id IN (SELECT id FROM shifts WHERE order_id=$1)', [id]);
    await pool.query('DELETE FROM shifts WHERE order_id=$1', [id]);
    await pool.query('DELETE FROM production_orders WHERE id=$1', [id]);
    await logAudit('ORDER_DELETE', 'order', Number(id), req.user);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/orders', admin, async (req, res) => {
  try {
    const b = req.body;
    const r = await q1('INSERT INTO production_orders(order_number,reference_id,color_id,machine_id,quantity,unit,mp_phases,notes) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id',
      [b.order_number, b.reference_id||null, b.color_id||null, b.machine_id||null, b.quantity||null, b.unit||'pecas', JSON.stringify(b.mp_phases||[]), b.notes||null]);
    await logAudit('ORDER_CREATE', 'order', r.id, req.user, { order_number: b.order_number });
    res.json({ id: r.id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/orders/:id', admin, async (req, res) => {
  try {
    const b = req.body;
    await pool.query('UPDATE production_orders SET order_number=$1,reference_id=$2,color_id=$3,machine_id=$4,quantity=$5,unit=$6,mp_phases=$7,notes=$8,status=$9 WHERE id=$10',
      [b.order_number, b.reference_id||null, b.color_id||null, b.machine_id||null, b.quantity||null, b.unit||'pecas', JSON.stringify(b.mp_phases||[]), b.notes||null, b.status||'active', req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

const TZ = 'Europe/Lisbon';
function lisboaHour() {
  return Number(new Intl.DateTimeFormat('pt-PT', { hour: '2-digit', hour12: false, timeZone: TZ }).format(new Date()));
}
function currentShift() {
  const h = lisboaHour();
  if (h >= 8 && h < 17) return 1;  // Manhã 08-17
  if (h >= 17 || h < 1) return 2;  // Tarde 17-01
  return 3;                          // Noite 01-08
}
function todayStr() { return new Date().toLocaleDateString('en-CA', { timeZone: TZ }); }
function nowTime() { return new Date().toLocaleTimeString('pt-PT', { hour: '2-digit', minute: '2-digit', timeZone: TZ }); }

const SHIFT_COLS = `s.*,op.name as operator_name,op.number as operator_number,
  po.order_number,po.unit,po.status as order_status,
  r.code as ref_code,r.name as ref_name,r.weight_per_ml,r.weight_per_piece,
  c.name as color_name,c.code as color_code,c.hex_color,
  m.name as machine_name,m.type as machine_type,m.has_weighing
  FROM shifts s
  LEFT JOIN operators op ON s.operator_id=op.id
  LEFT JOIN production_orders po ON s.order_id=po.id
  LEFT JOIN refs r ON po.reference_id=r.id
  LEFT JOIN colors c ON po.color_id=c.id
  LEFT JOIN machines m ON s.machine_id=m.id`;

app.get('/api/shifts/active', auth, async (req, res) => {
  try {
    // Sem filtro de data: um turno noturno aberto ontem deve ser encontrado hoje
    const shift = await q1(
      `SELECT ${SHIFT_COLS} WHERE s.machine_id=$1 AND s.status='open' ORDER BY s.created_at DESC LIMIT 1`,
      [req.query.machine_id]
    );
    res.json(shift || null);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/shifts', admin, async (req, res) => {
  try {
    let sql = 'SELECT ' + SHIFT_COLS + ' WHERE 1=1';
    const p = [];
    if (req.query.date) { sql += ` AND s.date=$${p.length+1}`; p.push(req.query.date); }
    if (req.query.date_from) { sql += ` AND s.date>=$${p.length+1}`; p.push(req.query.date_from); }
    if (req.query.date_to) { sql += ` AND s.date<=$${p.length+1}`; p.push(req.query.date_to); }
    if (req.query.machine_id) { sql += ` AND s.machine_id=$${p.length+1}`; p.push(req.query.machine_id); }
    sql += ' ORDER BY s.date DESC,s.shift_number';
    res.json(await q(sql, p));
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/shifts/:id', auth, async (req, res) => {
  try {
    const shift = await q1('SELECT ' + SHIFT_COLS + ' WHERE s.id=$1', [req.params.id]);
    if (!shift) return res.status(404).json({ error: 'Turno nao encontrado' });
    const entries = await q('SELECT * FROM production_entries WHERE shift_id=$1 ORDER BY created_at', [req.params.id]);
    const stoppages = await q(
      'SELECT st.*,sc.code as stop_code,sc.description as stop_desc,sc.category FROM stoppages st LEFT JOIN stoppage_codes sc ON st.stoppage_code_id=sc.id WHERE st.shift_id=$1 ORDER BY st.created_at',
      [req.params.id]
    );
    const weighing = await q('SELECT * FROM weighing_records WHERE shift_id=$1 ORDER BY rolo_number,created_at', [req.params.id]);
    const orderTotals = shift.order_id ? await q1(
      `SELECT SUM(pe.meters_pieces) as total_meters,SUM(pe.pieces_ok) as total_pieces_ok,
       SUM(pe.rolls_bundles) as total_rolls,SUM(pe.rejected+pe.pieces_rejected) as total_rejected
       FROM production_entries pe JOIN shifts s2 ON pe.shift_id=s2.id WHERE s2.order_id=$1`,
      [shift.order_id]
    ) : null;
    res.json(Object.assign({}, shift, { entries, stoppages, weighing, orderTotals }));
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/shifts', auth, async (req, res) => {
  try {
    const order = await q1("SELECT * FROM production_orders WHERE id=$1 AND status='active'", [req.body.order_id]);
    if (!order) return res.status(400).json({ error: 'Ordem nao encontrada ou nao ativa' });
    const shiftNum = Number(req.body.shift_number) || currentShift();
    const sameShift = await q1("SELECT id FROM shifts WHERE machine_id=$1 AND date=$2 AND shift_number=$3 AND status='open'",
      [req.body.machine_id, todayStr(), shiftNum]);
    if (sameShift) return res.json({ id: sameShift.id, resumed: true });
    const anyOpen = await q1("SELECT id FROM shifts WHERE machine_id=$1 AND status='open'",
      [req.body.machine_id]);
    if (anyOpen) return res.status(400).json({ error: 'Esta máquina já tem um turno aberto. Feche o turno atual antes de abrir um novo.' });
    const r = await q1('INSERT INTO shifts(order_id,operator_id,machine_id,shift_number,date,start_time) VALUES($1,$2,$3,$4,$5,$6) RETURNING id',
      [req.body.order_id, req.user.id, req.body.machine_id, shiftNum, todayStr(), nowTime()]);
    await logAudit('SHIFT_OPEN', 'shift', r.id, req.user, { machine_id: req.body.machine_id, order_id: req.body.order_id, shift_number: shiftNum });
    res.json({ id: r.id, resumed: false });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/shifts/:id/close', auth, async (req, res) => {
  try {
    await pool.query("UPDATE shifts SET status='closed',end_time=$1,notes=$2 WHERE id=$3",
      [nowTime(), (req.body && req.body.notes)||null, req.params.id]);
    await logAudit('SHIFT_CLOSE', 'shift', Number(req.params.id), req.user);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/shifts/:id', admin, async (req, res) => {
  try {
    const id = req.params.id;
    await pool.query('DELETE FROM stoppages WHERE shift_id=$1', [id]);
    await pool.query('DELETE FROM weighing_records WHERE shift_id=$1', [id]);
    await pool.query('DELETE FROM production_entries WHERE shift_id=$1', [id]);
    await pool.query('DELETE FROM shifts WHERE id=$1', [id]);
    await logAudit('SHIFT_DELETE', 'shift', Number(id), req.user);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// PRODUCTION ENTRIES
app.post('/api/production-entries', auth, async (req, res) => {
  try {
    const b = req.body;
    const hasValue = (b.rolls_bundles||0)+(b.meters_pieces||0)+(b.pieces_ok||0)+(b.pieces_rejected||0)+(b.rejected||0);
    if (!hasValue) return res.status(400).json({ error: 'Registo em branco: introduz pelo menos um valor.' });
    const r = await q1(
      'INSERT INTO production_entries(shift_id,color,rolls_bundles,meters_pieces,rejected,active_cavities,counter,pieces_ok,pieces_rejected,finishing,notes,start_time,end_time) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id',
      [b.shift_id, b.color||null, b.rolls_bundles||0, b.meters_pieces||0, b.rejected||0, b.active_cavities||null, b.counter||null, b.pieces_ok||0, b.pieces_rejected||0, b.finishing||null, b.notes||null, b.start_time||null, b.end_time||null]
    );
    res.json({ id: r.id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/production-entries/:id', auth, async (req, res) => {
  try {
    const b = req.body;
    const before = await q1('SELECT * FROM production_entries WHERE id=$1', [req.params.id]);
    await pool.query(
      'UPDATE production_entries SET color=$1,rolls_bundles=$2,meters_pieces=$3,rejected=$4,active_cavities=$5,counter=$6,pieces_ok=$7,pieces_rejected=$8,finishing=$9,notes=$10,start_time=$11,end_time=$12 WHERE id=$13',
      [b.color||null, b.rolls_bundles||0, b.meters_pieces||0, b.rejected||0, b.active_cavities||null, b.counter||null, b.pieces_ok||0, b.pieces_rejected||0, b.finishing||null, b.notes||null, b.start_time||null, b.end_time||null, req.params.id]
    );
    await logAudit('ENTRY_EDIT', 'production_entry', Number(req.params.id), req.user, {
      before: { rolls: before?.rolls_bundles, meters: before?.meters_pieces, pieces_ok: before?.pieces_ok, rejected: before?.rejected },
      after:  { rolls: b.rolls_bundles||0, meters: b.meters_pieces||0, pieces_ok: b.pieces_ok||0, rejected: b.rejected||0 }
    });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
// QUALITY VALIDATION
app.put('/api/production-entries/:id/validate', auth, async (req, res) => {
  try {
    await pool.query('UPDATE production_entries SET validated=TRUE WHERE id=$1', [req.params.id]);
    await logAudit('ENTRY_VALIDATE', 'production_entry', Number(req.params.id), req.user, {});
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: dbErr(e) }); }
});
app.put('/api/production-entries/:id/unvalidate', auth, async (req, res) => {
  try {
    await pool.query('UPDATE production_entries SET validated=FALSE WHERE id=$1', [req.params.id]);
    await logAudit('ENTRY_UNVALIDATE', 'production_entry', Number(req.params.id), req.user, {});
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: dbErr(e) }); }
});
app.delete('/api/production-entries/:id', auth, async (req, res) => {
  try {
    // Admins podem apagar tudo; operadores só podem apagar os seus próprios registos
    if (req.user.role !== 'admin') {
      const entry = await q1(
        'SELECT pe.id FROM production_entries pe JOIN shifts s ON pe.shift_id=s.id WHERE pe.id=$1 AND s.operator_id=$2',
        [req.params.id, req.user.id]
      );
      if (!entry) return res.status(403).json({ error: 'Não tens permissão para apagar este registo' });
    }
    await pool.query('DELETE FROM production_entries WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// WEIGHING
app.post('/api/weighing', auth, async (req, res) => {
  try {
    const b = req.body;
    const r = await q1('INSERT INTO weighing_records(shift_id,rolo_number,weight_kg,notes) VALUES($1,$2,$3,$4) RETURNING id',
      [b.shift_id, b.rolo_number||null, b.weight_kg, b.notes||null]);
    res.json({ id: r.id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/weighing/:id', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      const rec = await q1(
        'SELECT w.id FROM weighing_records w JOIN shifts s ON w.shift_id=s.id WHERE w.id=$1 AND s.operator_id=$2',
        [req.params.id, req.user.id]
      );
      if (!rec) return res.status(403).json({ error: 'Não tens permissão para apagar esta pesagem' });
    }
    await pool.query('DELETE FROM weighing_records WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// STOPPAGES
app.post('/api/stoppages', auth, async (req, res) => {
  try {
    const b = req.body;
    const r = await q1('INSERT INTO stoppages(shift_id,stoppage_code_id,duration_minutes,notes) VALUES($1,$2,$3,$4) RETURNING id',
      [b.shift_id, b.stoppage_code_id||null, b.duration_minutes||0, b.notes||null]);
    res.json({ id: r.id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/stoppages/:id', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      const rec = await q1(
        'SELECT st.id FROM stoppages st JOIN shifts s ON st.shift_id=s.id WHERE st.id=$1 AND s.operator_id=$2',
        [req.params.id, req.user.id]
      );
      if (!rec) return res.status(403).json({ error: 'Não tens permissão para apagar esta paragem' });
    }
    await pool.query('DELETE FROM stoppages WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// DASHBOARD
app.get('/api/dashboard', admin, async (req, res) => {
  try {
    const t = todayStr();
    // Usar timezone de Lisboa para garantir que "hoje" é consistente com o frontend
    const wsDate = new Date();
    wsDate.setDate(wsDate.getDate() - 6);
    const ws = wsDate.toLocaleDateString('sv-SE', { timeZone: 'Europe/Lisbon' }); // sv-SE dá formato YYYY-MM-DD

    const [todayProd, todayStops, machines, topStops, daily, stopCats] = await Promise.all([
      q1('SELECT SUM(pe.rolls_bundles) as total_rolls,SUM(pe.meters_pieces) as total_meters,SUM(pe.pieces_ok) as total_pieces_ok,SUM(pe.rejected+pe.pieces_rejected) as total_rejected,COUNT(DISTINCT s.id) as shift_count FROM production_entries pe JOIN shifts s ON pe.shift_id=s.id WHERE s.date=$1', [t]),
      q1('SELECT SUM(st.duration_minutes) as total_min,COUNT(*) as count FROM stoppages st JOIN shifts s ON st.shift_id=s.id WHERE s.date=$1', [t]),
      q("SELECT m.id,m.name,m.type,s.id as shift_id,s.shift_number,s.status,s.start_time,op.name as operator_name,po.order_number,r.code as ref_code FROM machines m LEFT JOIN shifts s ON s.machine_id=m.id AND s.date=$1 AND s.status='open' LEFT JOIN operators op ON s.operator_id=op.id LEFT JOIN production_orders po ON s.order_id=po.id LEFT JOIN refs r ON po.reference_id=r.id WHERE m.active=1 ORDER BY m.type,m.name", [t]),
      q('SELECT sc.code,sc.description,sc.category,COUNT(*) as cnt,SUM(st.duration_minutes) as total_min FROM stoppages st JOIN stoppage_codes sc ON st.stoppage_code_id=sc.id JOIN shifts s ON st.shift_id=s.id WHERE s.date>=$1 GROUP BY sc.id,sc.code,sc.description,sc.category ORDER BY total_min DESC LIMIT 10', [ws]),
      q('SELECT s.date,SUM(pe.meters_pieces) as meters,SUM(pe.pieces_ok) as pieces,SUM(pe.rolls_bundles) as rolls FROM production_entries pe JOIN shifts s ON pe.shift_id=s.id WHERE s.date>=$1 GROUP BY s.date ORDER BY s.date', [ws]),
      q('SELECT sc.category,SUM(st.duration_minutes) as total_min FROM stoppages st JOIN stoppage_codes sc ON st.stoppage_code_id=sc.id JOIN shifts s ON st.shift_id=s.id WHERE s.date>=$1 GROUP BY sc.category', [ws])
    ]);
    res.json({ today: { production: todayProd, stoppages: todayStops }, machines, topStops, daily, stopCats });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// EFFICIENCY
// QUALITY ENDPOINTS
app.get('/api/quality/shifts', auth, async (req, res) => {
  try {
    const date = req.query.date || todayStr();
    const shifts = await q(`SELECT ${SHIFT_COLS} WHERE s.date=$1 ORDER BY m.name, s.shift_number`, [date]);
    for (const shift of shifts) {
      shift.entries = await q(
        `SELECT pe.*, c.name as color_name FROM production_entries pe
         LEFT JOIN colors c ON pe.color=c.code
         WHERE pe.shift_id=$1 ORDER BY pe.created_at`,
        [shift.id]
      );
    }
    res.json(shifts);
  } catch(e) { res.status(500).json({ error: dbErr(e) }); }
});
app.get('/api/quality/daily-report', auth, async (req, res) => {
  try {
    const date = req.query.date || todayStr();
    const entries = await q(
      `SELECT pe.*, c.name as color_name,
         s.shift_number, s.date,
         op.name as operator_name, op.number as operator_number,
         m.name as machine_name, m.type as machine_type,
         r.code as ref_code, r.name as ref_name
       FROM production_entries pe
       JOIN shifts s ON pe.shift_id=s.id
       JOIN operators op ON s.operator_id=op.id
       JOIN machines m ON s.machine_id=m.id
       LEFT JOIN colors c ON pe.color=c.code
       LEFT JOIN production_orders po ON s.order_id=po.id
       LEFT JOIN refs r ON po.reference_id=r.id
       WHERE s.date=$1 AND pe.validated=TRUE
       ORDER BY m.name, s.shift_number, pe.created_at`,
      [date]
    );
    res.json(entries);
  } catch(e) { res.status(500).json({ error: dbErr(e) }); }
});

app.get('/api/efficiency', admin, async (req, res) => {
  try {
    const from = req.query.from || new Date(Date.now()-30*86400000).toISOString().split('T')[0];
    const to   = req.query.to   || todayStr();
    const rows = await q(
      `SELECT m.id,m.name,m.type,
         COUNT(DISTINCT s.id) as shift_count,
         SUM(st.duration_minutes) as total_stop_min,
         SUM(pe.meters_pieces) as total_meters,
         SUM(pe.pieces_ok) as total_pieces_ok
       FROM machines m
       LEFT JOIN shifts s ON s.machine_id=m.id AND s.date>=$1 AND s.date<=$2
       LEFT JOIN production_entries pe ON pe.shift_id=s.id
       LEFT JOIN stoppages st ON st.shift_id=s.id
       WHERE m.active=1
       GROUP BY m.id,m.name,m.type ORDER BY m.name`,
      [from, to]
    );
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// REPORTS
const REPORT_COLS = `s.id,s.date,s.shift_number,s.start_time,s.end_time,s.status,
  op.name as operator_name,m.name as machine_name,m.type as machine_type,
  po.order_number,r.code as ref_code,r.name as ref_name,c.name as color_name,
  COALESCE(SUM(pe.rolls_bundles),0) as total_rolls,
  COALESCE(SUM(pe.meters_pieces),0) as total_meters,
  COALESCE(SUM(pe.pieces_ok),0) as total_pieces_ok,
  COALESCE(SUM(pe.rejected+pe.pieces_rejected),0) as total_rejected,
  COALESCE(SUM(st.duration_minutes),0) as total_stop_min`;

const REPORT_FROM = `FROM shifts s
  LEFT JOIN operators op ON s.operator_id=op.id
  LEFT JOIN machines m ON s.machine_id=m.id
  LEFT JOIN production_orders po ON s.order_id=po.id
  LEFT JOIN refs r ON po.reference_id=r.id
  LEFT JOIN colors c ON po.color_id=c.id
  LEFT JOIN production_entries pe ON pe.shift_id=s.id
  LEFT JOIN stoppages st ON st.shift_id=s.id`;

// ANALYTICS (EfficiencyPage)
app.get('/api/analytics', admin, async (req, res) => {
  try {
    const from = req.query.date_from || new Date(Date.now()-30*86400000).toLocaleDateString('sv-SE',{timeZone:'Europe/Lisbon'});
    const to   = req.query.date_to   || todayStr();
    const [efficiencyEntries, qualityByMachine, workerPerf] = await Promise.all([
      q(`SELECT pe.id, s.date, s.shift_number, pe.start_time, pe.end_time,
           pe.counter, pe.pieces_ok, pe.pieces_rejected,
           op.name as operator_name, m.name as machine_name, m.type as machine_type,
           NULL::REAL as cycle_time_seconds
         FROM production_entries pe
         JOIN shifts s ON pe.shift_id=s.id
         JOIN machines m ON s.machine_id=m.id
         JOIN operators op ON s.operator_id=op.id
         WHERE s.date>=$1 AND s.date<=$2 AND m.type='injecao'
         ORDER BY s.date, s.shift_number`, [from, to]),
      q(`SELECT m.id, m.name as machine_name, m.type as machine_type,
           COALESCE(SUM(pe.pieces_ok + pe.rolls_bundles),0) as total_ok,
           COALESCE(SUM(pe.pieces_rejected + pe.rejected),0) as total_rejected
         FROM machines m
         LEFT JOIN shifts s ON s.machine_id=m.id AND s.date>=$1 AND s.date<=$2
         LEFT JOIN production_entries pe ON pe.shift_id=s.id
         WHERE m.active=1
         GROUP BY m.id, m.name, m.type ORDER BY m.name`, [from, to]),
      q(`SELECT op.id, op.name as operator_name, op.number as operator_number,
           COUNT(DISTINCT s.id) as shift_count,
           COALESCE(SUM(pe.pieces_ok),0) as total_ok,
           COALESCE(SUM(pe.pieces_rejected),0) as total_rejected
         FROM operators op
         JOIN shifts s ON s.operator_id=op.id AND s.date>=$1 AND s.date<=$2
         JOIN machines m ON s.machine_id=m.id
         LEFT JOIN production_entries pe ON pe.shift_id=s.id
         WHERE m.type='injecao'
         GROUP BY op.id, op.name, op.number ORDER BY total_ok DESC`, [from, to])
    ]);
    res.json({ efficiencyEntries, qualityByMachine, workerPerf });
  } catch(e) { res.status(500).json({ error: dbErr(e) }); }
});

// PRODUCTION PROGRESS (ProductionAnalysisPage)
app.get('/api/production-progress', admin, async (req, res) => {
  try {
    const to   = todayStr();
    const from = new Date(Date.now()-14*86400000).toLocaleDateString('sv-SE',{timeZone:'Europe/Lisbon'});
    const [daily, stopReasons, orderDaily, orders] = await Promise.all([
      q(`SELECT s.date,
           COALESCE(SUM(CASE WHEN m.type='extrusao' THEN pe.meters_pieces ELSE 0 END),0) as ext_meters,
           COALESCE(SUM(CASE WHEN m.type='injecao' THEN pe.pieces_ok ELSE 0 END),0) as inj_pieces,
           COALESCE(SUM(pe.rejected + pe.pieces_rejected),0) as rejected
         FROM shifts s
         JOIN machines m ON s.machine_id=m.id
         LEFT JOIN production_entries pe ON pe.shift_id=s.id
         WHERE s.date>=$1 AND s.date<=$2
         GROUP BY s.date ORDER BY s.date`, [from, to]),
      q(`SELECT sc.code, sc.description, COUNT(*) as cnt, COALESCE(SUM(st.duration_minutes),0) as total_min
         FROM stoppages st
         JOIN stoppage_codes sc ON st.stoppage_code_id=sc.id
         JOIN shifts s ON st.shift_id=s.id
         WHERE s.date>=$1 AND s.date<=$2
         GROUP BY sc.code, sc.description ORDER BY total_min DESC LIMIT 10`, [from, to]),
      q(`SELECT po.order_number, s.date,
           COALESCE(SUM(CASE WHEN m.type='extrusao' THEN pe.meters_pieces ELSE pe.pieces_ok END),0) as produced
         FROM production_orders po
         JOIN shifts s ON s.order_id=po.id
         JOIN machines m ON s.machine_id=m.id
         LEFT JOIN production_entries pe ON pe.shift_id=s.id
         WHERE s.date>=$1 AND s.date<=$2 AND po.status IN ('active','pending')
         GROUP BY po.order_number, s.date ORDER BY s.date`, [from, to]),
      q(`SELECT po.id, po.order_number, po.quantity, po.unit, po.status,
           r.code as ref_code, r.name as ref_name,
           COALESCE(SUM(CASE WHEN m.type='extrusao' THEN pe.meters_pieces ELSE pe.pieces_ok END),0) as produced,
           COALESCE(SUM(CASE WHEN s.date=$3 THEN CASE WHEN m.type='extrusao' THEN pe.meters_pieces ELSE pe.pieces_ok END ELSE 0 END),0) as produced_today,
           COALESCE(SUM(CASE WHEN st2.shift_id IS NOT NULL AND s.date=$3 THEN st2.duration_minutes ELSE 0 END),0) as stop_min_today,
           COUNT(DISTINCT CASE WHEN s.status='open' THEN s.id END) as open_shifts
         FROM production_orders po
         LEFT JOIN refs r ON po.reference_id=r.id
         LEFT JOIN shifts s ON s.order_id=po.id
         LEFT JOIN machines m ON s.machine_id=m.id
         LEFT JOIN production_entries pe ON pe.shift_id=s.id
         LEFT JOIN stoppages st2 ON st2.shift_id=s.id
         WHERE po.status IN ('active','pending')
         GROUP BY po.id, po.order_number, po.quantity, po.unit, po.status, r.code, r.name
         ORDER BY po.order_number`, [from, to, to])
    ]);
    res.json({ daily, stopReasons, orderDaily, orders });
  } catch(e) { res.status(500).json({ error: dbErr(e) }); }
});

app.get('/api/reports', admin, async (req, res) => {
  try {
    let where = ' WHERE 1=1';
    const p = [];
    if (req.query.from)        { where += ` AND s.date>=$${p.length+1}`;          p.push(req.query.from); }
    if (req.query.to)          { where += ` AND s.date<=$${p.length+1}`;          p.push(req.query.to); }
    if (req.query.machine_id)  { where += ` AND s.machine_id=$${p.length+1}`;     p.push(req.query.machine_id); }
    if (req.query.operator_id) { where += ` AND s.operator_id=$${p.length+1}`;    p.push(req.query.operator_id); }
    if (req.query.reference_id){ where += ` AND po.reference_id=$${p.length+1}`;  p.push(req.query.reference_id); }
    const perPage = Math.min(Number(req.query.per_page)||50, 200);
    const page    = Math.max(Number(req.query.page)||1, 1);
    const countRow = await q1(`SELECT COUNT(DISTINCT s.id) as n ${REPORT_FROM}${where}`, p);
    const total = Number(countRow.n);
    const pages = Math.ceil(total/perPage)||1;
    const rows = await q(`SELECT ${REPORT_COLS} ${REPORT_FROM}${where} GROUP BY s.id,op.name,m.name,m.type,po.order_number,r.code,r.name,c.name ORDER BY s.date DESC,s.id DESC LIMIT $${p.length+1} OFFSET $${p.length+2}`, [...p, perPage, (page-1)*perPage]);
    res.json({ rows, total, page, pages, per_page: perPage });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/reports/export', admin, async (req, res) => {
  try {
    let sql = `SELECT ${REPORT_COLS} ${REPORT_FROM} WHERE 1=1`;
    const p = [];
    if (req.query.from)        { sql += ` AND s.date>=$${p.length+1}`;          p.push(req.query.from); }
    if (req.query.to)          { sql += ` AND s.date<=$${p.length+1}`;          p.push(req.query.to); }
    if (req.query.machine_id)  { sql += ` AND s.machine_id=$${p.length+1}`;     p.push(req.query.machine_id); }
    if (req.query.operator_id) { sql += ` AND s.operator_id=$${p.length+1}`;    p.push(req.query.operator_id); }
    if (req.query.reference_id){ sql += ` AND po.reference_id=$${p.length+1}`;  p.push(req.query.reference_id); }
    sql += ' GROUP BY s.id,op.name,m.name,m.type,po.order_number,r.code,r.name,c.name ORDER BY s.date,s.id';
    const rows = await q(sql, p);
    const headers = ['Data','Turno','Operador','Maquina','Tipo','Ordem','Referencia','Cor','Rolos/Atados','Metros/Pecas','Pecas OK','Rejeitados','Paragens (min)'];
    const lines = rows.map(r => [
      r.date, r.shift_number, r.operator_name||'', r.machine_name||'', r.machine_type||'',
      r.order_number||'', r.ref_code||'', r.color_name||'',
      r.total_rolls, r.total_meters, r.total_pieces_ok, r.total_rejected, r.total_stop_min
    ].map(v => `"${String(v).replace(/"/g,'""')}"`).join(';'));
    const csv = '\uFEFF' + [headers.join(';'), ...lines].join('\r\n');
    res.setHeader('Content-Type','text/csv; charset=utf-8');
    res.setHeader('Content-Disposition',`attachment; filename="producao_${todayStr()}.csv"`);
    res.send(csv);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// AUDIT LOG
app.get('/api/audit-log', admin, async (req, res) => {
  try {
    let sql = 'SELECT * FROM audit_log WHERE 1=1';
    const p = [];
    const whereClause = 'FROM audit_log WHERE 1=1' + (req.query.from ? ` AND created_at::date>=$${p.length+1}` : '');
    if (req.query.from) { sql += ` AND created_at::date>=$${p.length+1}`; p.push(req.query.from); }
    if (req.query.to)   { sql += ` AND created_at::date<=$${p.length+1}`; p.push(req.query.to); }
    const page = Math.max(1, Number(req.query.page)||1);
    const perPage = Math.min(200, Number(req.query.per_page)||100);
    const offset = (page - 1) * perPage;
    const countP = [...p];
    const countRow = await q1(`SELECT COUNT(*) as n FROM audit_log WHERE 1=1${req.query.from?' AND created_at::date>=$1':''}${req.query.to?' AND created_at::date<=$'+(countP.length+1):''}`, countP);
    const total = Number(countRow?.n || 0);
    sql += ` ORDER BY created_at DESC LIMIT ${perPage} OFFSET ${offset}`;
    res.json({ rows: await q(sql, p), total, page, pages: Math.ceil(total/perPage) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// AUTH
app.post('/api/auth/operator', loginLimiter, async (req, res) => {
  try {
    const { number, pin } = req.body;
    const op = await q1('SELECT * FROM operators WHERE number=$1 AND active=1', [number]);
    if (!op) return res.status(401).json({ error: 'Operador não encontrado' });
    const ok = await bcrypt.compare(String(pin), op.pin_hash);
    if (!ok) return res.status(401).json({ error: 'PIN incorreto' });
    const token = jwt.sign({ id: op.id, name: op.name, number: op.number, role: op.role||'operator' }, JWT_SECRET, { expiresIn: '12h' });
    await logAudit('LOGIN', 'operator', op.id, { id: op.id, name: op.name, role: op.role||'operator' });
    res.json({ token, operator: { id: op.id, name: op.name, number: op.number, role: op.role||'operator' } });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/admin', loginLimiter, async (req, res) => {
  try {
    const { password } = req.body;
    // ADMIN_PASSWORD env var always works as emergency override
    const envPass = process.env.ADMIN_PASSWORD;
    if (envPass && password === envPass) {
      const token = jwt.sign({ id: 0, name: 'Admin', role: 'admin' }, JWT_SECRET, { expiresIn: '8h' });
      await logAudit('LOGIN', 'admin', null, { id: 0, name: 'Admin', role: 'admin', via: 'env_override' });
      return res.json({ token });
    }
    const setting = await q1("SELECT value FROM app_settings WHERE key='admin_password_hash'");
    let ok = false;
    if (setting) {
      ok = await bcrypt.compare(password, setting.value);
    } else {
      ok = (password === 'admin123');
      if (ok) {
        await pool.query("INSERT INTO app_settings(key,value) VALUES('admin_password_hash',$1) ON CONFLICT(key) DO UPDATE SET value=$1,updated_at=NOW()", [bcrypt.hashSync(password, 10)]);
      }
    }
    if (!ok) return res.status(401).json({ error: 'Palavra-passe incorreta' });
    const token = jwt.sign({ id: 0, name: 'Admin', role: 'admin' }, JWT_SECRET, { expiresIn: '8h' });
    await logAudit('LOGIN', 'admin', null, { id: 0, name: 'Admin', role: 'admin' });
    res.json({ token });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/auth/admin/password', loginLimiter, admin, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;
    if (!new_password || new_password.length < 6) return res.status(400).json({ error: 'A nova palavra-passe deve ter pelo menos 6 caracteres' });
    const setting = await q1("SELECT value FROM app_settings WHERE key='admin_password_hash'");
    let ok = false;
    if (setting) {
      ok = await bcrypt.compare(current_password, setting.value);
    } else {
      ok = (current_password === (process.env.ADMIN_PASSWORD || 'admin123'));
    }
    if (!ok) return res.status(401).json({ error: 'Palavra-passe atual incorreta' });
    const newHash = bcrypt.hashSync(new_password, 10);
    await pool.query("INSERT INTO app_settings(key,value) VALUES('admin_password_hash',$1) ON CONFLICT(key) DO UPDATE SET value=$1,updated_at=NOW()", [newHash]);
    await logAudit('ADMIN_PASSWORD_CHANGED', 'admin', null, { id: 0, name: 'Admin', role: 'admin' });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// SETTINGS
app.get('/api/settings', admin, async (req, res) => {
  try { res.json(await q('SELECT key,value,updated_at FROM app_settings')); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

// HEALTH CHECK
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', ts: new Date().toISOString() });
});

// STARTUP
initDB()
  .then(() => {
    app.listen(PORT, () => {
      console.log('Servidor a correr em http://localhost:' + PORT);
      if (JWT_SECRET === 'producao-secret-2024-change-me') console.warn('⚠️  AVISO: JWT_SECRET não definido! Define a variável de ambiente JWT_SECRET no Render.');
      if (!ENCRYPTION_KEY) console.warn('⚠️  AVISO: ENCRYPTION_KEY não definido. PINs dos operadores guardados sem encriptação.');
    });
  })
  .catch(err => { console.error('Falha ao inicializar a BD:', err); process.exit(1); });

