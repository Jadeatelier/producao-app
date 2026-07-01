const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const JWT_SECRET = process.env.JWT_SECRET || 'producao-secret-2024-change-me';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const PORT = process.env.PORT || 3000;

if (!process.env.JWT_SECRET || !process.env.ADMIN_PASSWORD) {
  console.warn('⚠️  AVISO: Definir JWT_SECRET e ADMIN_PASSWORD como variáveis de ambiente no Render!');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const q  = (sql, params = []) => pool.query(sql, params).then(r => r.rows);
const q1 = (sql, params = []) => pool.query(sql, params).then(r => r.rows[0] || null);

// Rate limiting em memória para o login
const _loginAttempts = {};
setInterval(() => {
  const now = Date.now();
  for (const k in _loginAttempts) {
    if (_loginAttempts[k].resetAt < now) delete _loginAttempts[k];
  }
}, 60000);
function checkRateLimit(key) {
  const now = Date.now();
  if (!_loginAttempts[key] || _loginAttempts[key].resetAt < now) {
    _loginAttempts[key] = { count: 1, resetAt: now + 15 * 60 * 1000 };
    return false;
  }
  _loginAttempts[key].count++;
  return _loginAttempts[key].count > 5;
}
function clearRateLimit(key) { delete _loginAttempts[key]; }

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
  `);

  await pool.query(`ALTER TABLE operators ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'operator'`);
  await pool.query(`ALTER TABLE production_orders ADD COLUMN IF NOT EXISTS cycle_time_seconds INTEGER DEFAULT 0`);
  await pool.query(`ALTER TABLE production_entries ADD COLUMN IF NOT EXISTS start_time TEXT`);
  await pool.query(`ALTER TABLE production_entries ADD COLUMN IF NOT EXISTS end_time TEXT`);
  await pool.query(`ALTER TABLE production_entries ADD COLUMN IF NOT EXISTS validated INTEGER DEFAULT 0`);
  await pool.query(`ALTER TABLE production_entries ADD COLUMN IF NOT EXISTS validated_by TEXT`);
  await pool.query(`ALTER TABLE production_entries ADD COLUMN IF NOT EXISTS validated_at TIMESTAMP`);

  const { rows } = await pool.query('SELECT COUNT(*) as c FROM machines');
  if (parseInt(rows[0].c) === 0) {
    await pool.query(`
      INSERT INTO machines (name,type,has_weighing) VALUES
        ('Extrusao 1','extrusao',0),('Extrusao 2','extrusao',1),('Extrusao 3','extrusao',0),
        ('Injecao 1','injecao',0),('Injecao 2','injecao',0),('Injecao 3','injecao',0)
    `);
    await pool.query(`
      INSERT INTO stoppage_codes (code,description,category) VALUES
        ('01','Mudanca de cor','Producao'),('02','Mudanca de referencia','Producao'),
        ('03','Regulacao / Afinacao','Producao'),('04','Avaria mecanica','Avaria'),
        ('05','Avaria eletrica','Avaria'),('06','Limpeza de maquina','Manutencao'),
        ('07','Manutencao preventiva','Manutencao'),('08','Falta de materia-prima','Material'),
        ('09','Pausa / Intervalo','Pessoal'),('10','Falta de energia','Infraestrutura'),
        ('11','Troca de molde','Producao'),('99','Outros','Geral')
    `);
    const pin_hash = bcrypt.hashSync('1234', 10);
    await pool.query('INSERT INTO operators (name,number,pin_hash) VALUES ($1,$2,$3)',
      ['Operador Demo', '001', pin_hash]);
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
function quality(req, res, next) {
  const token = req.headers.authorization && req.headers.authorization.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Sem autorizacao' });
  try {
    const u = jwt.verify(token, JWT_SECRET);
    if (u.role !== 'quality' && u.role !== 'admin') return res.status(403).json({ error: 'Sem permissao' });
    req.user = u; next();
  } catch(e) { res.status(401).json({ error: 'Token invalido' }); }
}

// AUTH
app.post('/api/auth/operator', async (req, res) => {
  try {
    const { number, pin } = req.body;
    if (!number || !pin) return res.status(400).json({ error: 'Numero e PIN obrigatorios' });
    if (checkRateLimit(`op:${number}`))
      return res.status(429).json({ error: 'Muitas tentativas falhadas. Aguarde 15 minutos.' });
    const op = await q1('SELECT * FROM operators WHERE number=$1 AND active=1', [number]);
    if (!op || !bcrypt.compareSync(pin, op.pin_hash))
      return res.status(401).json({ error: 'Numero ou PIN incorretos' });
    clearRateLimit(`op:${number}`);
    const role = op.role || 'operator';
    const token = jwt.sign({ id: op.id, name: op.name, number: op.number, role }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token, operator: { id: op.id, name: op.name, number: op.number, role } });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/admin', (req, res) => {
  if (req.body.password !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Password incorreta' });
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '8h' });
  res.json({ token });
});

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
  try { res.json(await q('SELECT name, number FROM operators WHERE active=1 ORDER BY name')); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/operators', admin, async (req, res) => {
  try { res.json(await q('SELECT id,name,number,role,active,created_at FROM operators ORDER BY name')); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/operators', admin, async (req, res) => {
  try {
    const b = req.body;
    const r = await q1('INSERT INTO operators(name,number,pin_hash,role) VALUES($1,$2,$3,$4) RETURNING id',
      [b.name, b.number, bcrypt.hashSync(String(b.pin), 10), b.role||'operator']);
    res.json({ id: r.id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/operators/:id', admin, async (req, res) => {
  try {
    const b = req.body;
    if (b.pin) {
      await pool.query('UPDATE operators SET name=$1,number=$2,pin_hash=$3,role=$4,active=$5 WHERE id=$6',
        [b.name, b.number, bcrypt.hashSync(String(b.pin),10), b.role||'operator', b.active?1:0, req.params.id]);
    } else {
      await pool.query('UPDATE operators SET name=$1,number=$2,role=$3,active=$4 WHERE id=$5',
        [b.name, b.number, b.role||'operator', b.active?1:0, req.params.id]);
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// REFERENCES
app.get('/api/references', auth, async (req, res) => {
  try {
    const mt = req.query.machine_type;
    if (mt) res.json(await q('SELECT * FROM refs WHERE active=1 AND machine_type=$1 ORDER BY code', [mt]));
    else    res.json(await q('SELECT * FROM refs WHERE active=1 ORDER BY code'));
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
    const used = await q1('SELECT COUNT(*) as cnt FROM production_orders WHERE reference_id=$1', [req.params.id]);
    if (Number(used?.cnt) > 0) return res.status(400).json({ error: 'Referência em uso por ordens de produção — não pode ser eliminada.' });
    await pool.query('DELETE FROM refs WHERE id=$1', [req.params.id]);
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
    if (req.query.status)     { sql += ` AND po.status=$${p.length+1}`; p.push(req.query.status); }
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
app.post('/api/orders', admin, async (req, res) => {
  try {
    const b = req.body;
    const r = await q1('INSERT INTO production_orders(order_number,reference_id,color_id,machine_id,quantity,unit,mp_phases,cycle_time_seconds,notes) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id',
      [b.order_number, b.reference_id||null, b.color_id||null, b.machine_id||null, b.quantity||null, b.unit||'pecas', JSON.stringify(b.mp_phases||[]), b.cycle_time_seconds||0, b.notes||null]);
    res.json({ id: r.id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/orders/:id', admin, async (req, res) => {
  try {
    const b = req.body;
    await pool.query('UPDATE production_orders SET order_number=$1,reference_id=$2,color_id=$3,machine_id=$4,quantity=$5,unit=$6,mp_phases=$7,cycle_time_seconds=$8,notes=$9,status=$10 WHERE id=$11',
      [b.order_number, b.reference_id||null, b.color_id||null, b.machine_id||null, b.quantity||null, b.unit||'pecas', JSON.stringify(b.mp_phases||[]), b.cycle_time_seconds||0, b.notes||null, b.status||'active', req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

function currentShift() {
  const h = new Date().getHours();
  if (h >= 8 && h < 17) return 1;
  if (h >= 17 || h === 0) return 2;
  return 3;
}
function todayStr() { return new Date().toISOString().split('T')[0]; }
function nowTime()  { return new Date().toTimeString().slice(0,5); }

const SHIFT_COLS = `s.*,op.name as operator_name,op.number as operator_number,
  po.order_number,po.quantity,po.unit,po.status as order_status,
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
    // Procura turno aberto mais recente (sem filtrar por data/shift — evita bug de meia-noite)
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
    if (req.query.date)       { sql += ` AND s.date=$${p.length+1}`; p.push(req.query.date); }
    if (req.query.date_from)  { sql += ` AND s.date>=$${p.length+1}`; p.push(req.query.date_from); }
    if (req.query.date_to)    { sql += ` AND s.date<=$${p.length+1}`; p.push(req.query.date_to); }
    if (req.query.machine_id) { sql += ` AND s.machine_id=$${p.length+1}`; p.push(req.query.machine_id); }
    sql += ' ORDER BY s.date DESC,s.shift_number';
    res.json(await q(sql, p));
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/shifts/:id', auth, async (req, res) => {
  try {
    const shift = await q1('SELECT ' + SHIFT_COLS + ' WHERE s.id=$1', [req.params.id]);
    if (!shift) return res.status(404).json({ error: 'Turno nao encontrado' });
    const entries   = await q('SELECT * FROM production_entries WHERE shift_id=$1 ORDER BY created_at', [req.params.id]);
    const stoppages = await q(
      'SELECT st.*,sc.code as stop_code,sc.description as stop_desc,sc.category FROM stoppages st LEFT JOIN stoppage_codes sc ON st.stoppage_code_id=sc.id WHERE st.shift_id=$1 ORDER BY st.created_at',
      [req.params.id]
    );
    const weighing = await q('SELECT * FROM weighing_records WHERE shift_id=$1 ORDER BY rolo_number,created_at', [req.params.id]);
    // Totais acumulados da ORDEM (todos os turnos, não apenas o atual)
    const orderTotals = shift.order_id ? await q1(
      `SELECT COALESCE(SUM(pe.meters_pieces),0) as total_meters,
              COALESCE(SUM(pe.pieces_ok),0) as total_pieces_ok,
              COALESCE(SUM(pe.rolls_bundles),0) as total_rolls
       FROM production_entries pe
       JOIN shifts s2 ON pe.shift_id=s2.id
       WHERE s2.order_id=$1`,
      [shift.order_id]
    ) : null;
    res.json(Object.assign({}, shift, { entries, stoppages, weighing, orderTotals }));
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/shifts', auth, async (req, res) => {
  try {
    const order = await q1("SELECT * FROM production_orders WHERE id=$1 AND status='active'", [req.body.order_id]);
    if (!order) return res.status(400).json({ error: 'Ordem nao encontrada ou nao ativa' });
    const existing = await q1("SELECT id FROM shifts WHERE machine_id=$1 AND status='open' ORDER BY created_at DESC LIMIT 1",
      [req.body.machine_id]);
    if (existing) return res.json({ id: existing.id, resumed: true });
    // shift_number pode vir do cliente (operador escolheu); fallback para detecção automática por hora
    const shiftNum = [1,2,3].includes(Number(req.body.shift_number)) ? Number(req.body.shift_number) : currentShift();
    const r = await q1('INSERT INTO shifts(order_id,operator_id,machine_id,shift_number,date,start_time) VALUES($1,$2,$3,$4,$5,$6) RETURNING id',
      [req.body.order_id, req.user.id, req.body.machine_id, shiftNum, todayStr(), nowTime()]);
    res.json({ id: r.id, resumed: false });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/shifts/:id/close', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      const shift = await q1('SELECT id FROM shifts WHERE id=$1 AND operator_id=$2', [req.params.id, req.user.id]);
      if (!shift) return res.status(403).json({ error: 'Sem permissao para fechar este turno' });
    }
    await pool.query("UPDATE shifts SET status='closed',end_time=$1,notes=$2 WHERE id=$3",
      [nowTime(), (req.body && req.body.notes)||null, req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// PRODUCTION ENTRIES
app.post('/api/production-entries', auth, async (req, res) => {
  try {
    const b = req.body;
    const pieces_ok       = Math.max(0, Number(b.pieces_ok)||0);
    const pieces_rejected = Math.max(0, Number(b.pieces_rejected)||0);
    const rolls_bundles   = Math.max(0, Number(b.rolls_bundles)||0);
    const meters_pieces   = Math.max(0, Number(b.meters_pieces)||0);
    const rejected        = Math.max(0, Number(b.rejected)||0);
    const counter         = (b.counter !== null && b.counter !== '') ? Math.max(0, Number(b.counter)) : null;
    const active_cavities = b.active_cavities ? Math.max(0, Number(b.active_cavities)) : null;
    const r = await q1(
      'INSERT INTO production_entries(shift_id,color,rolls_bundles,meters_pieces,rejected,active_cavities,counter,pieces_ok,pieces_rejected,finishing,start_time,end_time,notes) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id,created_at',
      [b.shift_id, b.color||null, rolls_bundles, meters_pieces, rejected, active_cavities, counter, pieces_ok, pieces_rejected, b.finishing||null, b.start_time||null, b.end_time||null, b.notes||null]
    );
    res.json({ id: r.id, created_at: r.created_at });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/production-entries/:id', quality, async (req, res) => {
  try {
    const b = req.body;
    await pool.query('UPDATE production_entries SET color=$1,rolls_bundles=$2,meters_pieces=$3,rejected=$4,active_cavities=$5,counter=$6,pieces_ok=$7,pieces_rejected=$8,finishing=$9,start_time=$10,end_time=$11,notes=$12 WHERE id=$13',
      [b.color||null, Math.max(0,Number(b.rolls_bundles)||0), Math.max(0,Number(b.meters_pieces)||0), Math.max(0,Number(b.rejected)||0), b.active_cavities?Math.max(0,Number(b.active_cavities)):null, (b.counter!==''&&b.counter!==null)?Math.max(0,Number(b.counter)):null, Math.max(0,Number(b.pieces_ok)||0), Math.max(0,Number(b.pieces_rejected)||0), b.finishing||null, b.start_time||null, b.end_time||null, b.notes||null, req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/production-entries/:id/validate', quality, async (req, res) => {
  try {
    const by = req.user.name ? `${req.user.name} (#${req.user.number})` : 'Qualidade';
    await pool.query('UPDATE production_entries SET validated=1,validated_by=$1,validated_at=NOW() WHERE id=$2', [by, req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/production-entries/:id/unvalidate', quality, async (req, res) => {
  try {
    await pool.query('UPDATE production_entries SET validated=0,validated_by=NULL,validated_at=NULL WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/production-entries/:id', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin' && req.user.role !== 'quality') {
      const entry = await q1(
        `SELECT pe.id FROM production_entries pe JOIN shifts s ON pe.shift_id=s.id WHERE pe.id=$1 AND s.operator_id=$2`,
        [req.params.id, req.user.id]
      );
      if (!entry) return res.status(403).json({ error: 'Sem permissao para apagar este registo' });
    }
    await pool.query('DELETE FROM production_entries WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// QUALITY
app.get('/api/quality/shifts', quality, async (req, res) => {
  try {
    const date = req.query.date || todayStr();
    const shifts = await q(`SELECT ${SHIFT_COLS} WHERE s.date=$1 ORDER BY m.type,m.name,s.shift_number`, [date]);
    const result = [];
    for (const s of shifts) {
      const entries = await q('SELECT * FROM production_entries WHERE shift_id=$1 ORDER BY id', [s.id]);
      result.push({...s, entries});
    }
    res.json(result);
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
    if (req.user.role !== 'admin' && req.user.role !== 'quality') {
      const rec = await q1(
        `SELECT wr.id FROM weighing_records wr JOIN shifts s ON wr.shift_id=s.id WHERE wr.id=$1 AND s.operator_id=$2`,
        [req.params.id, req.user.id]
      );
      if (!rec) return res.status(403).json({ error: 'Sem permissao para apagar esta pesagem' });
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
    if (req.user.role !== 'admin' && req.user.role !== 'quality') {
      const stop = await q1(
        `SELECT st.id FROM stoppages st JOIN shifts s ON st.shift_id=s.id WHERE st.id=$1 AND s.operator_id=$2`,
        [req.params.id, req.user.id]
      );
      if (!stop) return res.status(403).json({ error: 'Sem permissao para apagar esta paragem' });
    }
    await pool.query('DELETE FROM stoppages WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// DASHBOARD
app.get('/api/dashboard', admin, async (req, res) => {
  try {
    const t = todayStr();
    const weekStart = new Date();
    weekStart.setDate(weekStart.getDate() - 6);
    const ws = weekStart.toISOString().split('T')[0];
    const [todayProd, todayStops, machines, topStops, daily, stopCats] = await Promise.all([
      q1('SELECT SUM(pe.rolls_bundles) as total_rolls,SUM(pe.meters_pieces) as total_meters,SUM(pe.pieces_ok) as total_pieces_ok,SUM(pe.rejected+pe.pieces_rejected) as total_rejected,COUNT(DISTINCT s.id) as shift_count FROM production_entries pe JOIN shifts s ON pe.shift_id=s.id WHERE s.date=$1', [t]),
      q1('SELECT SUM(st.duration_minutes) as total_min,COUNT(*) as count FROM stoppages st JOIN shifts s ON st.shift_id=s.id WHERE s.date=$1', [t]),
      q("SELECT m.id,m.name,m.type,s.id as shift_id,s.shift_number,s.status,s.start_time,op.name as operator_name,po.order_number,r.code as ref_code FROM machines m LEFT JOIN shifts s ON s.machine_id=m.id AND s.date=$1 AND s.status='open' LEFT JOIN operators op ON s.operator_id=op.id LEFT JOIN production_orders po ON s.order_id=po.id LEFT JOIN refs r ON po.reference_id=r.id WHERE m.active=1 ORDER BY m.type,m.name", [t]),
      q('SELECT sc.code,sc.description,sc.category,COUNT(*) as cnt,SUM(st.duration_minutes) as total_min FROM stoppages st JOIN stoppage_codes sc ON st.stoppage_code_id=sc.id JOIN shifts s ON st.shift_id=s.id WHERE s.date>=$1 GROUP BY sc.id,sc.code,sc.description,sc.category ORDER BY total_min DESC LIMIT 8', [ws]),
      q("SELECT s.date,SUM(CASE WHEN m.type='extrusao' THEN pe.rolls_bundles ELSE 0 END) as ext_rolls,SUM(CASE WHEN m.type='extrusao' THEN pe.meters_pieces ELSE 0 END) as ext_meters,SUM(CASE WHEN m.type='injecao' THEN pe.pieces_ok ELSE 0 END) as inj_pieces FROM shifts s JOIN machines m ON s.machine_id=m.id LEFT JOIN production_entries pe ON pe.shift_id=s.id WHERE s.date>=$1 GROUP BY s.date ORDER BY s.date", [ws]),
      q('SELECT sc.category,SUM(st.duration_minutes) as total_min FROM stoppages st JOIN stoppage_codes sc ON st.stoppage_code_id=sc.id JOIN shifts s ON st.shift_id=s.id WHERE s.date>=$1 GROUP BY sc.category ORDER BY total_min DESC', [ws])
    ]);
    res.json({ todayProd, todayStops, machines, topStops, daily, stopCats });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// REPORTS
app.get('/api/reports', admin, async (req, res) => {
  try {
    let sql = `SELECT s.id,s.date,s.shift_number,s.start_time,s.end_time,s.status,
      m.name as machine_name,m.type as machine_type,
      op.name as operator_name,op.number as operator_number,
      po.order_number,r.id as reference_id,r.code as ref_code,r.name as ref_name,
      SUM(pe.rolls_bundles) as total_rolls,SUM(pe.meters_pieces) as total_meters,
      SUM(pe.pieces_ok) as total_pieces_ok,SUM(pe.rejected+pe.pieces_rejected) as total_rejected,
      (SELECT SUM(st2.duration_minutes) FROM stoppages st2 WHERE st2.shift_id=s.id) as stop_min,
      (SELECT COUNT(*) FROM stoppages st3 WHERE st3.shift_id=s.id) as stop_count
      FROM shifts s
      JOIN machines m ON s.machine_id=m.id
      LEFT JOIN operators op ON s.operator_id=op.id
      LEFT JOIN production_orders po ON s.order_id=po.id
      LEFT JOIN refs r ON po.reference_id=r.id
      LEFT JOIN production_entries pe ON pe.shift_id=s.id
      WHERE 1=1`;
    const p = [];
    if (req.query.date_from)    { sql += ` AND s.date>=$${p.length+1}`; p.push(req.query.date_from); }
    if (req.query.date_to)      { sql += ` AND s.date<=$${p.length+1}`; p.push(req.query.date_to); }
    if (req.query.machine_id)   { sql += ` AND s.machine_id=$${p.length+1}`; p.push(req.query.machine_id); }
    if (req.query.reference_id) { sql += ` AND po.reference_id=$${p.length+1}`; p.push(req.query.reference_id); }
    sql += ' GROUP BY s.id,m.name,m.type,op.name,op.number,po.order_number,r.id,r.code,r.name ORDER BY s.date DESC,s.shift_number';
    res.json(await q(sql, p));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ANALYTICS
app.get('/api/analytics', admin, async (req, res) => {
  try {
    const df = req.query.date_from || new Date(Date.now()-30*24*60*60*1000).toISOString().slice(0,10);
    const dt = req.query.date_to   || todayStr();
    const [qualityByMachine, qualityByOrder, workerPerf, efficiencyEntries] = await Promise.all([
      q(`SELECT m.id,m.name as machine_name,m.type as machine_type,
          COALESCE(SUM(CASE WHEN m.type='injecao' THEN pe.pieces_ok ELSE pe.meters_pieces END),0) as total_ok,
          COALESCE(SUM(CASE WHEN m.type='injecao' THEN pe.pieces_rejected ELSE pe.rejected END),0) as total_rejected
         FROM machines m
         LEFT JOIN shifts s ON s.machine_id=m.id AND s.date>=$1 AND s.date<=$2
         LEFT JOIN production_entries pe ON pe.shift_id=s.id
         WHERE m.active=1
         GROUP BY m.id,m.name,m.type ORDER BY m.type,m.name`, [df,dt]),
      q(`SELECT po.order_number,po.cycle_time_seconds,r.code as ref_code,r.name as ref_name,
          m.name as machine_name,m.type as machine_type,
          COALESCE(SUM(CASE WHEN m.type='injecao' THEN pe.pieces_ok ELSE pe.meters_pieces END),0) as total_ok,
          COALESCE(SUM(CASE WHEN m.type='injecao' THEN pe.pieces_rejected ELSE pe.rejected END),0) as total_rejected,
          COUNT(DISTINCT s.id) as shift_count
         FROM production_orders po
         LEFT JOIN machines m ON po.machine_id=m.id
         LEFT JOIN refs r ON po.reference_id=r.id
         LEFT JOIN shifts s ON s.order_id=po.id AND s.date>=$1 AND s.date<=$2
         LEFT JOIN production_entries pe ON pe.shift_id=s.id
         GROUP BY po.id,po.order_number,po.cycle_time_seconds,r.code,r.name,m.name,m.type
         HAVING COUNT(DISTINCT s.id)>0 ORDER BY po.order_number`, [df,dt]),
      q(`SELECT op.id,op.name as operator_name,op.number as operator_number,
          COUNT(DISTINCT s.id) as shift_count,
          COALESCE(SUM(pe.pieces_ok),0) as total_ok,
          COALESCE(SUM(pe.pieces_rejected),0) as total_rejected,
          COALESCE(SUM(pe.counter),0) as total_counter
         FROM operators op
         JOIN shifts s ON s.operator_id=op.id AND s.date>=$1 AND s.date<=$2
         JOIN machines m ON s.machine_id=m.id AND m.type='injecao'
         LEFT JOIN production_entries pe ON pe.shift_id=s.id
         GROUP BY op.id,op.name,op.number ORDER BY total_ok DESC`, [df,dt]),
      q(`SELECT pe.id,pe.counter,pe.pieces_ok,pe.pieces_rejected,pe.start_time,pe.end_time,pe.created_at,
          po.cycle_time_seconds,po.order_number,r.code as ref_code,
          m.name as machine_name,op.name as operator_name,op.number as operator_number,
          s.shift_number,s.date
         FROM production_entries pe
         JOIN shifts s ON pe.shift_id=s.id AND s.date>=$1 AND s.date<=$2
         JOIN production_orders po ON s.order_id=po.id AND po.cycle_time_seconds>0
         JOIN machines m ON s.machine_id=m.id
         LEFT JOIN operators op ON s.operator_id=op.id
         WHERE m.type='injecao'
         ORDER BY s.date DESC,pe.created_at DESC LIMIT 500`, [df,dt])
    ]);
    res.json({ qualityByMachine, qualityByOrder, workerPerf, efficiencyEntries });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// PRODUCTION PROGRESS (admin only)
app.get('/api/production-progress', admin, async (req, res) => {
  try {
    const today = todayStr();
    const since14 = new Date(Date.now()-14*24*60*60*1000).toISOString().slice(0,10);

    const [orders, daily, orderDaily, stopReasons] = await Promise.all([
      // Active orders with cumulative production
      q(`SELECT po.id, po.order_number, po.quantity, po.unit,
            r.code as ref_code, r.name as ref_name,
            c.name as color_name, c.hex_code as hex_color,
            m.name as machine_name,
            COALESCE(SUM(
              CASE WHEN m.type='extrусао' OR m.type='extrusao' THEN pe.meters_pieces
                   ELSE pe.pieces_ok END
            ),0) as produced,
            COALESCE(SUM(
              CASE WHEN m.type='extrusao' THEN pe.rejected
                   ELSE pe.pieces_rejected END
            ),0) as rejected,
            COALESCE(SUM(CASE WHEN s.date=$1 THEN
              CASE WHEN m.type='extrusao' THEN pe.meters_pieces ELSE pe.pieces_ok END
            ELSE 0 END),0) as produced_today,
            COALESCE((SELECT SUM(st.duration_minutes)
              FROM stoppages st JOIN shifts s2 ON st.shift_id=s2.id
              WHERE s2.order_id=po.id AND s2.date=$1),0) as stop_min_today,
            COUNT(DISTINCT s.id) as shift_count,
            MAX(s.date) as last_shift_date,
            COUNT(DISTINCT CASE WHEN s.end_time IS NULL THEN s.id END) as open_shifts
         FROM production_orders po
         JOIN machines m ON po.machine_id=m.id
         LEFT JOIN refs r ON po.reference_id=r.id
         LEFT JOIN colors c ON po.color_id=c.id
         LEFT JOIN shifts s ON s.order_id=po.id
         LEFT JOIN production_entries pe ON pe.shift_id=s.id
         WHERE po.status='active'
         GROUP BY po.id,po.order_number,po.quantity,po.unit,r.code,r.name,c.name,c.hex_code,m.name,m.type
         ORDER BY (CASE WHEN po.quantity>0 THEN
           COALESCE(SUM(CASE WHEN m.type='extrusao' THEN pe.meters_pieces ELSE pe.pieces_ok END),0)::float/po.quantity
           ELSE 0 END) DESC`, [today]),

      // Daily production last 14 days
      q(`SELECT s.date,
            COALESCE(SUM(CASE WHEN m.type='extrusao' THEN pe.meters_pieces ELSE 0 END),0) as ext_meters,
            COALESCE(SUM(CASE WHEN m.type='injecao' THEN pe.pieces_ok ELSE 0 END),0) as inj_pieces,
            COALESCE(SUM(CASE WHEN m.type='injecao' THEN pe.pieces_rejected ELSE pe.rejected END),0) as rejected
         FROM shifts s
         JOIN machines m ON s.machine_id=m.id
         LEFT JOIN production_entries pe ON pe.shift_id=s.id
         WHERE s.date>=$1
         GROUP BY s.date ORDER BY s.date`, [since14]),

      // Per-order daily breakdown
      q(`SELECT po.order_number, s.date,
            COALESCE(SUM(CASE WHEN m.type='extrusao' THEN pe.meters_pieces ELSE pe.pieces_ok END),0) as produced
         FROM production_orders po
         JOIN machines m ON po.machine_id=m.id
         JOIN shifts s ON s.order_id=po.id AND s.date>=$1
         LEFT JOIN production_entries pe ON pe.shift_id=s.id
         WHERE po.status='active'
         GROUP BY po.order_number, s.date ORDER BY s.date`, [since14]),

      // Top stoppage reasons last 14 days
      q(`SELECT sc.code, sc.description, sc.category,
            COUNT(*) as cnt,
            COALESCE(SUM(st.duration_minutes),0) as total_min
         FROM stoppages st
         JOIN stop_codes sc ON st.stop_code_id=sc.id
         JOIN shifts s ON st.shift_id=s.id
         WHERE s.date>=$1
         GROUP BY sc.code, sc.description, sc.category
         ORDER BY total_min DESC LIMIT 10`, [since14])
    ]);

    res.json({ orders, daily, orderDaily, stopReasons });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// SERVE FRONTEND
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
