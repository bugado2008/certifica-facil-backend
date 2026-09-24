const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "troque-esta-chave-em-producao";

app.use(cors());
app.use(express.json());

const dataDir = path.join(__dirname, "data");
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, "certifica.db"));
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('aluno','professor')),
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS classes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT,
  code TEXT NOT NULL UNIQUE,
  teacher_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (teacher_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS class_students (
  class_id INTEGER NOT NULL,
  student_id INTEGER NOT NULL,
  joined_at TEXT NOT NULL,
  PRIMARY KEY (class_id, student_id),
  FOREIGN KEY (class_id) REFERENCES classes(id) ON DELETE CASCADE,
  FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS activities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  class_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  due_date TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (class_id) REFERENCES classes(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  activity_id INTEGER NOT NULL,
  student_id INTEGER NOT NULL,
  answer TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pendente',
  submitted_at TEXT NOT NULL,
  validated_at TEXT,
  UNIQUE(activity_id, student_id),
  FOREIGN KEY (activity_id) REFERENCES activities(id) ON DELETE CASCADE,
  FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS certificates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  student_id INTEGER NOT NULL,
  class_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  hours INTEGER NOT NULL DEFAULT 20,
  qr_token TEXT NOT NULL UNIQUE,
  issued_at TEXT NOT NULL,
  FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (class_id) REFERENCES classes(id) ON DELETE CASCADE
);
`);

function now() {
  return new Date().toISOString();
}

function makeCode() {
  let code;
  do {
    code = Math.random().toString(36).slice(2, 8).toUpperCase();
  } while (db.prepare("SELECT id FROM classes WHERE code = ?").get(code));
  return code;
}

function makeToken() {
  return require("crypto").randomBytes(24).toString("hex");
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Não autenticado." });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Token inválido ou expirado." });
  }
}

function only(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ error: "Acesso não permitido." });
    }
    next();
  };
}

function publicUser(u) {
  return { id: u.id, name: u.name, email: u.email, role: u.role };
}

app.get("/", (req, res) => {
  res.json({
    name: "Certifica Fácil API",
    status: "online",
    version: "1.0.0"
  });
});

app.post("/api/auth/register", (req, res) => {
  const { name, email, password, role } = req.body;

  if (!name || !email || !password || !["aluno", "professor"].includes(role)) {
    return res.status(400).json({ error: "Preencha nome, e-mail, senha e tipo de conta." });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: "A senha deve ter pelo menos 6 caracteres." });
  }

  const normalizedEmail = String(email).trim().toLowerCase();

  if (db.prepare("SELECT id FROM users WHERE email = ?").get(normalizedEmail)) {
    return res.status(409).json({ error: "E-mail já cadastrado." });
  }

  const hash = bcrypt.hashSync(password, 12);
  const result = db.prepare(`
    INSERT INTO users (name, email, password_hash, role, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(name.trim(), normalizedEmail, hash, role, now());

  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(result.lastInsertRowid);
  const token = jwt.sign(publicUser(user), JWT_SECRET, { expiresIn: "7d" });

  res.status(201).json({ token, user: publicUser(user) });
});

app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE email = ?")
    .get(String(email || "").trim().toLowerCase());

  if (!user || !bcrypt.compareSync(password || "", user.password_hash)) {
    return res.status(401).json({ error: "E-mail ou senha incorretos." });
  }

  const token = jwt.sign(publicUser(user), JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, user: publicUser(user) });
});

app.get("/api/me", auth, (req, res) => {
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
  if (!user) return res.status(404).json({ error: "Usuário não encontrado." });
  res.json({ user: publicUser(user) });
});

app.get("/api/classes", auth, (req, res) => {
  let rows;

  if (req.user.role === "professor") {
    rows = db.prepare(`
      SELECT c.*, u.name AS teacher_name,
        (SELECT COUNT(*) FROM class_students cs WHERE cs.class_id = c.id) AS student_count
      FROM classes c
      JOIN users u ON u.id = c.teacher_id
      WHERE c.teacher_id = ?
      ORDER BY c.id DESC
    `).all(req.user.id);
  } else {
    rows = db.prepare(`
      SELECT c.*, u.name AS teacher_name,
        (SELECT COUNT(*) FROM class_students cs WHERE cs.class_id = c.id) AS student_count
      FROM classes c
      JOIN users u ON u.id = c.teacher_id
      JOIN class_students me ON me.class_id = c.id AND me.student_id = ?
      ORDER BY c.id DESC
    `).all(req.user.id);
  }

  res.json({ classes: rows });
});

app.post("/api/classes", auth, only("professor"), (req, res) => {
  const { name, description = "" } = req.body;
  if (!name) return res.status(400).json({ error: "Informe o nome da turma." });

  const result = db.prepare(`
    INSERT INTO classes (name, description, code, teacher_id, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(name.trim(), description.trim(), makeCode(), req.user.id, now());

  res.status(201).json({
    class: db.prepare("SELECT * FROM classes WHERE id = ?").get(result.lastInsertRowid)
  });
});

app.post("/api/classes/join", auth, only("aluno"), (req, res) => {
  const code = String(req.body.code || "").trim().toUpperCase();
  const c = db.prepare("SELECT * FROM classes WHERE code = ?").get(code);

  if (!c) return res.status(404).json({ error: "Turma não encontrada." });

  try {
    db.prepare(`
      INSERT INTO class_students (class_id, student_id, joined_at)
      VALUES (?, ?, ?)
    `).run(c.id, req.user.id, now());
  } catch {
    return res.status(409).json({ error: "Você já está nessa turma." });
  }

  res.json({ message: "Você entrou na turma.", class: c });
});

app.get("/api/classes/:id", auth, (req, res) => {
  const c = db.prepare(`
    SELECT c.*, u.name AS teacher_name
    FROM classes c JOIN users u ON u.id = c.teacher_id
    WHERE c.id = ?
  `).get(req.params.id);

  if (!c) return res.status(404).json({ error: "Turma não encontrada." });

  const allowed = c.teacher_id === req.user.id ||
    !!db.prepare("SELECT 1 FROM class_students WHERE class_id = ? AND student_id = ?")
      .get(c.id, req.user.id);

  if (!allowed) return res.status(403).json({ error: "Você não participa desta turma." });

  const students = db.prepare(`
    SELECT u.id, u.name, u.email
    FROM users u
    JOIN class_students cs ON cs.student_id = u.id
    WHERE cs.class_id = ?
  `).all(c.id);

  res.json({ class: c, students });
});

app.get("/api/classes/:id/activities", auth, (req, res) => {
  const c = db.prepare("SELECT * FROM classes WHERE id = ?").get(req.params.id);
  if (!c) return res.status(404).json({ error: "Turma não encontrada." });

  const allowed = c.teacher_id === req.user.id ||
    !!db.prepare("SELECT 1 FROM class_students WHERE class_id = ? AND student_id = ?")
      .get(c.id, req.user.id);

  if (!allowed) return res.status(403).json({ error: "Acesso negado." });

  const activities = db.prepare(`
    SELECT a.*,
      (SELECT COUNT(*) FROM submissions s WHERE s.activity_id = a.id) AS submissions_count
    FROM activities a
    WHERE a.class_id = ?
    ORDER BY a.id DESC
  `).all(c.id);

  res.json({ activities });
});

app.post("/api/classes/:id/activities", auth, only("professor"), (req, res) => {
  const c = db.prepare("SELECT * FROM classes WHERE id = ?").get(req.params.id);
  if (!c || c.teacher_id !== req.user.id) {
    return res.status(403).json({ error: "Você não é o professor desta turma." });
  }

  const { title, description, dueDate = "" } = req.body;
  if (!title || !description) {
    return res.status(400).json({ error: "Título e descrição são obrigatórios." });
  }

  const result = db.prepare(`
    INSERT INTO activities (class_id, title, description, due_date, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(c.id, title.trim(), description.trim(), dueDate, now());

  res.status(201).json({
    activity: db.prepare("SELECT * FROM activities WHERE id = ?").get(result.lastInsertRowid)
  });
});

app.post("/api/activities/:id/submit", auth, only("aluno"), (req, res) => {
  const activity = db.prepare("SELECT * FROM activities WHERE id = ?").get(req.params.id);
  if (!activity) return res.status(404).json({ error: "Atividade não encontrada." });

  const member = db.prepare(`
    SELECT 1 FROM class_students WHERE class_id = ? AND student_id = ?
  `).get(activity.class_id, req.user.id);

  if (!member) return res.status(403).json({ error: "Você não está nesta turma." });

  const answer = String(req.body.answer || "").trim();
  if (!answer) return res.status(400).json({ error: "Digite uma resposta." });

  try {
    db.prepare(`
      INSERT INTO submissions
      (activity_id, student_id, answer, status, submitted_at)
      VALUES (?, ?, ?, 'pendente', ?)
    `).run(activity.id, req.user.id, answer, now());
  } catch {
    return res.status(409).json({ error: "Você já entregou esta atividade." });
  }

  res.status(201).json({ message: "Atividade enviada." });
});

app.get("/api/activities/:id/submissions", auth, only("professor"), (req, res) => {
  const activity = db.prepare(`
    SELECT a.*, c.teacher_id
    FROM activities a JOIN classes c ON c.id = a.class_id
    WHERE a.id = ?
  `).get(req.params.id);

  if (!activity || activity.teacher_id !== req.user.id) {
    return res.status(403).json({ error: "Acesso negado." });
  }

  const submissions = db.prepare(`
    SELECT s.*, u.name AS student_name, u.email AS student_email
    FROM submissions s
    JOIN users u ON u.id = s.student_id
    WHERE s.activity_id = ?
    ORDER BY s.id DESC
  `).all(activity.id);

  res.json({ submissions });
});

app.post("/api/submissions/:id/validate", auth, only("professor"), (req, res) => {
  const submission = db.prepare(`
    SELECT s.*, a.class_id, c.teacher_id, c.name AS class_name
    FROM submissions s
    JOIN activities a ON a.id = s.activity_id
    JOIN classes c ON c.id = a.class_id
    WHERE s.id = ?
  `).get(req.params.id);

  if (!submission || submission.teacher_id !== req.user.id) {
    return res.status(403).json({ error: "Acesso negado." });
  }

  const validatedAt = now();

  db.prepare(`
    UPDATE submissions SET status = 'validada', validated_at = ?
    WHERE id = ?
  `).run(validatedAt, submission.id);

  let cert = db.prepare(`
    SELECT * FROM certificates
    WHERE student_id = ? AND class_id = ?
  `).get(submission.student_id, submission.class_id);

  if (!cert) {
    const result = db.prepare(`
      INSERT INTO certificates
      (student_id, class_id, title, hours, qr_token, issued_at)
      VALUES (?, ?, ?, 20, ?, ?)
    `).run(
      submission.student_id,
      submission.class_id,
      submission.class_name,
      makeToken(),
      validatedAt
    );
    cert = db.prepare("SELECT * FROM certificates WHERE id = ?").get(result.lastInsertRowid);
  }

  res.json({ message: "Atividade validada e certificado liberado.", certificate: cert });
});

app.get("/api/certificates", auth, (req, res) => {
  const certificates = db.prepare(`
    SELECT c.*, u.name AS student_name, cl.name AS teacher_class_name,
           t.name AS teacher_name
    FROM certificates c
    JOIN users u ON u.id = c.student_id
    JOIN classes cl ON cl.id = c.class_id
    JOIN users t ON t.id = cl.teacher_id
    WHERE c.student_id = ?
    ORDER BY c.id DESC
  `).all(req.user.id);

  res.json({ certificates });
});

app.get("/api/certificates/public/:token", (req, res) => {
  const c = db.prepare(`
    SELECT c.id, c.title, c.hours, c.issued_at, c.qr_token,
           u.name AS student_name, t.name AS teacher_name
    FROM certificates c
    JOIN users u ON u.id = c.student_id
    JOIN classes cl ON cl.id = c.class_id
    JOIN users t ON t.id = cl.teacher_id
    WHERE c.qr_token = ?
  `).get(req.params.token);

  if (!c) return res.status(404).json({ error: "Certificado não encontrado." });

  res.json({ certificate: c, valid: true });
});

app.listen(PORT, () => {
  console.log(`Certifica Fácil API rodando na porta ${PORT}`);
});
