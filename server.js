const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const app = express();
app.use(express.json());
app.use(cors());


const dbPath = path.resolve(__dirname, "users.db");
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) console.error("❌ Failed to connect to database:", err);
  else console.log("✅ Connected to SQLite database.");
});


db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL
  )
`);

const ALLOWED_ROLES = [
  "Hospital Admins",
  "Clinic Doctors",
  "Diagnostic Labs",
  "IoT Device Gateways"
];


app.post("/api/auth/signup", async (req, res) => {
  const { email, password, role } = req.body;

  if (!email || !password || !role) {
    return res.status(400).json({ error: "Please provide all fields" });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Invalid email format" });
  }

  if (!ALLOWED_ROLES.includes(role)) {
    return res.status(400).json({ error: "Invalid role" });
  }

  db.get("SELECT * FROM users WHERE email = ? AND role = ?", [email, role], async (err, row) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (row) return res.status(400).json({ error: "This email already has this role" });

    const hashedPass = await bcrypt.hash(password, 10);
    db.run("INSERT INTO users (email, password, role) VALUES (?, ?, ?)", [email, hashedPass, role], function (err) {
      if (err) return res.status(500).json({ error: "Database insert failed" });
      res.json({ message: "User created successfully", user: { email, role } });
    });
  });
});


app.post("/api/auth/login", async (req, res) => {
  const { email, password, role } = req.body;

  if (!email || !password || !role) {
    return res.status(400).json({ error: "Please provide all fields" });
  }

  db.get("SELECT * FROM users WHERE email = ? AND role = ?", [email, role], async (err, user) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (!user) return res.status(400).json({ error: "User with this role not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid password" });

    const token = jwt.sign({ email: user.email, role: user.role }, "secretkey", { expiresIn: "1h" });

    res.json({ message: "Login successful", email: user.email, role: user.role, token });
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✅ Backend running`));
