const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const db = new sqlite3.Database('./database.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT,
    phone TEXT,
    message TEXT,
    gender TEXT,
    nationality TEXT,
    selectedCelebrity TEXT,
    submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'new'
  )`);

  const hashed = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10);
  db.run(`INSERT OR IGNORE INTO admins (username, password) VALUES (?,?)`,
    [process.env.ADMIN_USERNAME, hashed]);
});

function auth(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({error: 'No token'});
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({error: 'Invalid token'});
    req.user = user;
    next();
  });
}

app.post('/api/login', (req, res) => {
  const {username, password} = req.body;
  db.get('SELECT * FROM admins WHERE username =?', [username], (err, admin) => {
    if (!admin ||!bcrypt.compareSync(password, admin.password)) {
      return res.status(401).json({error: 'Invalid credentials'});
    }
    const token = jwt.sign({id: admin.id}, process.env.JWT_SECRET, {expiresIn: '24h'});
    res.json({token});
  });
});

app.post('/api/apply', (req, res) => {
  const {name, email, phone, message, gender, nationality, selectedCelebrity} = req.body;
  db.run('INSERT INTO applications (name,email,phone,message,gender,nationality,selectedCelebrity) VALUES (?,?,?,?,?,?,?)',
    [name, email, phone, message, gender, nationality, selectedCelebrity],
    function(err) {
      if (err) return res.status(500).json({error: err.message});
      res.json({success: true});
    }
  );
});

app.get('/api/applications', auth, (req, res) => {
  db.all('SELECT * FROM applications ORDER BY submitted_at DESC', (err, rows) => {
    if (err) return res.status(500).json({error: err.message});
    res.json(rows);
  });
});

app.listen(process.env.PORT, () => console.log('Server running on port', process.env.PORT));

