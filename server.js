const express = require('express');
const session = require('express-session');
const fileUpload = require('express-fileupload');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const app = express();
const dbPath = path.join(__dirname, 'database.sqlite');
console.log("Opening DB at:", dbPath);

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(fileUpload());
app.use(express.static('public'));
app.use(session({
  secret: 'supersecret',
  resave: false,
  saveUninitialized: false
}));

// View Engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ======================= ROUTES =======================

// GET: Register Page
app.get('/register', (req, res) => {
  res.render('register');
});

// POST: Handle Registration
app.post('/register', async (req, res) => {
  const { username, password, firstName, lastName, email, birthDate } = req.body;
  const imageFile = req.files?.image;

  if (!username || !password || !firstName || !lastName || !email || !birthDate || !imageFile) {
    return res.send('Please fill all fields and upload an image.');
  }

  const imageName = `${Date.now()}_${imageFile.name}`;
  const imagePath = path.join(__dirname, 'public', 'uploads', imageName);
  await imageFile.mv(imagePath);

  const hashedPassword = await bcrypt.hash(password, 10);

  const db = new sqlite3.Database(dbPath);
  const query = `INSERT INTO users (username, password, firstName, lastName, email, birthDate, image)
                 VALUES (?, ?, ?, ?, ?, ?, ?)`;

  db.run(query, [username, hashedPassword, firstName, lastName, email, birthDate, imageName], function (err) {
    if (err) {
      console.error("Database error:", err.message);
      return res.send('Database error: ' + err.message);
    }

    res.redirect('/login');
    db.close();
  });
});

// GET: Login Page
app.get('/login', (req, res) => {
  res.render('login');
});

// POST: Handle Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  const db = new sqlite3.Database(dbPath);
  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (err || !user) {
      return res.send('User not found.');
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.send('Invalid password.');
    }

    req.session.user = user;
    res.redirect('/home');
  });

  db.close();
});

// GET: Home Page
app.get('/home', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }

  res.render('home', { user: req.session.user });
});

// GET: Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// ======================= START SERVER =======================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
