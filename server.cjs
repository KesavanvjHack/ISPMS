const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const app = express();

app.use(cors());
app.use(express.json());

// ✅ MySQL DB connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '', // default for XAMPP
  database: 'connectisp', // make sure this DB exists in phpMyAdmin
});

// ✅ Registration route
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  // Check if user already exists
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (results.length > 0) {
      return res.status(400).json({ error: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user with default role 'user'
    db.query(
      'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
      [name, email, hashedPassword, 'user'],
      (err, result) => {
        if (err) return res.status(500).json({ error: 'Failed to register user' });
        return res.status(201).json({ message: 'User registered successfully', name });
      }
    );
  });
});

// ✅ Login route
app.post('/api/login', (req, res) => {
  const { email, password, role } = req.body;

  if (!email || !password || !role) {
    return res.status(400).json({ error: 'Missing credentials' });
  }

  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });

    const user = results[0];
    if (!user) return res.status(400).json({ error: 'User not found' });

    if (user.role && role !== user.role) {
      return res.status(403).json({ error: 'Role mismatch' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid password' });

    res.json({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      token: null // add JWT later if needed
    });
  });
});

// ✅ Start server
app.listen(5000, () => {
  console.log('Server running on http://localhost:5000');
});
