const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const db = require('../database/db');
const { validateLogin, validateRegister } = require('../middleware/validate');

const SALT_ROUNDS = 10;

// ── Login ──
router.post('/login', validateLogin, async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

    if (!user) {
      return res.render('login', { errors: ['Invalid username or password'], values: { username } });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.render('login', { errors: ['Invalid username or password'], values: { username } });
    }

    // Create session
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.role = user.role;

    req.session.save((saveErr) => {
      if (saveErr) {
        console.error('Session save error:', saveErr);
        return res.render('login', { errors: ['Session error. Please try again.'], values: { username } });
      }
      res.redirect('/admin');
    });
  } catch (err) {
    console.error('Login error:', err);
    res.render('login', { errors: ['An error occurred. Please try again.'], values: {} });
  }
});

// ── Register ──
router.post('/register', validateRegister, async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Check if username or email already exists
    const existing = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(username, email);
    if (existing) {
      return res.render('register', {
        errors: ['Username or email already exists'],
        values: { username, email }
      });
    }

    const totalUsers = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
    let role = 'viewer';
    if (totalUsers === 0) {
      role = 'admin';
    } else if (req.body.inviteCode && process.env.ADMIN_INVITE_CODE && req.body.inviteCode.trim() === process.env.ADMIN_INVITE_CODE) {
      role = 'admin';
    } else if (req.session && req.session.userId && req.session.role === 'admin') {
      role = req.body.role === 'admin' ? 'admin' : 'viewer';
    }

    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    db.prepare('INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)').run(username, email, hash, role);

    // Auto-login after registration
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.role = user.role;

    req.session.save((saveErr) => {
      if (saveErr) {
        console.error('Session save error:', saveErr);
        return res.render('register', { errors: ['Session error. Please try again.'], values: {} });
      }
      res.redirect('/admin');
    });
  } catch (err) {
    console.error('Register error:', err);
    res.render('register', { errors: ['An error occurred. Please try again.'], values: {} });
  }
});

// ── Logout ──
router.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

module.exports = router;
