const express = require('express');
const router = express.Router();
const db = require('../database/db');

// ── Landing page ──
router.get('/', (req, res) => {
  const stats = db.prepare('SELECT * FROM site_stats ORDER BY display_order ASC').all();
  res.render('landing', { stats });
});

// ── Contact page ──
router.get('/contact', (req, res) => {
  const source = req.query.source || 'contact_form';
  res.render('contact', { source, success: null, errors: null, values: {} });
});

// ── Login page ──
router.get('/login', (req, res) => {
  if (req.session?.userId) return res.redirect('/admin');
  res.render('login', { errors: null, values: {} });
});

// ── Register page ──
router.get('/register', (req, res) => {
  if (req.session?.userId) return res.redirect('/admin');
  res.render('register', { errors: null, values: {} });
});

module.exports = router;
