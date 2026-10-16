const express = require('express');
const router = express.Router();
const db = require('../database/db');
const { validateContact } = require('../middleware/validate');

// ── Submit contact form ──
router.post('/', validateContact, (req, res) => {
  try {
    const { name, email, company, phone, message, source } = req.body;

    db.prepare(`
      INSERT INTO contacts (name, email, company, phone, message, source)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(name, email, company || null, phone || null, message, source || 'contact_form');

    // Check if they also want newsletter
    if (req.body.newsletter) {
      try {
        db.prepare('INSERT OR IGNORE INTO newsletter_subscribers (email) VALUES (?)').run(email);
      } catch (_) { /* ignore duplicate */ }
    }

    // If request wants JSON
    if (req.headers.accept?.includes('application/json') || req.xhr) {
      return res.json({ success: true, message: 'Your message has been sent. We\'ll be in touch shortly.' });
    }

    // Otherwise render contact page with success
    res.render('contact', {
      success: 'Your message has been sent. We\'ll be in touch shortly.',
      errors: null,
      values: {},
      source: source || 'contact_form'
    });
  } catch (err) {
    console.error('Contact submission error:', err);
    if (req.headers.accept?.includes('application/json')) {
      return res.status(500).json({ error: 'Failed to submit. Please try again.' });
    }
    res.render('contact', {
      success: null,
      errors: ['Failed to submit. Please try again.'],
      values: req.body,
      source: req.body.source || 'contact_form'
    });
  }
});

module.exports = router;
