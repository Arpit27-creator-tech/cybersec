const express = require('express');
const router = express.Router();
const db = require('../database/db');
const { validateNewsletter } = require('../middleware/validate');

// ── Subscribe to newsletter ──
router.post('/', validateNewsletter, (req, res) => {
  try {
    const { email } = req.body;

    const existing = db.prepare('SELECT id, is_active FROM newsletter_subscribers WHERE email = ?').get(email);

    if (existing && existing.is_active) {
      return res.json({ success: true, message: 'You\'re already subscribed!' });
    }

    if (existing && !existing.is_active) {
      // Re-activate
      db.prepare('UPDATE newsletter_subscribers SET is_active = 1, subscribed_at = CURRENT_TIMESTAMP WHERE id = ?').run(existing.id);
      return res.json({ success: true, message: 'Welcome back! You\'ve been re-subscribed.' });
    }

    db.prepare('INSERT INTO newsletter_subscribers (email) VALUES (?)').run(email);
    res.json({ success: true, message: 'Successfully subscribed to our newsletter!' });
  } catch (err) {
    console.error('Newsletter subscription error:', err);
    res.status(500).json({ error: 'Failed to subscribe. Please try again.' });
  }
});

module.exports = router;
