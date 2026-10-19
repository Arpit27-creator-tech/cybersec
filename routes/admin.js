const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const db = require('../database/db');
const { requireAuth, requireAdmin } = require('../middleware/auth');
const { sanitize } = require('../middleware/validate');

// All admin routes require auth
router.use(requireAuth);

// ── Dashboard ──
router.get('/', (req, res) => {
  const totalLeads = db.prepare('SELECT COUNT(*) as count FROM contacts').get().count;
  const newLeads = db.prepare("SELECT COUNT(*) as count FROM contacts WHERE created_at >= datetime('now', '-7 days')").get().count;
  const totalSubscribers = db.prepare('SELECT COUNT(*) as count FROM newsletter_subscribers WHERE is_active = 1').get().count;
  const stats = db.prepare('SELECT * FROM site_stats ORDER BY display_order ASC').all();

  const recentLeads = db.prepare('SELECT * FROM contacts ORDER BY created_at DESC LIMIT 10').all();

  // Status breakdown
  const statusCounts = db.prepare(`
    SELECT status, COUNT(*) as count FROM contacts GROUP BY status
  `).all();
  const statusMap = {};
  statusCounts.forEach(s => { statusMap[s.status] = s.count; });

  res.render('admin/dashboard', {
    totalLeads,
    newLeads,
    totalSubscribers,
    stats,
    recentLeads,
    statusMap
  });
});

// ── Leads ──
router.get('/leads', (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = 20;
  const offset = (page - 1) * limit;
  const status = req.query.status || '';
  const search = req.query.search || '';

  let query = 'SELECT * FROM contacts';
  let countQuery = 'SELECT COUNT(*) as count FROM contacts';
  const params = [];
  const conditions = [];

  if (status) {
    conditions.push('status = ?');
    params.push(status);
  }
  if (search) {
    conditions.push('(name LIKE ? OR email LIKE ? OR company LIKE ?)');
    const s = `%${search}%`;
    params.push(s, s, s);
  }

  if (conditions.length > 0) {
    const where = ' WHERE ' + conditions.join(' AND ');
    query += where;
    countQuery += where;
  }

  const total = db.prepare(countQuery).get(...params).count;
  const totalPages = Math.ceil(total / limit);

  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  const leads = db.prepare(query).all(...params, limit, offset);

  res.render('admin/leads', { leads, page, totalPages, total, status, search });
});

// ── Update lead status ──
router.patch('/leads/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id) || id <= 0) {
    return res.status(400).json({ error: 'Invalid lead ID' });
  }

  const { status } = req.body;
  const validStatuses = ['new', 'contacted', 'qualified', 'closed'];

  if (!validStatuses.includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }

  const existing = db.prepare('SELECT id FROM contacts WHERE id = ?').get(id);
  if (!existing) {
    return res.status(404).json({ error: 'Lead not found' });
  }

  db.prepare('UPDATE contacts SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(status, id);
  res.json({ success: true });
});

// ── Delete lead ──
router.delete('/leads/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id) || id <= 0) {
    return res.status(400).json({ error: 'Invalid lead ID' });
  }

  const existing = db.prepare('SELECT id FROM contacts WHERE id = ?').get(id);
  if (!existing) {
    return res.status(404).json({ error: 'Lead not found' });
  }

  db.prepare('DELETE FROM contacts WHERE id = ?').run(id);
  res.json({ success: true });
});

// ── Newsletter subscribers ──
router.get('/newsletter', (req, res) => {
  const subscribers = db.prepare('SELECT * FROM newsletter_subscribers ORDER BY subscribed_at DESC').all();
  res.render('admin/newsletter', { subscribers });
});

// ── Remove subscriber ──
router.delete('/newsletter/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id) || id <= 0) {
    return res.status(400).json({ error: 'Invalid subscriber ID' });
  }

  const existing = db.prepare('SELECT id FROM newsletter_subscribers WHERE id = ?').get(id);
  if (!existing) {
    return res.status(404).json({ error: 'Subscriber not found' });
  }

  db.prepare('UPDATE newsletter_subscribers SET is_active = 0 WHERE id = ?').run(id);
  res.json({ success: true });
});

// ── Settings page ──
router.get('/settings', (req, res) => {
  const stats = db.prepare('SELECT * FROM site_stats ORDER BY display_order ASC').all();
  const user = db.prepare('SELECT id, username, email FROM users WHERE id = ?').get(req.session.userId);
  res.render('admin/settings', { stats, adminUser: user, success: null, errors: null });
});

// ── Update a stat ──
router.put('/stats/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id) || id <= 0) {
    return res.status(400).json({ error: 'Invalid stat ID' });
  }

  const { stat_value, stat_label } = req.body;

  if (!stat_value || !stat_label) {
    return res.status(400).json({ error: 'Value and label are required' });
  }

  const cleanValue = sanitize(stat_value);
  const cleanLabel = sanitize(stat_label);

  const existing = db.prepare('SELECT id FROM site_stats WHERE id = ?').get(id);
  if (!existing) {
    return res.status(404).json({ error: 'Stat not found' });
  }

  db.prepare('UPDATE site_stats SET stat_value = ?, stat_label = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
    .run(cleanValue, cleanLabel, id);

  res.json({ success: true });
});

// ── Change password ──
router.post('/change-password', async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);

    const errors = [];
    if (!currentPassword) errors.push('Current password is required');
    if (!newPassword || newPassword.length < 8) errors.push('New password must be at least 8 characters');
    if (newPassword !== confirmPassword) errors.push('Passwords do not match');

    if (errors.length > 0) {
      const stats = db.prepare('SELECT * FROM site_stats ORDER BY display_order ASC').all();
      return res.render('admin/settings', { stats, adminUser: user, errors, success: null });
    }

    const valid = await bcrypt.compare(currentPassword, user.password_hash);
    if (!valid) {
      const stats = db.prepare('SELECT * FROM site_stats ORDER BY display_order ASC').all();
      return res.render('admin/settings', { stats, adminUser: user, errors: ['Current password is incorrect'], success: null });
    }

    const hash = await bcrypt.hash(newPassword, 12);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, user.id);

    const stats = db.prepare('SELECT * FROM site_stats ORDER BY display_order ASC').all();
    res.render('admin/settings', { stats, adminUser: user, errors: null, success: 'Password updated successfully' });
  } catch (err) {
    console.error('Change password error:', err);
    const stats = db.prepare('SELECT * FROM site_stats ORDER BY display_order ASC').all();
    const user = db.prepare('SELECT id, username, email FROM users WHERE id = ?').get(req.session.userId);
    res.render('admin/settings', { stats, adminUser: user, errors: ['An error occurred'], success: null });
  }
});

module.exports = router;
