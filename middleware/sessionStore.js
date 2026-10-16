const session = require('express-session');
const db = require('../database/db');

class SqliteSessionStore extends session.Store {
  constructor(options = {}) {
    super();
    this.db = db;
    // Cleanup expired sessions every 15 minutes
    this.cleanupInterval = setInterval(() => {
      try {
        const now = Date.now();
        this.db.prepare('DELETE FROM sessions WHERE expired_at < ?').run(now);
      } catch (err) {
        console.error('Session cleanup error:', err);
      }
    }, options.cleanupIntervalMs || 900000);
    this.cleanupInterval.unref();
  }

  get(sid, callback) {
    try {
      const now = Date.now();
      const row = this.db.prepare('SELECT sess FROM sessions WHERE sid = ? AND expired_at >= ?').get(sid, now);
      if (!row) return callback(null, null);
      const data = JSON.parse(row.sess);
      return callback(null, data);
    } catch (err) {
      return callback(err);
    }
  }

  set(sid, sess, callback) {
    try {
      const maxAge = sess.cookie?.maxAge || 1000 * 60 * 60 * 24 * 7;
      const expiredAt = Date.now() + maxAge;
      const sessStr = JSON.stringify(sess);

      this.db.prepare(`
        INSERT INTO sessions (sid, sess, expired_at)
        VALUES (?, ?, ?)
        ON CONFLICT(sid) DO UPDATE SET sess = excluded.sess, expired_at = excluded.expired_at
      `).run(sid, sessStr, expiredAt);

      if (callback) callback(null);
    } catch (err) {
      if (callback) callback(err);
    }
  }

  destroy(sid, callback) {
    try {
      this.db.prepare('DELETE FROM sessions WHERE sid = ?').run(sid);
      if (callback) callback(null);
    } catch (err) {
      if (callback) callback(err);
    }
  }

  touch(sid, sess, callback) {
    try {
      const maxAge = sess.cookie?.maxAge || 1000 * 60 * 60 * 24 * 7;
      const expiredAt = Date.now() + maxAge;
      this.db.prepare('UPDATE sessions SET expired_at = ? WHERE sid = ?').run(expiredAt, sid);
      if (callback) callback(null);
    } catch (err) {
      if (callback) callback(err);
    }
  }
}

module.exports = SqliteSessionStore;
