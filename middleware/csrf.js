const crypto = require('crypto');

/**
 * Custom robust CSRF protection middleware for Express sessions
 */
function csrfProtection(req, res, next) {
  // Ensure session has a secure random CSRF token
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }

  // Expose token to all templates
  res.locals.csrfToken = req.session.csrfToken;

  // Safe HTTP methods don't require CSRF verification
  const method = req.method.toUpperCase();
  if (['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    return next();
  }

  // Exempt public stateless API routes that do not rely on cookie session authentication
  if (req.path.startsWith('/api/')) {
    return next();
  }

  // Exempt external OAuth redirect callback
  if (req.path === '/auth/google/callback') {
    return next();
  }

  // Extract token from form body or HTTP headers
  const token =
    req.body?._csrf ||
    req.headers['x-csrf-token'] ||
    req.headers['csrf-token'] ||
    req.headers['x-xsrf-token'];

  if (!token || token !== req.session.csrfToken) {
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      return res.status(403).json({ error: 'Invalid or missing CSRF token' });
    }
    return res.status(403).render('login', {
      errors: ['Session expired or invalid CSRF token. Please log in again.'],
      values: {}
    });
  }

  next();
}

module.exports = csrfProtection;
