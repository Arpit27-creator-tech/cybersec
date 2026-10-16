/**
 * Authentication middleware — protects admin routes
 */
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  // For API calls, return JSON error
  if (req.xhr || req.headers.accept?.includes('application/json')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  // For page requests, redirect to login
  return res.redirect('/login');
}

/**
 * Make user data available to all EJS templates
 */
function injectUser(req, res, next) {
  res.locals.user = req.session?.userId
    ? { id: req.session.userId, username: req.session.username, role: req.session.role }
    : null;
  res.locals.path = req.path;
  next();
}

/**
 * Authorization middleware — restricts routes to admin role only
 */
function requireAdmin(req, res, next) {
  if (req.session && req.session.userId && req.session.role === 'admin') {
    return next();
  }
  if (req.xhr || req.headers.accept?.includes('application/json')) {
    return res.status(403).json({ error: 'Admin privileges required' });
  }
  return res.status(403).render('login', {
    errors: ['Access denied: Administrator privileges required.'],
    values: {}
  });
}

module.exports = { requireAuth, requireAdmin, injectUser };
