/**
 * Input validation helpers
 */

function isValidEmail(email) {
  if (typeof email !== 'string') return false;
  const trimmed = email.trim();
  if (trimmed.length > 254 || trimmed.includes('..')) return false;
  return /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/.test(trimmed);
}

function sanitize(str) {
  if (typeof str !== 'string') return '';
  // Strip control characters while preserving valid input
  return str.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').trim();
}

/**
 * Validate contact form submission
 */
function validateContact(req, res, next) {
  const { name, email, message } = req.body;
  const errors = [];

  if (!name || sanitize(name).length < 2) errors.push('Name is required (min 2 characters)');
  if (!email || !isValidEmail(email)) errors.push('Valid email is required');
  if (!message || sanitize(message).length < 10) errors.push('Message is required (min 10 characters)');

  if (errors.length > 0) {
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      return res.status(400).json({ errors });
    }
    return res.status(400).render('contact', {
      errors,
      values: {
        name: req.body.name || '',
        email: req.body.email || '',
        company: req.body.company || '',
        phone: req.body.phone || '',
        message: req.body.message || ''
      },
      success: null,
      source: req.body.source || 'contact_page'
    });
  }

  // Sanitize inputs
  req.body.name = sanitize(name);
  req.body.email = sanitize(email).toLowerCase();
  req.body.message = sanitize(message);
  if (req.body.company) req.body.company = sanitize(req.body.company);
  if (req.body.phone) req.body.phone = sanitize(req.body.phone);
  if (req.body.source) req.body.source = sanitize(req.body.source);

  next();
}

/**
 * Validate newsletter subscription
 */
function validateNewsletter(req, res, next) {
  const { email } = req.body;

  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ errors: ['Valid email is required'] });
  }

  req.body.email = sanitize(email).toLowerCase();
  next();
}

/**
 * Validate login
 */
function validateLogin(req, res, next) {
  const { username, password } = req.body;
  const errors = [];

  if (!username || sanitize(username).length < 2) errors.push('Username is required');
  if (!password || password.length < 6) errors.push('Password must be at least 6 characters');

  if (errors.length > 0) {
    if (req.headers.accept?.includes('application/json')) {
      return res.status(400).json({ errors });
    }
    return res.render('login', { errors, values: { username } });
  }

  req.body.username = sanitize(username);
  next();
}

/**
 * Validate registration
 */
function validateRegister(req, res, next) {
  const { username, email, password, confirmPassword } = req.body;
  const errors = [];

  if (!username || sanitize(username).length < 3) errors.push('Username must be at least 3 characters');
  if (!email || !isValidEmail(email)) errors.push('Valid email is required');
  if (!password || password.length < 8) errors.push('Password must be at least 8 characters');
  if (password !== confirmPassword) errors.push('Passwords do not match');

  if (errors.length > 0) {
    if (req.headers.accept?.includes('application/json')) {
      return res.status(400).json({ errors });
    }
    return res.render('register', { errors, values: { username, email } });
  }

  req.body.username = sanitize(username);
  req.body.email = sanitize(email).toLowerCase();
  next();
}

module.exports = { validateContact, validateNewsletter, validateLogin, validateRegister, sanitize, isValidEmail };
