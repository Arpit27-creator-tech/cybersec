const rateLimit = require('express-rate-limit');

// Rate limiter for authentication routes (login / register brute-force protection)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // Limit each IP to 20 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many authentication attempts from this IP, please try again after 15 minutes.'
  },
  handler: (req, res, next, options) => {
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      return res.status(429).json(options.message);
    }
    return res.status(429).render('login', {
      errors: ['Too many authentication attempts. Please try again after 15 minutes.'],
      values: {}
    });
  }
});

// Rate limiter for AI Chat & Content Scanning APIs
const aiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 60, // Limit each IP to 60 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'AI query rate limit exceeded. Please wait a few moments before trying again.'
  }
});

// Rate limiter for public forms (contact and newsletter)
const formLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 25, // Limit each IP to 25 form submissions per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many requests. Please try again later.'
  }
});

module.exports = {
  authLimiter,
  aiLimiter,
  formLimiter
};
