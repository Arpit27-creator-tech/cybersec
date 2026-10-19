require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const helmet = require('helmet');
const crypto = require('crypto');
const db = require('./database/db');
const { injectUser } = require('./middleware/auth');
const csrfProtection = require('./middleware/csrf');
const { authLimiter, aiLimiter, formLimiter } = require('./middleware/rateLimiter');
const SqliteSessionStore = require('./middleware/sessionStore');

// Route imports (all defined at top of file)
const pagesRouter = require('./routes/pages');
const authRouter = require('./routes/auth');
const contactRouter = require('./routes/contact');
const newsletterRouter = require('./routes/newsletter');
const adminRouter = require('./routes/admin');
const emailScannerRouter = require('./routes/emailScanner');
const aiChatRouter = require('./routes/aiChat');
const extensionApiRouter = require('./routes/extensionApi');
const emailWriterRouter = require('./routes/emailWriterApi');

const app = express();
const PORT = process.env.PORT || 3000;

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Security & Helmet (configured to allow CDN videos and fonts)
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        scriptSrcAttr: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        styleSrcAttr: ["'self'", "'unsafe-inline'"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:", "https:"],
        mediaSrc: ["'self'", "https://d8j0ntlcm91z4.cloudfront.net"],
        connectSrc: ["'self'"],
      },
    },
  })
);

// Body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Static files (single mapping to avoid duplicate routes)
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration
const sessionStore = new SqliteSessionStore();

// Fallback session secret generator (non-predictable secure random)
let sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret) {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('SESSION_SECRET environment variable is strictly required in production mode');
  }
  console.warn('⚠️ Warning: SESSION_SECRET is not set in .env. Generating random runtime secret.');
  sessionSecret = crypto.randomBytes(32).toString('hex');
}

app.use(
  session({
    store: sessionStore,
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production'
    }
  })
);

// Inject user session into all views
app.use(injectUser);

// CSRF Protection middleware for state-changing forms and actions
app.use(csrfProtection);

// Mount routes with rate limiters
app.use('/', pagesRouter);
app.use('/', emailScannerRouter);
app.use('/auth', authLimiter, authRouter);
app.use('/api/contact', formLimiter, contactRouter);
app.use('/api/newsletter', formLimiter, newsletterRouter);
app.use('/api/ai-chat', aiLimiter, aiChatRouter);
app.use('/api/extension', extensionApiRouter);
app.use('/api/classifier', extensionApiRouter);
app.use('/api/writer', emailWriterRouter);
app.use('/', emailWriterRouter);
app.use('/admin', adminRouter);

// 404 handler
app.use((req, res) => {
  if (req.xhr || req.headers.accept?.includes('application/json')) {
    return res.status(404).json({ error: 'Endpoint not found' });
  }
  res.status(404).render('404');
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal Server Error' });
});

const { initBackgroundScanner } = require('./services/backgroundScanner');

// Start server
app.listen(PORT, () => {
  console.log(`🚀 CyberSec full-stack CRM running at http://localhost:${PORT}`);
  initBackgroundScanner();
});

module.exports = app;
