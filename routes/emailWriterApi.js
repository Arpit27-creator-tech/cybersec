const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const { requireAuth, requireAdmin } = require('../middleware/auth');
const {
  generateEmail,
  PURPOSES,
  TONES,
  AUDIENCES,
  LENGTHS
} = require('../services/emailWriter');

// ══════════════════════════════════════════════════════════════
// ── PUBLIC / CHROME EXTENSION API ENDPOINTS ──
// ══════════════════════════════════════════════════════════════

// CORS & Preflight middleware for Chrome extension & cross-origin requests
router.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, X-CSRF-Token');
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  next();
});

/**
 * Public Endpoint: Generate Email
 * POST /api/writer/generate
 */
router.post('/generate', express.json(), async (req, res) => {
  try {
    const result = await generateEmail(req.body);
    res.json({
      success: true,
      email: result
    });
  } catch (err) {
    console.error('AI Email Writer API error:', err);
    res.status(500).json({
      success: false,
      error: err.message || 'Email generation failed'
    });
  }
});

/**
 * Public Endpoint: Get Taxonomy & Presets
 * GET /api/writer/presets
 */
router.get('/presets', (req, res) => {
  res.json({
    success: true,
    purposes: PURPOSES,
    tones: TONES,
    audiences: AUDIENCES,
    lengths: LENGTHS,
    hasGeminiKey: Boolean(process.env.GEMINI_API_KEY),
    hasOpenaiKey: Boolean(process.env.OPENAI_API_KEY)
  });
});

// ══════════════════════════════════════════════════════════════
// ── ADMIN PANEL STUDIO & SETTINGS ROUTES ──
// ══════════════════════════════════════════════════════════════

/**
 * View AI Email Writer Studio
 * GET /admin/email-writer
 */
router.get('/admin/email-writer', requireAuth, (req, res) => {
  res.render('admin/email-writer', {
    user: req.session,
    purposes: PURPOSES,
    tones: TONES,
    audiences: AUDIENCES,
    lengths: LENGTHS,
    hasGeminiKey: Boolean(process.env.GEMINI_API_KEY),
    hasOpenaiKey: Boolean(process.env.OPENAI_API_KEY),
    geminiKeyMasked: process.env.GEMINI_API_KEY ? maskApiKey(process.env.GEMINI_API_KEY) : '',
    openaiKeyMasked: process.env.OPENAI_API_KEY ? maskApiKey(process.env.OPENAI_API_KEY) : ''
  });
});

/**
 * Admin AJAX: Generate Email with Session CSRF
 * POST /admin/email-writer/generate
 */
router.post('/admin/email-writer/generate', requireAuth, express.json(), async (req, res) => {
  try {
    const result = await generateEmail(req.body);
    res.json({
      success: true,
      email: result
    });
  } catch (err) {
    console.error('Admin Email Writer generation error:', err);
    res.status(500).json({
      success: false,
      error: err.message || 'Generation failed'
    });
  }
});

/**
 * Admin: Configure AI Engine API Keys
 * POST /admin/email-writer/config-keys
 */
router.post('/admin/email-writer/config-keys', requireAuth, requireAdmin, (req, res) => {
  const { geminiApiKey, openaiApiKey } = req.body;

  const envPath = path.join(__dirname, '..', '.env');
  try {
    let envContent = fs.existsSync(envPath) ? fs.readFileSync(envPath, 'utf8') : '';

    function setOrAppend(content, key, val) {
      const reg = new RegExp(`^${key}=.*$`, 'm');
      if (val) {
        if (reg.test(content)) {
          return content.replace(reg, `${key}=${val}`);
        } else {
          return content.trim() + `\n${key}=${val}\n`;
        }
      } else {
        // Remove key if blank
        return content.replace(reg, '').replace(/\n\n+/g, '\n');
      }
    }

    if (geminiApiKey !== undefined) {
      const cleanGemini = geminiApiKey.trim();
      process.env.GEMINI_API_KEY = cleanGemini;
      envContent = setOrAppend(envContent, 'GEMINI_API_KEY', cleanGemini);
    }

    if (openaiApiKey !== undefined) {
      const cleanOpenai = openaiApiKey.trim();
      process.env.OPENAI_API_KEY = cleanOpenai;
      envContent = setOrAppend(envContent, 'OPENAI_API_KEY', cleanOpenai);
    }

    fs.writeFileSync(envPath, envContent.trim() + '\n', 'utf8');

    if (req.xhr || req.headers.accept?.includes('application/json')) {
      return res.json({
        success: true,
        message: 'AI API credentials updated successfully'
      });
    }

    res.redirect('/admin/email-writer?saved=true');
  } catch (err) {
    console.error('Error saving AI keys:', err);
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      return res.status(500).json({ success: false, error: err.message });
    }
    res.redirect('/admin/email-writer?error=' + encodeURIComponent(err.message));
  }
});

function maskApiKey(key) {
  if (!key || key.length < 8) return '••••••••';
  return key.slice(0, 4) + '••••••••' + key.slice(-4);
}

module.exports = router;
