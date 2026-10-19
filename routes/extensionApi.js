const express = require('express');
const router = express.Router();
const db = require('../database/db');
const { scanEmailThreats } = require('../services/threatScanner');
const crypto = require('crypto');

// ── CORS & Security Preflight Middleware for Extension ──
router.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  next();
});

/**
 * Health & connection check for Chrome Extension
 * GET /api/extension/status
 */
router.get('/status', (req, res) => {
  try {
    const totalScans = db.prepare('SELECT COUNT(*) as count FROM email_scans').get()?.count || 0;
    const threatsBlocked = db.prepare("SELECT COUNT(*) as count FROM email_scans WHERE threat_level IN ('high', 'critical') OR is_phishing = 1").get()?.count || 0;

    res.json({
      online: true,
      service: 'CyberSec Email Threat Radar',
      version: '1.0.0',
      systemTime: new Date().toISOString(),
      stats: {
        totalScans,
        threatsBlocked
      }
    });
  } catch (err) {
    res.json({
      online: true,
      service: 'CyberSec Email Threat Radar',
      version: '1.0.0',
      stats: { totalScans: 0, threatsBlocked: 0 }
    });
  }
});

/**
 * Scan email ingested directly from Gmail Chrome Extension
 * POST /api/extension/scan
 */
router.post('/scan', express.json({ limit: '5mb' }), (req, res) => {
  try {
    const {
      sender = '',
      senderName = '',
      recipient = 'me@gmail.com',
      subject = '',
      bodyText = '',
      bodyHtml = '',
      links = [],
      attachments = [],
      headers = {}
    } = req.body;

    if (!bodyText && !subject && !sender) {
      return res.status(400).json({
        success: false,
        error: 'Missing email content. Please provide subject, bodyText, or sender.'
      });
    }

    const cleanSender = String(sender).trim() || 'unknown@external.com';
    const cleanName = String(senderName).trim();
    const cleanSubject = String(subject).trim() || '(No Subject)';
    const cleanBody = String(bodyText).trim();

    // Map attachments if passed
    const normalizedAttachments = Array.isArray(attachments)
      ? attachments.map(a => typeof a === 'string' ? { filename: a, contentType: 'application/octet-stream', size: 0 } : a)
      : [];

    // Run deep heuristic and pattern threat analysis
    const threatReport = scanEmailThreats({
      sender: cleanSender,
      sender_name: cleanName,
      recipient,
      subject: cleanSubject,
      body_text: cleanBody,
      body_html: bodyHtml,
      headers: headers || {},
      attachments: normalizedAttachments
    });

    // Generate unique scan tracking ID
    const msgHash = crypto.createHash('md5').update(`${cleanSender}:${cleanSubject}:${cleanBody.substring(0, 100)}`).digest('hex').substring(0, 12);
    const scanId = `ext-gmail-${Date.now()}-${msgHash}`;

    // Associate with the primary connected account or standalone extension scans
    const primaryAccount = db.prepare('SELECT id FROM email_accounts ORDER BY id ASC LIMIT 1').get();
    const accountId = primaryAccount ? primaryAccount.id : null;

    // Persist into database for audit logs and forensic reporting
    db.prepare(`
      INSERT INTO email_scans (
        account_id, message_id, thread_id, sender, sender_name, recipient,
        subject, date, snippet, body_text, summary, threat_score, threat_level,
        is_phishing, phishing_reasons, malicious_links, suspicious_attachments,
        leaked_secrets, auth_issues, classification_category, classification_confidence,
        classification_details, scanned_at
      ) VALUES (
        ?, ?, 'chrome-extension', ?, ?, ?,
        ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, CURRENT_TIMESTAMP
      )
      ON CONFLICT(message_id) DO UPDATE SET
        threat_score = excluded.threat_score,
        threat_level = excluded.threat_level,
        is_phishing = excluded.is_phishing,
        summary = excluded.summary,
        classification_category = excluded.classification_category,
        classification_confidence = excluded.classification_confidence,
        classification_details = excluded.classification_details,
        scanned_at = CURRENT_TIMESTAMP
    `).run(
      accountId,
      scanId,
      cleanSender,
      cleanName,
      recipient,
      cleanSubject,
      cleanBody.substring(0, 150),
      cleanBody.substring(0, 4000),
      threatReport.summary,
      threatReport.threat_score,
      threatReport.threat_level,
      threatReport.is_phishing,
      threatReport.phishing_reasons,
      threatReport.malicious_links,
      threatReport.suspicious_attachments,
      threatReport.leaked_secrets,
      threatReport.auth_issues,
      threatReport.classification_category || 'legitimate',
      threatReport.classification_confidence || 0,
      threatReport.classification_details || '{}'
    );

    // Parse summary object if needed
    let parsedSummary = {};
    try {
      parsedSummary = typeof threatReport.summary === 'string'
        ? JSON.parse(threatReport.summary)
        : (threatReport.summary || {});
    } catch (_) {
      parsedSummary = { verdict: threatReport.summary };
    }

    res.json({
      success: true,
      scanId,
      threatScore: threatReport.threat_score,
      threatLevel: threatReport.threat_level,
      isPhishing: Boolean(threatReport.is_phishing),
      classification: threatReport.classification,
      phishingReasons: JSON.parse(threatReport.phishing_reasons || '[]'),
      maliciousLinks: JSON.parse(threatReport.malicious_links || '[]'),
      suspiciousAttachments: JSON.parse(threatReport.suspicious_attachments || '[]'),
      leakedSecrets: JSON.parse(threatReport.leaked_secrets || '[]'),
      authIssues: JSON.parse(threatReport.auth_issues || '[]'),
      summary: parsedSummary,
      reportUrl: `http://localhost:3000/admin/email-scanner/report/${scanId}`
    });
  } catch (err) {
    console.error('Extension scan error:', err);
    res.status(500).json({
      success: false,
      error: 'Analysis engine error: ' + err.message
    });
  }
});

/**
 * Reveal extension folder in native macOS Finder
 * POST /api/extension/reveal-finder
 */
router.post('/reveal-finder', (req, res) => {
  const { exec } = require('child_process');
  const path = require('path');
  const manifestPath = path.join(__dirname, '..', 'extension', 'manifest.json');
  exec(`open -R "${manifestPath}"`, (err) => {
    if (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
    res.json({ success: true, folder: path.join(__dirname, '..', 'extension') });
  });
});

/**
 * Public Classifier API - Classify Email Text / Payload
 * POST /api/classifier/classify
 */
router.post('/classify', express.json(), (req, res) => {
  try {
    const { classifyEmail } = require('../services/emailClassifier');
    const { subject = '', body = '', bodyText = '', body_text = '', sender = '', senderName = '', sender_name = '', recipient = '', attachments = [], links = [], headers = {} } = req.body;
    const result = classifyEmail({
      subject,
      body_text: body || bodyText || body_text,
      body: body || bodyText || body_text,
      sender,
      sender_name: senderName || sender_name,
      recipient,
      attachments,
      links,
      headers
    });
    res.json({ success: true, classification: result, result: result });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * Get Classifier Metadata & Categories
 * GET /api/classifier/categories
 */
router.get('/categories', (req, res) => {
  const { CATEGORIES, BENCHMARK_EMAILS } = require('../services/emailClassifier');
  res.json({ success: true, categories: CATEGORIES, benchmarks: BENCHMARK_EMAILS });
});

module.exports = router;
