const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { google } = require('googleapis');
const db = require('../database/db');
const { requireAuth } = require('../middleware/auth');
const {
  getAuthUrl,
  getTokensFromCode,
  getAuthenticatedClient,
  fetchAndScanGmail,
  generateDemoThreatEmails
} = require('../services/gmailService');
const { fetchAndScanImapEmails } = require('../services/imapService');
const { scanEmailThreats } = require('../services/threatScanner');
const { generateForensicReport } = require('../services/forensicReportGenerator');

// ── Encryption helpers for credentials at rest ──
const ENCRYPTION_ALGORITHM = 'aes-256-gcm';

function getEncryptionKey() {
  const secret = process.env.SESSION_SECRET || 'cybersec-secret-super-key-2026';
  return crypto.createHash('sha256').update(secret).digest();
}

function encryptToken(plainText) {
  if (!plainText) return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, getEncryptionKey(), iv);
  let encrypted = cipher.update(plainText, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  return `enc:${iv.toString('hex')}:${authTag}:${encrypted}`;
}

function decryptToken(cipherText) {
  if (!cipherText) return null;
  if (!cipherText.startsWith('enc:')) {
    // Return backward-compatible plaintext if not yet encrypted
    return cipherText;
  }
  try {
    const parts = cipherText.split(':');
    const iv = Buffer.from(parts[1], 'hex');
    const authTag = Buffer.from(parts[2], 'hex');
    const encrypted = parts[3];
    const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, getEncryptionKey(), iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (e) {
    console.error('Decryption failed:', e.message);
    return cipherText;
  }
}

// ── Configure Google OAuth Credentials ──
router.post('/admin/email-scanner/config-oauth', requireAuth, (req, res) => {
  const { clientId, clientSecret, redirectUri } = req.body;

  if (!clientId || !clientSecret) {
    return res.redirect('/admin/email-scanner?oauth_error=' + encodeURIComponent('Client ID and Client Secret are required'));
  }

  const cleanClientId = clientId.trim();
  const cleanClientSecret = clientSecret.trim();
  const cleanRedirectUri = (redirectUri || 'http://localhost:3000/auth/google/callback').trim();

  // Set runtime env
  process.env.GOOGLE_CLIENT_ID = cleanClientId;
  process.env.GOOGLE_CLIENT_SECRET = cleanClientSecret;
  process.env.GOOGLE_REDIRECT_URI = cleanRedirectUri;

  // Persist to .env
  const envPath = path.join(__dirname, '..', '.env');
  try {
    let envContent = fs.existsSync(envPath) ? fs.readFileSync(envPath, 'utf8') : '';
    
    function setOrAppend(content, key, val) {
      const reg = new RegExp(`^${key}=.*$`, 'm');
      if (reg.test(content)) {
        return content.replace(reg, `${key}=${val}`);
      } else {
        return content.trim() + `\n${key}=${val}\n`;
      }
    }

    envContent = setOrAppend(envContent, 'GOOGLE_CLIENT_ID', cleanClientId);
    envContent = setOrAppend(envContent, 'GOOGLE_CLIENT_SECRET', cleanClientSecret);
    envContent = setOrAppend(envContent, 'GOOGLE_REDIRECT_URI', cleanRedirectUri);

    fs.writeFileSync(envPath, envContent.trim() + '\n', 'utf8');
  } catch (envErr) {
    console.error('Error writing .env:', envErr);
  }

  // Redirect to Google OAuth consent screen
  res.redirect('/auth/google');
});

// ── Google OAuth Initiator ──
router.get('/auth/google', requireAuth, (req, res) => {
  const authUrl = getAuthUrl();
  if (!authUrl) {
    return res.redirect('/admin/email-scanner?oauth_error=missing_credentials&show_config=true');
  }
  res.redirect(authUrl);
});

// ── Google OAuth Callback ──
router.get('/auth/google/callback', requireAuth, async (req, res) => {
  const { code, error } = req.query;

  if (error || !code) {
    console.error('Google OAuth error:', error);
    return res.redirect('/admin/email-scanner?oauth_error=' + encodeURIComponent(error || 'Access denied'));
  }

  try {
    const tokens = await getTokensFromCode(code);
    const authClient = getAuthenticatedClient(tokens);

    const gmail = google.gmail({ version: 'v1', auth: authClient });
    const profile = await gmail.users.getProfile({ userId: 'me' });
    const userEmail = profile.data.emailAddress || 'connected_user@gmail.com';

    // Store encrypted token in database
    const encryptedAccessToken = tokens.access_token ? encryptToken(tokens.access_token) : null;
    const existingAccount = db.prepare('SELECT id FROM email_accounts WHERE user_id = ?').get(req.session.userId);
    let accountId;

    if (existingAccount) {
      db.prepare(`
        UPDATE email_accounts SET
          email = ?,
          access_token = ?,
          refresh_token = COALESCE(?, refresh_token),
          token_expiry = ?,
          status = 'connected',
          connected_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).run(userEmail, encryptedAccessToken, tokens.refresh_token || null, tokens.expiry_date || null, existingAccount.id);
      accountId = existingAccount.id;
    } else {
      const info = db.prepare(`
        INSERT INTO email_accounts (user_id, email, access_token, refresh_token, token_expiry, status)
        VALUES (?, ?, ?, ?, ?, 'connected')
      `).run(req.session.userId, userEmail, encryptedAccessToken, tokens.refresh_token || null, tokens.expiry_date || null);
      accountId = Number(info.lastInsertRowid);
    }

    // Run initial scan
    try {
      await fetchAndScanGmail(authClient, accountId, 15);
    } catch (scanErr) {
      console.warn('Initial Gmail scan notice:', scanErr.message);
    }

    res.redirect('/admin/email-scanner?connected=true');
  } catch (err) {
    console.error('OAuth Callback processing error:', err);
    res.redirect('/admin/email-scanner?oauth_error=' + encodeURIComponent(err.message));
  }
});

// ── Main Threat Scanner Dashboard ──
router.get('/admin/email-scanner', requireAuth, (req, res) => {
  const account = db.prepare("SELECT * FROM email_accounts WHERE user_id = ? AND status = 'connected'").get(req.session.userId);
  
  // Filter parameters
  const threatFilter = req.query.filter || 'all';
  const searchQuery = req.query.q || '';

  let query = 'SELECT * FROM email_scans';
  const conditions = [];
  const params = [];

  if (account) {
    conditions.push('(account_id = ? OR account_id IS NULL)');
    params.push(account.id);
  }

  if (threatFilter === 'critical') {
    conditions.push("threat_level = 'critical'");
  } else if (threatFilter === 'high') {
    conditions.push("threat_level IN ('high', 'critical')");
  } else if (threatFilter === 'phishing') {
    conditions.push('is_phishing = 1');
  } else if (threatFilter === 'leaks') {
    conditions.push("leaked_secrets != '[]' AND leaked_secrets IS NOT NULL");
  } else if (threatFilter === 'safe') {
    conditions.push("threat_level = 'safe'");
  }

  if (searchQuery) {
    conditions.push('(subject LIKE ? OR sender LIKE ? OR body_text LIKE ?)');
    const s = `%${searchQuery}%`;
    params.push(s, s, s);
  }

  if (conditions.length > 0) {
    query += ' WHERE ' + conditions.join(' AND ');
  }
  query += ' ORDER BY date DESC, scanned_at DESC LIMIT 50';

  const scans = params.length > 0 ? db.prepare(query).all(...params) : db.prepare(query).all();

  // Overall metrics
  const totalScanned = db.prepare('SELECT COUNT(*) as c FROM email_scans').get().c;
  const criticalCount = db.prepare("SELECT COUNT(*) as c FROM email_scans WHERE threat_level = 'critical'").get().c;
  const highCount = db.prepare("SELECT COUNT(*) as c FROM email_scans WHERE threat_level = 'high'").get().c;
  const phishingCount = db.prepare('SELECT COUNT(*) as c FROM email_scans WHERE is_phishing = 1').get().c;
  const leakCount = db.prepare("SELECT COUNT(*) as c FROM email_scans WHERE leaked_secrets != '[]' AND leaked_secrets IS NOT NULL").get().c;
  const safeCount = db.prepare("SELECT COUNT(*) as c FROM email_scans WHERE threat_level = 'safe'").get().c;

  // Average Threat Index
  const avgRow = db.prepare('SELECT AVG(threat_score) as avgScore FROM email_scans').get();
  const overallRiskScore = avgRow && avgRow.avgScore !== null ? Math.round(avgRow.avgScore) : 0;

  const isOAuthConfigured = Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);

  res.render('admin/email-scanner', {
    account,
    scans,
    metrics: {
      totalScanned,
      criticalCount,
      highCount,
      phishingCount,
      leakCount,
      safeCount,
      overallRiskScore
    },
    threatFilter,
    searchQuery,
    isOAuthConfigured,
    oauthError: req.query.oauth_error || null,
    connectedSuccess: req.query.connected === 'true',
    scannedCount: req.query.scanned ? parseInt(req.query.scanned, 10) : null
  });
});

// ── Connect via Gmail App Password (IMAP) ──
router.post('/admin/email-scanner/connect-imap', requireAuth, async (req, res) => {
  const { email, appPassword } = req.body;

  if (!email || !appPassword) {
    return res.redirect('/admin/email-scanner?oauth_error=' + encodeURIComponent('Gmail address and 16-character App Password are required'));
  }

  const cleanEmail = email.trim().toLowerCase();
  const cleanPass = appPassword.trim().replace(/\s+/g, '');

  if (cleanPass.length < 16) {
    return res.redirect('/admin/email-scanner?oauth_error=' + encodeURIComponent('Google App Passwords are 16 characters long. Generate one at myaccount.google.com/apppasswords'));
  }

  // Encrypt password before storing in database
  const encryptedPassword = encryptToken(cleanPass);
  const existingAccount = db.prepare("SELECT id FROM email_accounts WHERE user_id = ?").get(req.session.userId);
  let accountId;

  if (existingAccount) {
    db.prepare(`
      UPDATE email_accounts SET
        email = ?,
        access_token = ?,
        refresh_token = 'imap',
        status = 'connected',
        connected_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(cleanEmail, encryptedPassword, existingAccount.id);
    accountId = existingAccount.id;
  } else {
    const info = db.prepare(`
      INSERT INTO email_accounts (user_id, email, access_token, refresh_token, status)
      VALUES (?, ?, ?, 'imap', 'connected')
    `).run(req.session.userId, cleanEmail, encryptedPassword);
    accountId = Number(info.lastInsertRowid);
  }

  // Run fast direct scan
  try {
    await fetchAndScanImapEmails(cleanEmail, cleanPass, accountId, 8);
    res.redirect('/admin/email-scanner?connected=true');
  } catch (scanErr) {
    console.error('IMAP scan error:', scanErr.message);
    res.redirect('/admin/email-scanner?oauth_error=' + encodeURIComponent('Connected, but scan encountered: ' + scanErr.message));
  }
});

// ── Trigger Live Scan (OAuth or IMAP) ──
router.post('/admin/email-scanner/scan', requireAuth, async (req, res) => {
  try {
    const account = db.prepare("SELECT * FROM email_accounts WHERE user_id = ? AND status = 'connected'").get(req.session.userId);
    if (!account || !account.access_token) {
      return res.status(400).json({ error: 'No active Gmail account connected' });
    }

    const decryptedToken = decryptToken(account.access_token);

    if (account.refresh_token === 'imap') {
      // IMAP scan using decrypted App Password
      const results = await fetchAndScanImapEmails(account.email, decryptedToken, account.id, 20);
      return res.json({ success: true, count: results.length });
    }

    // Google OAuth scan
    const authClient = getAuthenticatedClient({
      access_token: decryptedToken,
      refresh_token: account.refresh_token,
      expiry_date: account.token_expiry
    });

    if (!authClient) {
      return res.status(400).json({ error: 'Google OAuth client not configured' });
    }

    const results = await fetchAndScanGmail(authClient, account.id, 20);
    res.json({ success: true, count: results.length });
  } catch (err) {
    console.error('Scan trigger error:', err);
    res.status(500).json({ error: err.message || 'Failed to scan inbox' });
  }
});

// ── Scan Pasted Email Text / Quick Input ──
router.post('/admin/email-scanner/scan-text', requireAuth, (req, res) => {
  try {
    const { sender, sender_name, subject, body_text } = req.body;

    if (!body_text && !subject) {
      return res.status(400).json({ error: 'Please enter email subject or body text to scan' });
    }

    const cleanSender = (sender || 'unknown@sender.com').trim();
    const cleanName = (sender_name || '').trim();
    const cleanSubject = (subject || '(Direct Text Scan)').trim();
    const cleanBody = (body_text || '').trim();

    const threatReport = scanEmailThreats({
      sender: cleanSender,
      sender_name: cleanName,
      subject: cleanSubject,
      body_text: cleanBody,
      headers: {},
      attachments: []
    });

    const msgId = `manual-scan-${Date.now()}`;
    const account = db.prepare("SELECT id FROM email_accounts WHERE user_id = ?").get(req.session.userId);

    db.prepare(`
      INSERT INTO email_scans (
        account_id, message_id, thread_id, sender, sender_name, recipient,
        subject, date, snippet, body_text, summary, threat_score, threat_level,
        is_phishing, phishing_reasons, malicious_links, suspicious_attachments,
        leaked_secrets, auth_issues, scanned_at
      ) VALUES (
        ?, ?, NULL, ?, ?, 'me@local',
        ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, CURRENT_TIMESTAMP
      )
    `).run(
      account ? account.id : null,
      msgId,
      cleanSender,
      cleanName,
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
      threatReport.auth_issues
    );

    res.json({
      success: true,
      scanId: msgId,
      threat_score: threatReport.threat_score,
      threat_level: threatReport.threat_level,
      is_phishing: Boolean(threatReport.is_phishing),
      phishing_reasons: JSON.parse(threatReport.phishing_reasons || '[]'),
      malicious_links: JSON.parse(threatReport.malicious_links || '[]'),
      suspicious_attachments: JSON.parse(threatReport.suspicious_attachments || '[]'),
      leaked_secrets: JSON.parse(threatReport.leaked_secrets || '[]'),
      auth_issues: JSON.parse(threatReport.auth_issues || '[]'),
      summary: typeof threatReport.summary === 'string' ? JSON.parse(threatReport.summary || '{}') : (threatReport.summary || {})
    });
  } catch (err) {
    console.error('Manual scan error:', err);
    res.status(500).json({ error: 'Failed to scan text' });
  }
});

// ── Trigger Demo Threat Simulation ──
router.post('/admin/email-scanner/demo-scan', requireAuth, (req, res) => {
  try {
    const account = db.prepare('SELECT id FROM email_accounts WHERE user_id = ?').get(req.session.userId);
    const results = generateDemoThreatEmails(account ? account.id : null);
    res.json({ success: true, count: results.length });
  } catch (err) {
    console.error('Demo scan error:', err);
    res.status(500).json({ error: 'Failed to generate threat simulation' });
  }
});

// ── Get Single Email Threat Detail JSON & Comprehensive Forensic Report ──
router.get('/admin/email-scanner/email/:id', requireAuth, (req, res) => {
  const scan = db.prepare('SELECT * FROM email_scans WHERE id = ?').get(req.params.id);
  if (!scan) {
    return res.status(404).json({ error: 'Scan report not found' });
  }

  const forensicReport = generateForensicReport(scan);

  res.json({
    id: scan.id,
    subject: scan.subject,
    sender: scan.sender,
    sender_name: scan.sender_name,
    recipient: scan.recipient,
    date: scan.date,
    body_text: scan.body_text,
    threat_score: scan.threat_score,
    threat_level: scan.threat_level,
    is_phishing: Boolean(scan.is_phishing),
    phishing_reasons: JSON.parse(scan.phishing_reasons || '[]'),
    malicious_links: JSON.parse(scan.malicious_links || '[]'),
    suspicious_attachments: JSON.parse(scan.suspicious_attachments || '[]'),
    leaked_secrets: JSON.parse(scan.leaked_secrets || '[]'),
    auth_issues: JSON.parse(scan.auth_issues || '[]'),
    summary: JSON.parse(scan.summary || '{}'),
    scanned_at: scan.scanned_at,
    forensicReport
  });
});

// ── View Standalone Comprehensive Forensic Incident Dossier ──
router.get('/admin/email-scanner/report/:id', requireAuth, (req, res) => {
  const scan = db.prepare('SELECT * FROM email_scans WHERE id = ?').get(req.params.id);
  if (!scan) {
    return res.redirect('/admin/email-scanner?oauth_error=' + encodeURIComponent('Threat report not found'));
  }

  const forensicReport = generateForensicReport(scan);
  res.render('admin/forensic-report', {
    scan,
    report: forensicReport,
    user: req.session
  });
});

// ── Disconnect Gmail Account ──
router.post('/admin/email-scanner/disconnect', requireAuth, (req, res) => {
  const account = db.prepare('SELECT id FROM email_accounts WHERE user_id = ?').get(req.session.userId);
  if (account) {
    db.prepare('DELETE FROM email_scans WHERE account_id = ?').run(account.id);
    db.prepare('DELETE FROM email_accounts WHERE id = ?').run(account.id);
  }
  res.redirect('/admin/email-scanner');
});

// ── Clear Scan Reports Scoped to User ──
router.post('/admin/email-scanner/clear', requireAuth, (req, res) => {
  const account = db.prepare('SELECT id FROM email_accounts WHERE user_id = ?').get(req.session.userId);
  if (account) {
    db.prepare('DELETE FROM email_scans WHERE account_id = ?').run(account.id);
  } else {
    // Delete unassigned manual scans created during manual scanning
    db.prepare('DELETE FROM email_scans WHERE account_id IS NULL').run();
  }
  res.redirect('/admin/email-scanner');
});

module.exports = router;
