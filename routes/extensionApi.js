const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const db = require('../database/db');
const { scanEmailThreats } = require('../services/threatScanner');
const crypto = require('crypto');

// ── Recursive Directory Traversal for Extension Packaging ──
function getAllExtensionFiles(dirPath, arrayOfFiles = [], baseDir = dirPath) {
  const files = fs.readdirSync(dirPath);
  files.forEach((file) => {
    const fullPath = path.join(dirPath, file);
    if (fs.statSync(fullPath).isDirectory()) {
      getAllExtensionFiles(fullPath, arrayOfFiles, baseDir);
    } else {
      const relativePath = path.relative(baseDir, fullPath).replace(/\\/g, '/');
      arrayOfFiles.push({
        name: relativePath,
        content: fs.readFileSync(fullPath)
      });
    }
  });
  return arrayOfFiles;
}

// ── In-Memory Standard ZIP Archive Generator ──
function createZipBuffer(files) {
  const localHeaders = [];
  const centralHeaders = [];
  let offset = 0;

  for (const file of files) {
    const nameBuf = Buffer.from(file.name);
    const data = file.content;
    const compressed = zlib.deflateRawSync(data);
    const crc = zlib.crc32(data);

    // Local file header (30 bytes + filename)
    const lfh = Buffer.alloc(30 + nameBuf.length);
    lfh.writeUInt32LE(0x04034b50, 0); // Local header signature
    lfh.writeUInt16LE(20, 4);          // Version needed (2.0)
    lfh.writeUInt16LE(0, 6);           // General purpose bit flag
    lfh.writeUInt16LE(8, 8);           // Compression method (8 = deflate)
    lfh.writeUInt16LE(0, 10);          // Last mod file time
    lfh.writeUInt16LE(0, 12);          // Last mod file date
    lfh.writeUInt32LE(crc, 14);        // CRC-32
    lfh.writeUInt32LE(compressed.length, 18); // Compressed size
    lfh.writeUInt32LE(data.length, 22);       // Uncompressed size
    lfh.writeUInt16LE(nameBuf.length, 26);    // File name length
    lfh.writeUInt16LE(0, 28);                 // Extra field length
    nameBuf.copy(lfh, 30);

    localHeaders.push(lfh, compressed);

    // Central directory file header (46 bytes + filename)
    const cdh = Buffer.alloc(46 + nameBuf.length);
    cdh.writeUInt32LE(0x02014b50, 0); // Central header signature
    cdh.writeUInt16LE(20, 4);          // Version made by
    cdh.writeUInt16LE(20, 6);          // Version needed
    cdh.writeUInt16LE(0, 8);           // Bit flag
    cdh.writeUInt16LE(8, 10);          // Compression method
    cdh.writeUInt16LE(0, 12);          // Last mod time
    cdh.writeUInt16LE(0, 14);          // Last mod date
    cdh.writeUInt32LE(crc, 16);        // CRC-32
    cdh.writeUInt32LE(compressed.length, 20); // Compressed size
    cdh.writeUInt32LE(data.length, 24);       // Uncompressed size
    cdh.writeUInt16LE(nameBuf.length, 28);    // File name length
    cdh.writeUInt16LE(0, 30);                 // Extra field length
    cdh.writeUInt16LE(0, 32);                 // Comment length
    cdh.writeUInt16LE(0, 34);                 // Disk number start
    cdh.writeUInt16LE(0, 36);                 // Internal file attributes
    cdh.writeUInt32LE(0, 38);                 // External file attributes
    cdh.writeUInt32LE(offset, 42);            // Relative offset of local header
    nameBuf.copy(cdh, 46);

    centralHeaders.push(cdh);
    offset += lfh.length + compressed.length;
  }

  const centralDirOffset = offset;
  let centralDirSize = 0;
  for (const ch of centralHeaders) centralDirSize += ch.length;

  // End of central directory record (22 bytes)
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);   // EOCD signature
  eocd.writeUInt16LE(0, 4);            // Number of this disk
  eocd.writeUInt16LE(0, 6);            // Disk where central directory starts
  eocd.writeUInt16LE(files.length, 8);  // Number of central directory records on this disk
  eocd.writeUInt16LE(files.length, 10); // Total number of central directory records
  eocd.writeUInt32LE(centralDirSize, 12);   // Size of central directory
  eocd.writeUInt32LE(centralDirOffset, 16); // Offset of start of central directory
  eocd.writeUInt16LE(0, 20);           // Comment length

  return Buffer.concat([...localHeaders, ...centralHeaders, eocd]);
}

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
  const extDir = path.resolve(__dirname, '..', 'extension');
  try {
    const totalScans = db.prepare('SELECT COUNT(*) as count FROM email_scans').get()?.count || 0;
    const threatsBlocked = db.prepare("SELECT COUNT(*) as count FROM email_scans WHERE threat_level IN ('high', 'critical') OR is_phishing = 1").get()?.count || 0;

    res.json({
      online: true,
      service: 'CyberSec Email Threat Radar',
      version: '1.0.0',
      systemTime: new Date().toISOString(),
      folderPath: extDir,
      platform: process.platform,
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
      folderPath: extDir,
      platform: process.platform,
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
      reportUrl: `${req.protocol}://${req.get('host') || 'localhost:3000'}/admin/email-scanner/report/${scanId}`
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
 * Download Chrome Extension as a ZIP package
 * GET /api/extension/download
 * GET /api/extension/download-zip
 */
function handleDownloadZip(req, res) {
  try {
    const extDir = path.resolve(__dirname, '..', 'extension');
    const files = getAllExtensionFiles(extDir);
    const zipBuf = createZipBuffer(files);

    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="cybersec-extension.zip"');
    res.setHeader('Content-Length', zipBuf.length);
    res.send(zipBuf);
  } catch (err) {
    console.error('Extension zip package error:', err);
    res.status(500).json({ success: false, error: 'Could not package extension zip: ' + err.message });
  }
}

router.get('/download', handleDownloadZip);
router.get('/download-zip', handleDownloadZip);

/**
 * Reveal extension folder in native file manager (Finder / File Explorer / XDG)
 * POST /api/extension/reveal-finder
 * POST /api/extension/reveal-folder
 */
function handleRevealFolder(req, res) {
  const { exec } = require('child_process');
  const extDir = path.resolve(__dirname, '..', 'extension');
  const manifestPath = path.join(extDir, 'manifest.json');

  let cmd;
  if (process.platform === 'darwin') {
    cmd = `open -R "${manifestPath}"`;
  } else if (process.platform === 'win32') {
    cmd = `explorer.exe /select,"${manifestPath}"`;
  } else {
    cmd = `xdg-open "${extDir}"`;
  }

  exec(cmd, (err) => {
    if (err) {
      return res.status(500).json({ success: false, error: err.message, platform: process.platform });
    }
    res.json({ success: true, folder: extDir, platform: process.platform });
  });
}

router.post('/reveal-finder', handleRevealFolder);
router.post('/reveal-folder', handleRevealFolder);

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
