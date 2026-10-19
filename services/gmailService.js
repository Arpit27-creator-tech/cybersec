const { google } = require('googleapis');
const db = require('../database/db');
const { scanEmailThreats } = require('./threatScanner');

const SCOPES = [
  'https://www.googleapis.com/auth/gmail.readonly',
  'https://www.googleapis.com/auth/userinfo.email'
];

/**
 * Get configured Google OAuth 2.0 Client
 */
function getOAuth2Client() {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  const redirectUri = process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3000/auth/google/callback';

  if (!clientId || !clientSecret) {
    return null;
  }

  return new google.auth.OAuth2(clientId, clientSecret, redirectUri);
}

/**
 * Generate Google OAuth authorization URL
 */
function getAuthUrl() {
  const oauth2Client = getOAuth2Client();
  if (!oauth2Client) return null;

  return oauth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: SCOPES
  });
}

/**
 * Exchange auth code for OAuth tokens
 */
async function getTokensFromCode(code) {
  const oauth2Client = getOAuth2Client();
  if (!oauth2Client) throw new Error('Google OAuth credentials not configured in .env');

  const { tokens } = await oauth2Client.getToken(code);
  return tokens;
}

/**
 * Create an authenticated Gmail API client from stored tokens
 */
function getAuthenticatedClient(tokens) {
  const oauth2Client = getOAuth2Client();
  if (!oauth2Client) return null;

  oauth2Client.setCredentials(tokens);
  return oauth2Client;
}

/**
 * Decode Base64URL encoded email payload
 */
function decodeBase64(data) {
  if (!data) return '';
  const buff = Buffer.from(data.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  return buff.toString('utf-8');
}

/**
 * Extract plain text body from Gmail message parts
 */
function extractBody(payload) {
  if (!payload) return '';
  if (payload.body && payload.body.data) {
    return decodeBase64(payload.body.data);
  }
  if (payload.parts && payload.parts.length) {
    for (const part of payload.parts) {
      if (part.mimeType === 'text/plain' && part.body && part.body.data) {
        return decodeBase64(part.body.data);
      }
    }
    for (const part of payload.parts) {
      if (part.mimeType === 'text/html' && part.body && part.body.data) {
        // Strip HTML tags for text analysis
        return decodeBase64(part.body.data).replace(/<[^>]+>/g, ' ');
      }
    }
    // Recursive parts search
    for (const part of payload.parts) {
      const nested = extractBody(part);
      if (nested) return nested;
    }
  }
  return '';
}

/**
 * Extract attachments metadata
 */
function extractAttachments(payload) {
  const attachments = [];
  if (!payload) return attachments;

  function traverse(parts) {
    if (!parts) return;
    for (const part of parts) {
      if (part.filename && part.filename.length > 0) {
        attachments.push({
          filename: part.filename,
          mimeType: part.mimeType,
          size: part.body ? part.body.size : 0
        });
      }
      if (part.parts) traverse(part.parts);
    }
  }

  if (payload.parts) traverse(payload.parts);
  return attachments;
}

/**
 * Fetch and scan live Gmail messages in parallel
 */
async function fetchAndScanGmail(authClient, accountId, maxResults = 12) {
  const gmail = google.gmail({ version: 'v1', auth: authClient });

  // List messages
  const res = await gmail.users.messages.list({
    userId: 'me',
    maxResults,
    q: 'in:inbox'
  });

  const messages = res.data.messages || [];
  if (messages.length === 0) return [];

  const insertScan = db.prepare(`
    INSERT INTO email_scans (
      account_id, message_id, thread_id, sender, sender_name, recipient,
      subject, date, snippet, body_text, summary, threat_score, threat_level,
      is_phishing, phishing_reasons, malicious_links, suspicious_attachments,
      leaked_secrets, auth_issues, classification_category, classification_confidence,
      classification_details, scanned_at
    ) VALUES (
      ?, ?, ?, ?, ?, ?,
      ?, ?, ?, ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, CURRENT_TIMESTAMP
    )
    ON CONFLICT(message_id) DO UPDATE SET
      subject = excluded.subject,
      sender = excluded.sender,
      sender_name = excluded.sender_name,
      snippet = excluded.snippet,
      body_text = excluded.body_text,
      threat_score = excluded.threat_score,
      threat_level = excluded.threat_level,
      is_phishing = excluded.is_phishing,
      phishing_reasons = excluded.phishing_reasons,
      malicious_links = excluded.malicious_links,
      suspicious_attachments = excluded.suspicious_attachments,
      leaked_secrets = excluded.leaked_secrets,
      auth_issues = excluded.auth_issues,
      classification_category = excluded.classification_category,
      classification_confidence = excluded.classification_confidence,
      classification_details = excluded.classification_details,
      summary = excluded.summary,
      scanned_at = CURRENT_TIMESTAMP
  `);

  // Parallel fetch for speed
  const fetchPromises = messages.map(async (msg) => {
    try {
      const fullMsg = await gmail.users.messages.get({
        userId: 'me',
        id: msg.id,
        format: 'full'
      });

      const payload = fullMsg.data.payload || {};
      const headersList = payload.headers || [];
      const headersMap = {};
      headersList.forEach(h => {
        headersMap[h.name.toLowerCase()] = h.value;
      });

      const fromHeader = headersMap['from'] || 'Unknown Sender';
      let senderName = '';
      let senderEmail = fromHeader;

      const fromMatch = fromHeader.match(/^(.*?)\s*<([^>]+)>/);
      if (fromMatch) {
        senderName = fromMatch[1].replace(/["']/g, '').trim();
        senderEmail = fromMatch[2].trim();
      }

      const subject = headersMap['subject'] || '(No Subject)';
      const dateStr = headersMap['date'] || new Date().toISOString();
      const recipient = headersMap['to'] || '';
      const bodyText = extractBody(payload) || fullMsg.data.snippet || '';
      const attachments = extractAttachments(payload);

      // Run cybersecurity threat scan & AI summary
      const threatReport = scanEmailThreats({
        sender: senderEmail,
        sender_name: senderName,
        recipient,
        subject,
        body_text: bodyText,
        headers: headersMap,
        attachments
      });

      insertScan.run(
        accountId,
        msg.id,
        fullMsg.data.threadId || null,
        senderEmail,
        senderName,
        recipient,
        subject,
        new Date(dateStr).toISOString(),
        fullMsg.data.snippet || '',
        bodyText.substring(0, 4000),
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

      return {
        id: msg.id,
        subject,
        sender: senderEmail,
        ...threatReport
      };
    } catch (msgErr) {
      console.error(`Error scanning message ${msg.id}:`, msgErr);
      return null;
    }
  });

  const results = await Promise.all(fetchPromises);
  const scannedReports = results.filter(Boolean);

  // Update account last_scanned_at
  if (accountId) {
    db.prepare('UPDATE email_accounts SET last_scanned_at = CURRENT_TIMESTAMP WHERE id = ?').run(accountId);
  }

  return scannedReports;
}

/**
 * Seed realistic simulated threat & corporate emails for testing the scanner
 */
function generateDemoThreatEmails(accountId) {
  const sampleEmails = [
    {
      message_id: 'demo-msg-phish-01',
      sender: 'security@paypa1-verify-account.xyz',
      sender_name: 'PayPal Security Team',
      recipient: 'user@company.com',
      subject: 'URGENT: Your PayPal Account will be suspended within 24 hours',
      date: new Date(Date.now() - 1000 * 60 * 25).toISOString(),
      snippet: 'We detected unauthorized access to your account from IP 185.220.101.5. Action required immediately.',
      body_text: 'Dear Customer,\n\nWe detected unauthorized access detected on your PayPal account. Your account will be suspended within 24 hours unless you confirm your identity.\n\nPlease click here to re-activate your account: http://192.168.1.105/paypa1/login.php?id=99281\n\nVerify your password and update your billing information immediately.\n\nPayPal Trust & Safety',
      headers: { 'reply-to': 'harvest-drop@scam-mail.top' },
      attachments: []
    },
    {
      message_id: 'demo-msg-leak-02',
      sender: 'devops-lead@company.com',
      sender_name: 'Alex Vance',
      recipient: 'engineering-team@company.com',
      subject: 'Production Database migration keys & AWS deployment credentials',
      date: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
      snippet: 'Here are the temporary AWS staging keys and database root password for tonight\'s deployment.',
      body_text: 'Hey team,\n\nHere are the AWS credentials for the deployment server:\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n\nDatabase access string:\ndb_pass: "SuperSecretPr0dPass#2026!"\n\nPlease rotate after migration is complete.\n\nAlex',
      headers: {},
      attachments: []
    },
    {
      message_id: 'demo-msg-malware-03',
      sender: 'billing@overdue-invoices-corp.top',
      sender_name: 'Accounting Dept',
      recipient: 'finance@company.com',
      subject: 'Overdue Invoice #INV-98421 - Immediate Wire Transfer Required',
      date: new Date(Date.now() - 1000 * 60 * 300).toISOString(),
      snippet: 'Attached is the revised invoice for overdue services. Urgent payment required via wire transfer.',
      body_text: 'Hello,\n\nPlease find attached the final overdue invoice #INV-98421. Urgent payment required within 48 hours to avoid legal escalation.\n\nWire transfer details are embedded in the attached spreadsheet.\n\nRegards,\nAccounts Receivable',
      headers: {},
      attachments: [{ filename: 'Invoice_Details_Q3_Final.xlsm', mimeType: 'application/vnd.ms-excel.sheet.macroEnabled.12' }]
    },
    {
      message_id: 'demo-msg-safe-04',
      sender: 'notifications@github.com',
      sender_name: 'GitHub',
      recipient: 'developer@company.com',
      subject: '[GitHub] A new release v2.4.0 has been published in cybersec-core',
      date: new Date(Date.now() - 1000 * 60 * 450).toISOString(),
      snippet: 'Release v2.4.0 is now available. Changes include bug fixes and performance improvements.',
      body_text: 'Hey there,\n\nRelease v2.4.0 has been published in repository cybersec-core.\n\nView release notes at https://github.com/organization/cybersec-core/releases/tag/v2.4.0\n\nYou received this email because you are subscribed to repository notifications.\n\nGitHub, Inc.',
      headers: {},
      attachments: []
    },
    {
      message_id: 'demo-msg-msft-05',
      sender: 'admin@0ffice365-password-reset.club',
      sender_name: 'Microsoft 365 Security',
      recipient: 'admin@company.com',
      subject: 'Critical Alert: Your Microsoft 365 Password will expire in 2 hours',
      date: new Date(Date.now() - 1000 * 60 * 600).toISOString(),
      snippet: 'Your corporate password will expire in 2 hours. Click here to verify your password and keep current session active.',
      body_text: 'Microsoft Security Alert\n\nYour corporate domain password will expire in 2 hours. Action required immediately to prevent losing access to your email and OneDrive files.\n\nKeep my password active: https://bit.ly/3xMS365-Reset-Portal\n\nMicrosoft Corporation, One Microsoft Way, Redmond, WA',
      headers: { 'reply-to': 'stealer@inbox-collector.xyz' },
      attachments: []
    }
  ];

  const results = [];
  const insertScan = db.prepare(`
    INSERT INTO email_scans (
      account_id, message_id, thread_id, sender, sender_name, recipient,
      subject, date, snippet, body_text, summary, threat_score, threat_level,
      is_phishing, phishing_reasons, malicious_links, suspicious_attachments,
      leaked_secrets, auth_issues, classification_category, classification_confidence,
      classification_details, scanned_at
    ) VALUES (
      ?, ?, ?, ?, ?, ?,
      ?, ?, ?, ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, CURRENT_TIMESTAMP
    )
    ON CONFLICT(message_id) DO UPDATE SET
      threat_score = excluded.threat_score,
      threat_level = excluded.threat_level,
      is_phishing = excluded.is_phishing,
      phishing_reasons = excluded.phishing_reasons,
      malicious_links = excluded.malicious_links,
      suspicious_attachments = excluded.suspicious_attachments,
      leaked_secrets = excluded.leaked_secrets,
      auth_issues = excluded.auth_issues,
      classification_category = excluded.classification_category,
      classification_confidence = excluded.classification_confidence,
      classification_details = excluded.classification_details,
      summary = excluded.summary,
      scanned_at = CURRENT_TIMESTAMP
  `);

  for (const sample of sampleEmails) {
    const threatReport = scanEmailThreats({
      sender: sample.sender,
      sender_name: sample.sender_name,
      recipient: sample.recipient,
      subject: sample.subject,
      body_text: sample.body_text,
      headers: sample.headers,
      attachments: sample.attachments
    });

    const classification = threatReport.classification || {};

    insertScan.run(
      accountId || null,
      sample.message_id,
      null,
      sample.sender,
      sample.sender_name,
      sample.recipient,
      sample.subject,
      sample.date,
      sample.snippet,
      sample.body_text,
      threatReport.summary,
      threatReport.threat_score,
      threatReport.threat_level,
      threatReport.is_phishing,
      threatReport.phishing_reasons,
      threatReport.malicious_links,
      threatReport.suspicious_attachments,
      threatReport.leaked_secrets,
      threatReport.auth_issues,
      classification.category || 'legitimate',
      classification.confidence !== undefined ? classification.confidence : 0.95,
      JSON.stringify(classification),
    );

    results.push({
      message_id: sample.message_id,
      subject: sample.subject,
      ...threatReport
    });
  }

  return results;
}

module.exports = {
  getOAuth2Client,
  getAuthUrl,
  getTokensFromCode,
  getAuthenticatedClient,
  fetchAndScanGmail,
  generateDemoThreatEmails
};
