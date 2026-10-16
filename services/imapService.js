const { ImapFlow } = require('imapflow');
const { simpleParser } = require('mailparser');
const db = require('../database/db');
const { scanEmailThreats } = require('./threatScanner');

/**
 * Create an optimized ImapFlow client for Gmail with robust timeouts
 */
function createImapClient(email, appPassword) {
  const cleanPassword = (appPassword || '').replace(/\s+/g, '');

  return new ImapFlow({
    host: 'imap.gmail.com',
    port: 993,
    secure: true,
    auth: {
      user: (email || '').trim(),
      pass: cleanPassword
    },
    logger: false,
    tls: {
      rejectUnauthorized: true
    },
    clientInfo: {
      name: 'CyberSec-Scanner',
      version: '2.0.0'
    },
    socketTimeout: 30000,
    connectionTimeout: 15000
  });
}

/**
 * Clean text extractor from HTML bodies
 */
function extractCleanText(rawContent) {
  if (!rawContent) return '';
  let str = typeof rawContent === 'string' ? rawContent : rawContent.toString('utf-8');
  
  str = str.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
           .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
           .replace(/<[^>]+>/g, ' ')
           .replace(/&#\d+;/g, ' ')
           .replace(/&#x[0-9a-f]+;/gi, ' ')
           .replace(/&nbsp;/g, ' ')
           .replace(/&amp;/g, '&')
           .replace(/&lt;/g, '<')
           .replace(/&gt;/g, '>')
           .replace(/\s+/g, ' ')
           .trim();

  return str;
}

/**
 * Fetch and scan emails via Gmail IMAP using mailparser
 */
async function fetchAndScanImapEmails(email, appPassword, accountId, maxResults = 20) {
  const client = createImapClient(email, appPassword);
  
  try {
    await client.connect();
  } catch (connErr) {
    throw new Error('Could not connect to Gmail IMAP server (Port 993). Please make sure "IMAP Access" is turned ON in your Gmail Settings: mail.google.com -> Settings -> Forwarding and POP/IMAP -> Enable IMAP -> Save Changes. Or generate a new 16-character App Password at myaccount.google.com/apppasswords.');
  }

  const scannedReports = [];

  try {
    const lock = await client.getMailboxLock('INBOX');
    try {
      const mailbox = client.mailbox;
      const totalMessages = mailbox.exists || 0;

      if (totalMessages === 0) {
        return scannedReports;
      }

      const countToFetch = Math.min(totalMessages, Math.max(1, maxResults));
      const startSeq = Math.max(1, totalMessages - countToFetch + 1);
      const seqRange = `${startSeq}:${totalMessages}`;

      const insertScan = db.prepare(`
        INSERT INTO email_scans (
          account_id, message_id, thread_id, sender, sender_name, recipient,
          subject, date, snippet, body_text, summary, threat_score, threat_level,
          is_phishing, phishing_reasons, malicious_links, suspicious_attachments,
          leaked_secrets, auth_issues, scanned_at
        ) VALUES (
          ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?,
          ?, ?, CURRENT_TIMESTAMP
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
          summary = excluded.summary,
          scanned_at = CURRENT_TIMESTAMP
      `);

      for await (const message of client.fetch(seqRange, { 
        source: true,
        uid: true, 
        envelope: true 
      })) {
        try {
          let parsed = null;
          if (message.source) {
            try {
              parsed = await simpleParser(message.source);
            } catch (pErr) {
              console.warn(`Warning parsing MIME for message UID ${message.uid}:`, pErr.message);
            }
          }

          const envelope = message.envelope || {};
          const subject = (parsed?.subject || envelope.subject || '(No Subject)').trim();
          
          const senderObj = parsed?.from?.value?.[0] || envelope.from?.[0] || {};
          const senderEmail = (senderObj.address || 'unknown@domain.com').trim();
          const senderName = (senderObj.name || '').trim();
          
          const recipientObj = parsed?.to?.value?.[0] || envelope.to?.[0] || {};
          const recipient = (recipientObj.address || '').trim();

          let dateVal = parsed?.date || envelope.date;
          let dateIso;
          if (dateVal instanceof Date && !isNaN(dateVal.getTime())) {
            dateIso = dateVal.toISOString();
          } else {
            dateIso = new Date().toISOString();
          }

          let bodyText = (parsed?.text || '').trim();
          if (!bodyText && parsed?.html) {
            bodyText = extractCleanText(parsed.html);
          }
          if (!bodyText) {
            bodyText = subject;
          }

          const cleanForSnippet = bodyText.replace(/\s+/g, ' ').trim();
          const snippet = cleanForSnippet.substring(0, 150) || subject;

          const attachments = (parsed?.attachments || []).map(att => ({
            filename: att.filename || 'attachment',
            contentType: att.contentType || 'application/octet-stream',
            size: att.size || 0
          }));

          const headersMap = {};
          if (parsed?.replyTo?.value?.[0]?.address) {
            headersMap['reply-to'] = parsed.replyTo.value[0].address;
          } else if (envelope.replyTo?.[0]?.address) {
            headersMap['reply-to'] = envelope.replyTo[0].address;
          }

          const threatReport = scanEmailThreats({
            sender: senderEmail,
            sender_name: senderName,
            recipient,
            subject,
            body_text: bodyText,
            body_html: parsed?.html || '',
            headers: headersMap,
            attachments
          });

          const msgId = parsed?.messageId || envelope.messageId || `imap-uid-${message.uid}`;

          insertScan.run(
            accountId || null,
            msgId,
            null,
            senderEmail,
            senderName,
            recipient,
            subject,
            dateIso,
            snippet,
            bodyText.substring(0, 4000),
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

          scannedReports.push({
            id: msgId,
            subject,
            sender: senderEmail,
            ...threatReport
          });
        } catch (msgErr) {
          console.error(`Error processing message UID ${message.uid}:`, msgErr);
        }
      }
    } finally {
      lock.release();
    }
  } finally {
    try { await client.logout(); } catch (_) {}
  }

  if (accountId) {
    db.prepare('UPDATE email_accounts SET last_scanned_at = CURRENT_TIMESTAMP WHERE id = ?').run(accountId);
  }

  return scannedReports;
}

module.exports = {
  fetchAndScanImapEmails
};
