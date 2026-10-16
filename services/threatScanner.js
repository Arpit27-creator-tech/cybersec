/**
 * Cybersecurity Threat Scanner & AI Email Summarizer Engine
 */

// ── Lookalike / Typosquatting Brand Patterns ──
const BRAND_PATTERNS = [
  { name: 'PayPal', pattern: /\b(?:paypa[l1i]|pay-pal)\b/i, legit: 'paypal.com' },
  { name: 'Google', pattern: /\b(?:g[o0]{2}g[l1]e|gmai[l1])\b/i, legit: 'google.com' },
  { name: 'Microsoft', pattern: /\b(?:micr[o0]s[o0]ft|0ffice365|ms-verify)\b/i, legit: 'microsoft.com' },
  { name: 'Apple', pattern: /\b(?:app[l1]e-id|icloud-verify)\b/i, legit: 'apple.com' },
  { name: 'Amazon', pattern: /\b(?:amaz[o0]n-security|amz-verify)\b/i, legit: 'amazon.com' },
  { name: 'Netflix', pattern: /\b(?:netfl[i1l]x|nflx-verify)\b/i, legit: 'netflix.com' },
  { name: 'Bank of America', pattern: /\b(?:bofa-security|bankofamerica-verify)\b/i, legit: 'bankofamerica.com' },
  { name: 'Wells Fargo', pattern: /\b(?:wellsfargo-secure|wf-update)\b/i, legit: 'wellsfargo.com' }
];

// ── Urgency & Social Engineering Lures ──
const URGENCY_TRIGGERS = [
  { text: 'account will be suspended', weight: 25, reason: 'Threat of immediate account suspension' },
  { text: 'action required immediately', weight: 20, reason: 'High urgency coercion phrase' },
  { text: 'unauthorized access detected', weight: 25, reason: 'Fake security alert pretext' },
  { text: 'verify your password', weight: 30, reason: 'Direct credential verification solicitation' },
  { text: 'update your billing information', weight: 20, reason: 'Financial info collection request' },
  { text: 'wire transfer', weight: 15, reason: 'High-risk financial wire instruction' },
  { text: 'urgent payment required', weight: 20, reason: 'Urgent financial demand' },
  { text: 'confirm your identity', weight: 20, reason: 'Identity harvesting trigger' },
  { text: 'click here to re-activate', weight: 25, reason: 'Deceptive reactivation link trigger' },
  { text: 'password will expire in', weight: 20, reason: 'Fake password expiration scare tactic' },
  { text: 'unusual login activity', weight: 20, reason: 'Pretexting unusual sign-in alert' },
  { text: 'claim your prize', weight: 30, reason: 'Classic lottery / reward scam' },
  { text: 'tax refund notification', weight: 25, reason: 'Government / tax agency impersonation' }
];

// ── Suspicious TLDs & Shorteners ──
const SUSPICIOUS_TLDS = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.club', '.work', '.click', '.loan', '.stream', '.gdn', '.racing'];
const URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 'is.gd', 'cutt.ly', 't.co', 'ow.ly', 'rb.gy', 'v.gd'];

// ── Dangerous Attachment Extensions ──
const DANGEROUS_EXTENSIONS = [
  { ext: '.exe', desc: 'Executable file (high malware risk)' },
  { ext: '.scr', desc: 'ScreenSaver executable' },
  { ext: '.vbs', desc: 'VBScript executable' },
  { ext: '.js', desc: 'JavaScript executable script' },
  { ext: '.bat', desc: 'Batch script' },
  { ext: '.cmd', desc: 'Command script' },
  { ext: '.ps1', desc: 'PowerShell script' },
  { ext: '.iso', desc: 'Disk image (common malware container)' },
  { ext: '.img', desc: 'Disk image container' },
  { ext: '.hta', desc: 'HTML Application executable' },
  { ext: '.cpl', desc: 'Control Panel item' },
  { ext: '.docm', desc: 'Word document with macros' },
  { ext: '.xlsm', desc: 'Excel spreadsheet with macros' }
];

// ── Luhn Algorithm for Credit Card validation ──
function isValidLuhn(ccNum) {
  const digits = ccNum.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = parseInt(digits.charAt(i), 10);
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

/**
 * Scan email for security threats
 */
function scanEmailThreats(emailData) {
  const { sender, sender_name, recipient, subject = '', body_text = '', body_html = '', headers = {}, attachments = [] } = emailData;
  const fullText = `${subject} ${body_text}`.toLowerCase();
  
  let threatScore = 0;
  const phishingReasons = [];
  const maliciousLinks = [];
  const suspiciousAttachments = [];
  const leakedSecrets = [];
  const authIssues = [];

  // 1. ── SENDER AUTHENTICITY & SPOOFING CHECK ──
  const senderEmail = (sender || '').toLowerCase().trim();
  const senderDisplayName = (sender_name || '').trim();
  const senderDomain = senderEmail.includes('@') ? senderEmail.split('@')[1] : '';

  // Check display name brand spoofing
  for (const brand of BRAND_PATTERNS) {
    if (brand.pattern.test(senderDisplayName)) {
      const isLegit = senderDomain === brand.legit || senderDomain.endsWith('.' + brand.legit);
      if (!isLegit) {
        threatScore += 45;
        phishingReasons.push(`Display name "${senderDisplayName}" impersonates ${brand.name}, but sender domain is "${senderDomain}"`);
        authIssues.push(`Brand Impersonation: ${brand.name} mismatch with domain ${senderDomain}`);
      }
    }
  }

  // Check From vs Reply-To mismatch
  const replyTo = (headers['reply-to'] || headers['Reply-To'] || '').toLowerCase();
  if (replyTo && senderEmail) {
    const replyToEmailMatch = replyTo.match(/<([^>]+)>/) || [null, replyTo];
    const replyToEmail = replyToEmailMatch[1] ? replyToEmailMatch[1].trim() : replyTo.trim();
    if (replyToEmail && replyToEmail.includes('@')) {
      const replyToDomain = replyToEmail.split('@')[1];
      if (replyToDomain && senderDomain && replyToDomain !== senderDomain) {
        // Allow subdomains (e.g., mail.example.com and example.com)
        const isSubdomain = replyToDomain.endsWith('.' + senderDomain) || senderDomain.endsWith('.' + replyToDomain);
        
        // Allow same organization domain root (e.g. unstop.news and unstop.com)
        const getBaseDomainName = d => d.split('.').slice(-2, -1)[0] || '';
        const sameBase = getBaseDomainName(replyToDomain) && getBaseDomainName(replyToDomain) === getBaseDomainName(senderDomain);

        if (!isSubdomain && !sameBase) {
          threatScore += 25;
          authIssues.push(`Reply-To address (${replyToEmail}) routes to a different external domain than From (${senderDomain})`);
          phishingReasons.push(`Routing mismatch: replies redirect to external domain ${replyToDomain}`);
        }
      }
    }
  }

  // 2. ── PHISHING & SOCIAL ENGINEERING DETECTION ──
  for (const trigger of URGENCY_TRIGGERS) {
    if (fullText.includes(trigger.text)) {
      threatScore += trigger.weight;
      phishingReasons.push(`${trigger.reason} (matched: "${trigger.text}")`);
    }
  }

  // 3. ── MALICIOUS LINK & URL SCANNER ──
  const urlSet = new Set();
  const rawUrlRegex = /https?:\/\/[^\s<>"')\]]+/gi;
  if (body_text) {
    const textUrls = body_text.match(rawUrlRegex) || [];
    textUrls.forEach(u => urlSet.add(u));
  }
  if (body_html) {
    const hrefRegex = /href=["'](https?:\/\/[^"'>]+)["']/gi;
    let m;
    while ((m = hrefRegex.exec(body_html)) !== null) {
      urlSet.add(m[1]);
    }
  }

  urlSet.forEach(rawUrl => {
    try {
      // Strip trailing soft breaks (=), punctuation, encoded characters
      let cleanUrl = rawUrl.trim().replace(/[=.,;:>)"']+$/, '');
      cleanUrl = cleanUrl.replace(/=3D/gi, '=');
      
      const parsed = new URL(cleanUrl);
      let host = parsed.hostname.toLowerCase().replace(/\.$/, '');

      // IP address URL
      if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
        threatScore += 40;
        maliciousLinks.push({ url: cleanUrl, reason: 'Raw IP address host (bypasses domain reputation)', severity: 'critical' });
      }

      // URL Shorteners
      if (URL_SHORTENERS.includes(host)) {
        threatScore += 20;
        maliciousLinks.push({ url: cleanUrl, reason: `Shortened URL (${host}) masking real destination`, severity: 'medium' });
      }

      // Suspicious TLDs
      for (const tld of SUSPICIOUS_TLDS) {
        if (host.endsWith(tld)) {
          threatScore += 30;
          maliciousLinks.push({ url: cleanUrl, reason: `High-risk TLD (${tld}) frequently used in phishing campaigns`, severity: 'high' });
          break;
        }
      }

      // Lookalike domain in URL
      for (const brand of BRAND_PATTERNS) {
        if (brand.pattern.test(host)) {
          const isLegit = host === brand.legit || host.endsWith('.' + brand.legit);
          if (!isLegit) {
            threatScore += 45;
            maliciousLinks.push({ url: cleanUrl, reason: `Lookalike domain targeting ${brand.name} (${host})`, severity: 'critical' });
          }
        }
      }
    } catch (_) {
      // malformed URL
    }
  });

  // 4. ── ATTACHMENT SCANNER ──
  attachments.forEach(att => {
    const filename = (att.filename || att.name || '').toLowerCase();
    for (const dang of DANGEROUS_EXTENSIONS) {
      if (filename.endsWith(dang.ext)) {
        threatScore += 40;
        suspiciousAttachments.push({ filename: att.filename, extension: dang.ext, risk: dang.desc });
        break;
      }
    }
  });

  // 5. ── DATA LEAKAGE & SECRET SCANNER ──
  // AWS Access Key
  const awsMatch = body_text.match(/\b(AKIA[0-9A-Z]{16})\b/g);
  if (awsMatch) {
    threatScore += 35;
    leakedSecrets.push({ type: 'AWS Access Key ID', sample: awsMatch[0].substring(0, 8) + '...' });
  }

  // GitHub Token
  const ghMatch = body_text.match(/\b(ghp_[0-9a-zA-Z]{36})\b/g);
  if (ghMatch) {
    threatScore += 35;
    leakedSecrets.push({ type: 'GitHub Personal Access Token', sample: ghMatch[0].substring(0, 8) + '...' });
  }

  // Private Keys
  if (/-----BEGIN (RSA|OPENSSH|EC|DSA)? PRIVATE KEY-----/i.test(body_text)) {
    threatScore += 50;
    leakedSecrets.push({ type: 'Private Cryptographic Key', sample: '-----BEGIN PRIVATE KEY-----' });
  }

  // Plaintext Password exposure
  const passMatch = body_text.match(/(?:password|passwd|pwd|db_pass)\s*[:=]\s*["']?([^\s"']{4,})/i);
  if (passMatch) {
    threatScore += 30;
    leakedSecrets.push({ type: 'Plaintext Password Exposure', sample: passMatch[0].substring(0, 15) + '...' });
  }

  // Credit Card Numbers
  const ccMatches = body_text.match(/\b(?:\d{4}[ -]?){3}\d{4}\b|\b\d{15,16}\b/g);
  if (ccMatches) {
    for (const cc of ccMatches) {
      if (isValidLuhn(cc)) {
        threatScore += 35;
        const clean = cc.replace(/\D/g, '');
        leakedSecrets.push({ type: 'Credit Card Number (Luhn Validated)', sample: '•••• •••• •••• ' + clean.slice(-4) });
        break;
      }
    }
  }

  // Cap threat score between 0 and 100
  threatScore = Math.min(100, Math.max(0, threatScore));

  // Determine threat level
  let threatLevel = 'safe';
  if (threatScore >= 80) threatLevel = 'critical';
  else if (threatScore >= 60) threatLevel = 'high';
  else if (threatScore >= 35) threatLevel = 'medium';
  else if (threatScore >= 15) threatLevel = 'low';

  // Accurate phishing determination: Requires significant threat score or critical indicators
  const hasCriticalLink = maliciousLinks.some(l => l.severity === 'critical');
  const hasHighConfidencePhish = threatScore >= 50 && phishingReasons.length > 0;
  const isPhishing = threatScore >= 60 || hasCriticalLink || hasHighConfidencePhish;

  // 6. ── EXECUTIVE AI/SMART SUMMARY GENERATOR ──
  const summary = generateEmailSummary({
    subject,
    sender,
    senderDisplayName,
    senderDomain,
    body_text,
    threatScore,
    threatLevel,
    isPhishing,
    phishingReasons,
    leakedSecrets,
    maliciousLinks
  });

  return {
    threat_score: threatScore,
    threat_level: threatLevel,
    is_phishing: isPhishing ? 1 : 0,
    phishing_reasons: JSON.stringify(phishingReasons),
    malicious_links: JSON.stringify(maliciousLinks),
    suspicious_attachments: JSON.stringify(suspiciousAttachments),
    leaked_secrets: JSON.stringify(leakedSecrets),
    auth_issues: JSON.stringify(authIssues),
    summary
  };
}

/**
 * Smart executive email summarizer
 */
function generateEmailSummary({
  subject,
  sender,
  senderDisplayName,
  sender_name,
  senderDomain,
  body_text,
  threatScore,
  threatLevel,
  isPhishing,
  phishingReasons,
  leakedSecrets,
  maliciousLinks
}) {
  const displayName = (senderDisplayName || sender_name || '').trim();
  const cleanBody = (body_text || '').replace(/\s+/g, ' ').trim();
  const firstSentences = cleanBody.split(/(?<=[.?!])\s+/).slice(0, 2).join(' ');

  let intent = 'General Communication';
  if (isPhishing) intent = 'Social Engineering / Credential Harvest';
  else if (leakedSecrets.length > 0) intent = 'Sensitive Data Exposure';
  else if (/invoice|billing|payment|receipt|wire/i.test(subject + ' ' + cleanBody)) intent = 'Financial / Invoice Notification';
  else if (/security|alert|password|login|verify/i.test(subject)) intent = 'Security & Account Alert';
  else if (/meeting|calendar|schedule|zoom|sync/i.test(subject + ' ' + cleanBody)) intent = 'Schedule / Calendar Request';

  let verdict = '';
  if (threatLevel === 'critical') {
    verdict = `⚠️ CRITICAL RISK: High-confidence phishing attack detected targeting credentials. Do not open links or reply.`;
  } else if (threatLevel === 'high') {
    verdict = `🚨 HIGH RISK: Significant threat indicators detected (${phishingReasons[0] || 'Unverified sender requesting sensitive action'}).`;
  } else if (threatLevel === 'medium') {
    verdict = `⚡ CAUTION: Moderate risk indicators identified. Verify sender identity through out-of-band channels.`;
  } else {
    verdict = `🛡️ VERIFIED SAFE: Standard legitimate communication from ${senderDomain || 'trusted sender'}.`;
  }

  // Key excerpt
  const excerpt = firstSentences.length > 180 ? firstSentences.substring(0, 177) + '...' : (firstSentences || subject || 'No body preview available');

  return JSON.stringify({
    intent,
    overview: excerpt,
    verdict,
    score: threatScore,
    flagsCount: phishingReasons.length + leakedSecrets.length + maliciousLinks.length
  });
}

module.exports = { scanEmailThreats, generateEmailSummary };
