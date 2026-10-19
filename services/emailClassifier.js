/**
 * CyberSec Multi-Class Email Classifier Engine
 * Categorizes emails into:
 *  1. phishing      - Credential harvesting, deceptive login portals, urgency threats
 *  2. bec_fraud     - Business Email Compromise, CEO/executive fraud, wire diversion, gift cards
 *  3. malware       - Weaponized attachments, macro droppers, malicious downloaders
 *  4. spam          - Unsolicited bulk marketing, low-value sweepstakes, junk pitches
 *  5. legitimate    - Normal corporate correspondence, updates, operational notifications
 */

// ── Category Definitions & Metadata ──
const CATEGORIES = {
  phishing: {
    id: 'phishing',
    label: 'Credential Phishing',
    shortLabel: 'Phishing',
    badge: 'PHISHING',
    color: '#ef4444',
    bg: 'rgba(239,68,68,.12)',
    border: 'rgba(239,68,68,.35)',
    icon: '🎣',
    severity: 'critical',
    defaultAction: 'Quarantine Email & Invalidate Targeted Credentials',
    description: 'Deceptive messages engineered to harvest authentication credentials, MFA tokens, or session cookies via spoofed portals.'
  },
  bec_fraud: {
    id: 'bec_fraud',
    label: 'Business Email Compromise (BEC)',
    shortLabel: 'BEC / Wire Fraud',
    badge: 'BEC FRAUD',
    color: '#f97316',
    bg: 'rgba(249,115,22,.12)',
    border: 'rgba(249,115,22,.35)',
    icon: '💼',
    severity: 'critical',
    defaultAction: 'Freeze Outgoing Payments & Verify Recipient via Out-of-Band Channel',
    description: 'Executive impersonation, invoice diversion, or payroll redirection attempting unauthorized fund transfers.'
  },
  malware: {
    id: 'malware',
    label: 'Weaponized Malware Dropper',
    shortLabel: 'Malware',
    badge: 'MALWARE DROPPER',
    color: '#a855f7',
    bg: 'rgba(168,85,247,.12)',
    border: 'rgba(168,85,247,.35)',
    icon: '☣️',
    severity: 'critical',
    defaultAction: 'Block Attachments, Isolate Endpoint Host & Execute EDR Sweep',
    description: 'Emails carrying or linking to weaponized executables, script archives, or macro-enabled documents.'
  },
  spam: {
    id: 'spam',
    label: 'Unsolicited Spam / Marketing',
    shortLabel: 'Spam',
    badge: 'BULK SPAM',
    color: '#eab308',
    bg: 'rgba(234,179,8,.12)',
    border: 'rgba(234,179,8,.35)',
    icon: '📢',
    severity: 'low',
    defaultAction: 'Tag with [SPAM] Prefix or Route to Junk Mailbox',
    description: 'Unsolicited bulk marketing, SEO solicitations, speculative pitches, or promotional spam.'
  },
  legitimate: {
    id: 'legitimate',
    label: 'Legitimate / Clean Email',
    shortLabel: 'Safe / Clean',
    badge: 'CLEAN TELEMETRY',
    color: '#22c55e',
    bg: 'rgba(34,197,94,.12)',
    border: 'rgba(34,197,94,.35)',
    icon: '🛡️',
    severity: 'safe',
    defaultAction: 'Safe for Inbox Delivery',
    description: 'Normal business communication, operational syncs, customer support, or expected internal correspondence.'
  }
};

// ── Weighted Linguistic Lexicons ──
const LEXICON = {
  phishing: [
    { term: 'verify your account', weight: 4.5 },
    { term: 'password will expire', weight: 4.2 },
    { term: 'unauthorized login', weight: 4.0 },
    { term: 'account suspended', weight: 4.2 },
    { term: 'click here to verify', weight: 4.6 },
    { term: 'security alert', weight: 3.2 },
    { term: 'confirm your identity', weight: 4.0 },
    { term: 'sign-in attempt', weight: 3.8 },
    { term: 'update payment method', weight: 3.5 },
    { term: 'restore account access', weight: 4.0 },
    { term: 'verification link', weight: 4.4 },
    { term: 'unusual sign-in activity', weight: 4.2 },
    { term: '24 hours to verify', weight: 4.0 },
    { term: 'paypal security', weight: 3.8 },
    { term: 'microsoft 365 alert', weight: 3.8 },
    { term: 'google workspace notice', weight: 3.5 },
    { term: 'apple id locked', weight: 4.2 },
    { term: 'mfa token', weight: 3.6 },
    { term: 'session expired', weight: 3.4 },
    { term: 're-authenticate', weight: 4.0 },
    { term: 'restricted account', weight: 3.8 },
    { term: 'password expiring', weight: 4.5 },
    { term: 'verify credentials', weight: 4.8 },
    { term: 'account access will be terminated', weight: 4.8 },
    { term: 're-enter your', weight: 4.2 },
    { term: 'corporate password', weight: 4.5 },
    { term: 'verify now', weight: 4.2 },
    { term: 'action required', weight: 3.8 },
    { term: 'microsoft 365', weight: 4.0 },
    { term: 'office 365', weight: 4.0 },
    { term: 'm365', weight: 3.5 }
  ],
  bec_fraud: [
    { term: 'wire transfer', weight: 4.8 },
    { term: 'urgent wire', weight: 5.0 },
    { term: 'updated bank details', weight: 4.8 },
    { term: 'routing number', weight: 4.6 },
    { term: 'new bank account', weight: 4.7 },
    { term: 'gift cards', weight: 4.8 },
    { term: 'purchase apple cards', weight: 5.0 },
    { term: 'need you to handle this urgently', weight: 4.4 },
    { term: 'are you at your desk', weight: 4.2 },
    { term: 'keep this strictly confidential', weight: 4.5 },
    { term: 'quick favor', weight: 3.8 },
    { term: 'payroll direct deposit', weight: 4.5 },
    { term: 'change my direct deposit', weight: 5.0 },
    { term: 'vendor invoice payment', weight: 4.2 },
    { term: 'remittance advice', weight: 3.8 },
    { term: 'ceo', weight: 3.2 },
    { term: 'cfo', weight: 3.4 },
    { term: 'urgent payment required', weight: 4.2 },
    { term: 'revised invoice', weight: 4.3 },
    { term: 'ach transfer', weight: 4.4 },
    { term: 'payment processing before end of day', weight: 4.6 }
  ],
  malware: [
    { term: '.exe', weight: 5.0 },
    { term: '.scr', weight: 5.0 },
    { term: '.vbs', weight: 5.0 },
    { term: '.iso', weight: 4.8 },
    { term: '.bat', weight: 4.8 },
    { term: '.ps1', weight: 4.8 },
    { term: '.docm', weight: 4.5 },
    { term: '.xlsm', weight: 4.5 },
    { term: 'enable macros', weight: 5.0 },
    { term: 'enable editing to view', weight: 4.8 },
    { term: 'enable content', weight: 4.7 },
    { term: 'encrypted zip', weight: 4.2 },
    { term: 'password for archive', weight: 4.4 },
    { term: 'attached document', weight: 3.0 },
    { term: 'run the application', weight: 4.5 },
    { term: 'view invoice pdf.exe', weight: 5.0 },
    { term: 'trojan', weight: 4.0 },
    { term: 'ransomware', weight: 4.5 },
    { term: 'payload', weight: 4.0 },
    { term: 'disk image', weight: 4.0 },
    { term: 'powershell script', weight: 4.5 }
  ],
  spam: [
    { term: 'click here to unsubscribe', weight: 3.5 },
    { term: 'special offer', weight: 3.6 },
    { term: 'discount code', weight: 3.5 },
    { term: 'earn money fast', weight: 4.5 },
    { term: 'congratulations you won', weight: 4.8 },
    { term: 'claim your prize', weight: 4.7 },
    { term: 'seo ranking', weight: 3.8 },
    { term: 'guest post opportunity', weight: 3.8 },
    { term: 'crypto trading bot', weight: 4.2 },
    { term: 'guaranteed returns', weight: 4.2 },
    { term: 'diet pill', weight: 4.5 },
    { term: 'free gift', weight: 3.8 },
    { term: 'limited time promotion', weight: 3.5 },
    { term: 'act now', weight: 3.2 },
    { term: 'marketing agency', weight: 3.0 },
    { term: 'hot deals', weight: 3.8 },
    { term: 'b2b leads list', weight: 4.0 },
    { term: 'viagra', weight: 5.0 },
    { term: 'casino bonus', weight: 4.6 },
    { term: 'lottery', weight: 4.8 },
    { term: 'sweepstakes', weight: 4.8 },
    { term: 'prize draw', weight: 4.6 },
    { term: 'lucky winner', weight: 4.8 },
    { term: 'cash payout', weight: 4.5 }
  ],
  legitimate: [
    { term: 'meeting tomorrow', weight: 3.8 },
    { term: 'agenda for', weight: 3.5 },
    { term: 'sync up', weight: 3.5 },
    { term: 'pull request', weight: 4.0 },
    { term: 'roadmap review', weight: 3.8 },
    { term: 'architecture sync', weight: 4.0 },
    { term: 'quarterly review', weight: 3.6 },
    { term: 'deployment status', weight: 3.8 },
    { term: 'hi team', weight: 3.5 },
    { term: 'best regards', weight: 3.2 },
    { term: 'jira ticket', weight: 4.0 },
    { term: 'slack notification', weight: 3.5 },
    { term: 'calendar invite', weight: 3.8 },
    { term: 'meeting notes', weight: 3.8 },
    { term: 'project timeline', weight: 3.5 },
    { term: 'weekly update', weight: 3.6 },
    { term: 'code review', weight: 4.0 },
    { term: 'customer feedback', weight: 3.4 },
    { term: 'thanks for the update', weight: 3.5 }
  ]
};

// ── Behavioral Pattern Matchers ──
const BEHAVIORAL_SIGNALS = [
  // Urgency & Pressure
  {
    name: 'High Urgency Coercion',
    index: 'urgency',
    pattern: /\b(?:immediately|urgent|within\s*24\s*hours?|act\s*now|before\s*(?:the\s*)?end\s*of\s*(?:the\s*)?day|right\s*away|asap|time\s*sensitive|final\s*notice)\b/i,
    weight: 25,
    categories: { phishing: 25, bec_fraud: 25 }
  },
  // Credential Solicitation
  {
    name: 'Credential Solicitation',
    index: 'credential',
    pattern: /\b(?:verify\s*(?:your\s*)?(?:password|credentials?|account|identity)|(?:password|account)\s*(?:expir(?:ed|ing|es)|suspended|locked)|(?:re-?enter|type|enter)\s*(?:your\s*)?(?:password|credentials?)|login\s*(?:here|below|now|to\s*verify)|sign-in\s*to\s*verify|unlock\s*(?:your\s*)?account|access\s*(?:will\s*be\s*)?terminated)\b/i,
    weight: 35,
    categories: { phishing: 55 }
  },
  // Financial Diversion & Wire Fraud
  {
    name: 'Financial Action / Wire Demand',
    index: 'financial',
    pattern: /\b(?:wire\s*transfer|bank\s*details|routing\s*number|swift\s*code|ach\s*payment|gift\s*card|crypto\s*wallet|remittance\s*advice|invoice\s*revised)\b/i,
    weight: 35,
    categories: { bec_fraud: 45 }
  },
  // Executive Authority Pretexting
  {
    name: 'Executive / Authority Pretexting',
    index: 'impersonation',
    pattern: /\b(?:sent\s*from\s*my\s*iphone|are\s*you\s*at\s*your\s*desk|need\s*you\s*to\s*handle\s*this|keep\s*this\s*confidential|strictly\s*confidential|between\s*us|i['’]m\s*in\s*a\s*meeting)\b/i,
    weight: 30,
    categories: { bec_fraud: 40 }
  },
  // Dangerous Binary / Script Execution
  {
    name: 'Executable / Macro Execution Trap',
    index: 'technical',
    pattern: /\b(?:enable\s*macros?|enable\s*content|enable\s*editing|run\s*(?:the\s*)?(?:setup|installer|application)|\.exe\b|\.scr\b|\.vbs\b|\.iso\b|\.docm\b|\.xlsm\b)\b/i,
    weight: 40,
    categories: { malware: 55 }
  },
  // Marketing & Bulk Spam Phrases
  {
    name: 'Commercial Pitch / Sweepstakes Pattern',
    index: 'spam',
    pattern: /\b(?:unsubscribe\s*(?:here)?|guaranteed\s*returns?|earn\s*\$?\d{3,}|\bseo\s*services?|guest\s*post|claim\s*(?:your\s*)?(?:prize|cash|payout)|you\s*have\s*been\s*selected|lucky\s*winner|lottery|sweepstakes|prize\s*draw|free\s*gift)\b/i,
    weight: 25,
    categories: { spam: 50 }
  }
];

/**
 * Clean & tokenize text
 */
function tokenize(text) {
  if (!text || typeof text !== 'string') return [];
  return text.toLowerCase()
    .replace(/[^\w\s\.-]/g, ' ')
    .split(/\s+/)
    .filter(t => t.length > 2);
}

/**
 * Core Multi-Class Classifier Implementation
 * Evaluates subject, body text, sender, links, and attachments.
 * 
 * @param {Object} emailData
 * @param {string} emailData.subject
 * @param {string} emailData.body_text
 * @param {string} [emailData.sender]
 * @param {Array} [emailData.attachments]
 * @param {Array} [emailData.links]
 * @returns {Object} Full classification report
 */
function classifyEmail(emailData) {
  const subject = String(emailData.subject || '').trim();
  const bodyText = String(emailData.body_text || emailData.body || emailData.bodyText || emailData.snippet || '').trim();
  const sender = String(emailData.sender || '').trim();
  const attachments = Array.isArray(emailData.attachments) ? emailData.attachments : [];
  const links = Array.isArray(emailData.links) ? emailData.links : [];

  const combinedText = `${subject}\n${bodyText}`.toLowerCase();

  // Initialize raw scores with small Laplace prior
  const rawScores = {
    phishing: 1.0,
    bec_fraud: 0.8,
    malware: 0.8,
    spam: 1.2,
    legitimate: 2.0
  };

  const detectedSignals = [];
  const matchingKeywords = [];

  // 1. Evaluate Lexicon Matches
  for (const [catKey, terms] of Object.entries(LEXICON)) {
    for (const item of terms) {
      if (combinedText.includes(item.term)) {
        rawScores[catKey] += item.weight;
        matchingKeywords.push({
          term: item.term,
          category: catKey,
          weight: item.weight
        });
      }
    }
  }

  // 2. Behavioral Cues
  const behavioralIndices = {
    urgency: 0,
    credential: 0,
    financial: 0,
    impersonation: 0,
    technical: 0
  };

  for (const sig of BEHAVIORAL_SIGNALS) {
    if (sig.pattern.test(combinedText)) {
      detectedSignals.push(sig.name);
      if (behavioralIndices[sig.index] !== undefined) {
        behavioralIndices[sig.index] = Math.min(100, behavioralIndices[sig.index] + sig.weight * 2);
      }
      for (const [cat, boost] of Object.entries(sig.categories)) {
        rawScores[cat] += boost;
      }
    }
  }

  // 3. Inspect Attachments for Malware Boost
  for (const att of attachments) {
    const filename = (typeof att === 'string' ? att : att.filename || '').toLowerCase();
    if (/\.(exe|scr|vbs|bat|ps1|iso|img|hta|cpl|docm|xlsm)$/i.test(filename)) {
      rawScores.malware += 45;
      behavioralIndices.technical = Math.min(100, behavioralIndices.technical + 60);
      detectedSignals.push(`Dangerous Attachment: ${filename}`);
    }
  }

  // 4. Sender Brand Spoofing Check (Phishing Boost)
  if (sender) {
    const senderLower = sender.toLowerCase();
    if (/(?:paypal|microsoft|m365|o365|office365|outlook|google|apple|amazon|netflix|bankofamerica|wellsfargo)/i.test(senderLower)) {
      // If not from official domain
      if (!/(?:@paypal\.com|@microsoft\.com|@google\.com|@apple\.com|@amazon\.com|@netflix\.com)/i.test(senderLower)) {
        rawScores.phishing += 40;
        behavioralIndices.credential = Math.min(100, behavioralIndices.credential + 40);
        detectedSignals.push(`Brand Name Mismatch in Sender: ${sender}`);
      }
    }
  }

  // 5. Lookalike / Suspicious Links Check
  const effectiveLinks = Array.isArray(links) ? [...links] : [];
  const textUrls = combinedText.match(/https?:\/\/[^\s"'<>]+/gi) || [];
  textUrls.forEach(u => {
    if (!effectiveLinks.includes(u)) effectiveLinks.push(u);
  });

  for (const link of effectiveLinks) {
    const linkStr = typeof link === 'string' ? link : link.url || '';
    if (/\.(xyz|top|buzz|club|work|click|tk|ml|ga|cf|gq|info)\b/i.test(linkStr)) {
      rawScores.phishing += 30;
      rawScores.malware += 15;
      behavioralIndices.technical = Math.min(100, behavioralIndices.technical + 30);
      detectedSignals.push(`Suspicious TLD in Link: ${linkStr}`);
    }
    if (/(?:bit\.ly|tinyurl\.com|is\.gd|cutt\.ly|t\.co)/i.test(linkStr)) {
      rawScores.phishing += 20;
      detectedSignals.push(`Obfuscated URL Shortener: ${linkStr}`);
    }
  }

  // 6. Calculate Softmax Probabilities
  const totalScore = Object.values(rawScores).reduce((a, b) => a + b, 0);
  const probabilities = {};
  for (const [cat, score] of Object.entries(rawScores)) {
    probabilities[cat] = Math.round((score / totalScore) * 100);
  }

  // Ensure sum equals 100%
  const currentSum = Object.values(probabilities).reduce((a, b) => a + b, 0);
  if (currentSum !== 100) {
    const diff = 100 - currentSum;
    // Add difference to top probability
    let maxCat = 'legitimate';
    let maxVal = -1;
    for (const [c, val] of Object.entries(probabilities)) {
      if (val > maxVal) {
        maxVal = val;
        maxCat = c;
      }
    }
    probabilities[maxCat] = Math.max(0, probabilities[maxCat] + diff);
  }

  // 7. Determine Primary Category by Highest Raw Score
  let primaryCategory = 'legitimate';
  let maxScore = -1;
  for (const [cat, score] of Object.entries(rawScores)) {
    if (score > maxScore) {
      maxScore = score;
      primaryCategory = cat;
    }
  }

  // If selected threat category has weak evidence (< 6.0), fall back to legitimate
  if (primaryCategory !== 'legitimate' && rawScores[primaryCategory] < 6.0 && rawScores.legitimate >= rawScores[primaryCategory]) {
    primaryCategory = 'legitimate';
  }

  const catMeta = CATEGORIES[primaryCategory] || CATEGORIES.legitimate;

  // Confidence calculation (normalized 0..1 and 0..100)
  const highestProb = probabilities[primaryCategory] || 60;
  const confidenceFloat = Math.min(0.99, Math.max(0.55, Math.round(highestProb) / 100));
  const confidenceInt = Math.min(99, Math.max(55, Math.round(highestProb)));

  // Deduplicate and select top signals
  const uniqueSignals = Array.from(new Set(detectedSignals)).slice(0, 6);
  const topKeywords = matchingKeywords.sort((a, b) => b.weight - a.weight).slice(0, 6).map(k => k.term);

  return {
    category: primaryCategory,
    categoryLabel: catMeta.label,
    label: catMeta.label,
    name: catMeta.name,
    description: catMeta.description,
    shortLabel: catMeta.shortLabel,
    badge: catMeta.badge,
    color: catMeta.color,
    bg: catMeta.bg,
    border: catMeta.border,
    icon: catMeta.icon,
    severity: catMeta.severity,
    confidence: confidenceFloat, // e.g. 0.94
    confidencePercent: confidenceInt, // e.g. 94
    action: catMeta.defaultAction,
    recommendedAction: catMeta.defaultAction,
    recommendation: catMeta.defaultAction,
    probabilities: probabilities, // { phishing: 88, bec_fraud: 6, malware: 3, spam: 2, legitimate: 1 }
    behavioralIndices: {
      urgencyScore: behavioralIndices.urgency,
      credentialScore: behavioralIndices.credential,
      financialScore: behavioralIndices.financial,
      impersonationScore: behavioralIndices.impersonation,
      technicalScore: behavioralIndices.technical
    },
    behavioral_indices: {
      urgency_coercion: behavioralIndices.urgency,
      credential_harvest: behavioralIndices.credential,
      financial_redirection: behavioralIndices.financial,
      impersonation_authority: behavioralIndices.impersonation,
      technical_anomaly: behavioralIndices.technical
    },
    signals: uniqueSignals,
    matchedKeywords: topKeywords,
    rationale: `${catMeta.icon} Classified as ${catMeta.label} (${confidenceInt}% confidence). ${catMeta.description}`,
    summaryVerdict: `${catMeta.icon} Classified as **${catMeta.label}** (${confidenceInt}% Confidence). ${catMeta.description}`
  };
}

// ── Built-in Benchmark Datasets for Playground Testing ──
const BENCHMARKS = [
  {
    id: 'phish_login',
    name: '🎣 Credential Phishing (Fake Login Alert)',
    category: 'phishing',
    sender: 'security@service-paypal-verify.com',
    subject: 'URGENT: Suspicious Login Detected from Moscow, Russia',
    body: `Dear Customer,

We detected an unauthorized sign-in attempt to your PayPal account from IP 185.220.101.5 (Moscow, Russia).
Your account has been temporarily restricted to protect your balance ($4,250.00 USD).

To verify your identity and restore access, click the secure verification link immediately:
http://verify-paypal-security-update.com/login?token=89fbc0018d9e

Failure to verify within 24 hours will result in permanent account suspension.

Security Operations Team
PayPal Protection Services`
  },
  {
    id: 'bec_wire',
    name: '💼 BEC / CEO Wire Fraud (Executive Impersonation)',
    category: 'bec_fraud',
    sender: 'ceo-office@company-corp.com',
    subject: 'CONFIDENTIAL: Urgent Wire Transfer Required for Acquisition',
    body: `Hey,

Are you at your desk right now? I am currently in a closed-door board meeting and cannot take calls.

We are closing a confidential acquisition today and I need you to process an urgent wire transfer of $48,500.00 USD to our outside counsel before end of day.

Please find the updated bank details below:
Bank: First National Commercial
Routing Number: 021000021
Account Number: 9840291024
Beneficiary: Apex Legal Escrow Ltd.

Keep this strictly confidential between us for now until the public press release tomorrow morning. Send me the transfer confirmation receipt as soon as it's completed.

Sent from my iPhone`
  },
  {
    id: 'malware_macro',
    name: '☣️ Weaponized Malware (Macro Document Dropper)',
    category: 'malware',
    sender: 'billing@overdue-invoices-notice.net',
    subject: 'Overdue Invoice #INV-89021 Past Due Notice - Immediate Action Required',
    body: `Dear Accounts Payable,

Your payment for Invoice #INV-89021 remains 45 days past due in the amount of $12,480.00 USD.
Legal collection proceedings will initiate if remittance is not confirmed today.

Please download the attached remittance voucher:
Attached: Invoice_Statement_89021.docm (Word Document with Macros)

Note: In order to view the verified digital cryptographic signature, you must click "Enable Editing" and "Enable Content" at the top of Microsoft Word.

Accounts Receivable Department
Global Supply Logistics Ltd.`
  },
  {
    id: 'spam_promo',
    name: '📢 Unsolicited Bulk Marketing (SEO / Crypto Pitch)',
    category: 'spam',
    sender: 'leadgen@digital-growth-accelerators.org',
    subject: 'Exclusive B2B Leads & Guaranteed #1 Google Ranking for CyberSec',
    body: `Hello Team,

I noticed your website while researching leaders in enterprise cybersecurity.
Are you currently looking to acquire 5,000+ verified B2B decision-maker leads every month on autopilot?

Our AI SEO accelerator guarantees #1 Google rankings within 30 days or your money back!
Claim your free 500 verified CEO leads list today:
Visit: https://b2b-growth-deals.xyz/claim-free-trial

To opt-out or unsubscribe from future offers, click here to unsubscribe.`
  },
  {
    id: 'clean_corporate',
    name: '🛡️ Clean Corporate (Internal Engineering Roadmap)',
    category: 'legitimate',
    sender: 'alice@cybersec-enterprise.com',
    subject: 'Q4 SOC Telemetry & Gmail Threat Radar Rollout Architecture',
    body: `Hi Team,

Hope you're having a productive week.

Let's meet tomorrow at 10:00 AM UTC to review the SOC telemetry and Chrome extension integration roadmap for Q4.

Agenda:
1. Threat intelligence feed enhancements
2. Gmail extension rollout status & sandbox testing
3. Zero-trust access policies review

Please review the attached architecture diagram prior to our sync.

Best regards,
Alice Bennett
Security Director | CyberSec Operations`
  }
];

module.exports = {
  CATEGORIES,
  classifyEmail,
  BENCHMARKS,
  BENCHMARK_EMAILS: BENCHMARKS
};
