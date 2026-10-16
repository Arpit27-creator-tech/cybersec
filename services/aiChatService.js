/**
 * AEGIS-AI: Autonomous Cyber Defense Intelligence Service
 * Handles conversational queries, threat analysis, security consulting, and CRM lead capture.
 */

const { scanEmailThreats } = require('./threatScanner');

// ── CYBERSECURITY KNOWLEDGE BASE & INTENT PATTERNS ──
const KNOWLEDGE_BASE = [
  {
    id: 'zero_trust',
    triggers: [/zero[\s-]trust/i, /ztna/i, /never trust/i, /least privilege/i, /microsegment/i],
    title: 'Zero-Trust Architecture (ZTA)',
    badge: 'ARCHITECTURE',
    reply: `**Zero-Trust Architecture: "Never Trust, Always Verify"**

CyberSec implements strict Zero-Trust Frameworks adhering to NIST SP 800-207 standards:

• **Continuous Verification**: Dynamic authentication & authorization per-session, assessing device health, user identity, and behavioral anomalies.
• **Micro-Segmentation**: Isolates network workloads into secure trust zones to prevent lateral threat movement.
• **Least-Privilege Access (PoLP)**: Strict Just-in-Time (JIT) and Just-Enough-Access (JEA) permissions.
• **Software-Defined Perimeter (SDP)**: Hides sensitive infrastructure behind encrypted tunnels before access is granted.

Would you like to schedule a Zero-Trust readiness assessment for your infrastructure?`,
    quickReplies: ['Schedule Zero-Trust Audit', 'Compare with VPN', 'Talk to an Engineer']
  },
  {
    id: 'soc_monitoring',
    triggers: [/soc/i, /24\/7/i, /monitoring/i, /mdr/i, /siem/i, /detection/i, /incident response/i, /active defense/i],
    title: '24/7 Managed SOC & Active Defense',
    badge: 'OPERATIONS',
    reply: `**24/7 Managed SOC (Security Operations Center)**

Our military-grade SOC provides round-the-clock telemetry, threat hunting, and automated remediation:

• **< 5-Minute Mean Time to Detect (MTTD)** across multi-cloud and on-premise endpoints.
• **AI-Assisted Triaging**: Correlates millions of log events to isolate true zero-day threats from benign noise.
• **Automated Containment**: Immediate process termination, host quarantine, and credential revocation upon malicious behavior.
• **Dedicated Threat Hunters**: Proactive offensive sweeps targeting APT (Advanced Persistent Threat) groups.

Our SOC currently protects 300+ enterprise clients globally with 99.99% operational uptime.`,
    quickReplies: ['Request SOC Demo', 'View SLA & Response Times', 'Get Pricing']
  },
  {
    id: 'penetration_testing',
    triggers: [/pen[\s-]?test/i, /ethical hack/i, /vulnerability/i, /red team/i, /bug bounty/i, /exploit/i],
    title: 'Offensive Penetration Testing & Red Teaming',
    badge: 'OFFENSIVE SEC',
    reply: `**Comprehensive Penetration Testing & Red Teaming**

We simulate real-world adversarial attacks before malicious actors can exploit your weaknesses:

• **Web App & API Assessment**: OWASP Top 10, GraphQL, JWT vulnerabilities, business logic bypasses.
• **Cloud Infrastructure Audits**: AWS, Azure, GCP IAM misconfigurations, bucket leaks, privilege escalation paths.
• **Adversary Simulation (Red Teaming)**: Physical security, social engineering, covert C2 payload deployment.
• **Executive & Technical Reports**: Detailed CVSSv3 scoring, proof-of-concept exploits, and step-by-step remediation code.

All penetration tests come with a free re-test within 30 days of patch deployment.`,
    quickReplies: ['Book a Pen Test', 'View Sample Report', 'Contact Sales']
  },
  {
    id: 'compliance',
    triggers: [/compliance/i, /soc\s*2/i, /iso\s*27001/i, /hipaa/i, /gdpr/i, /pci[\s-]?dss/i, /audit/i, /nist/i],
    title: 'Regulatory Compliance & Governance',
    badge: 'COMPLIANCE',
    reply: `**Regulatory Compliance & Continuous Audit Readiness**

We streamline security compliance to help your company close enterprise contracts faster:

• **SOC 2 Type I & Type II**: Automated evidence collection, policy drafting, and gap remediation.
• **ISO/IEC 27001:2022**: Complete Information Security Management System (ISMS) implementation.
• **HIPAA & HITECH**: Comprehensive PHI encryption, access controls, and audit trails.
• **PCI-DSS 4.0**: Payment card data protection, tokenization, and vulnerability scanning.
• **GDPR & CCPA**: Privacy impact assessments, data mapping, and automated consent management.`,
    quickReplies: ['Start Compliance Assessment', 'SOC 2 Readiness Check', 'Speak with Specialist']
  },
  {
    id: 'phishing_protection',
    triggers: [/phish/i, /email security/i, /bec/i, /typosquat/i, /spoof/i, /dmarc/i, /dkim/i, /spf/i],
    title: 'Phishing & Email Threat Intelligence',
    badge: 'EMAIL SEC',
    reply: `**Advanced Email & Phishing Defense Engine**

Email remains the #1 initial breach vector (accounting for 91% of enterprise attacks). Our integrated defense system features:

• **Heuristic & Natural Language Scanning**: Real-time detection of urgency lures, CEO fraud (BEC), and invoice redirection scams.
• **Domain Typosquatting Watch**: Identifies lookalike brand domains (e.g. \`paypa1.com\`, \`0ffice365.com\`).
• **Header & Cryptographic Verification**: Strict SPF, DKIM, and DMARC enforcement to block domain spoofing.
• **Payload & Attachment Sandbox**: Disarms malicious macros (\`.xlsm\`, \`.docm\`), executables, and obfuscated disk images (\`.iso\`).

💡 *Tip: You can paste any suspicious email or URL directly into this chat to scan it right now!*`,
    quickReplies: ['Scan Suspicious Link Now', 'Test Phishing Scanner', 'Book Demo']
  },
  {
    id: 'pricing_consultation',
    triggers: [/price/i, /cost/i, /quote/i, /hire/i, /sales/i, /consult/i, /demo/i, /meeting/i, /contact/i, /schedule/i],
    title: 'Consultation & Pricing Inquiries',
    badge: 'SALES & DEMO',
    reply: `**Enterprise Security Solutions & Tailored Pricing**

Every organization has unique threat surfaces. We offer flexible tiers tailored to your scale:

• **Startup Security Essentials**: Core vulnerability scanning, automated email protection & compliance starter pack.
• **Growth & Scale Tier**: Managed SOC monitoring, bi-annual penetration tests & SOC 2 certification support.
• **Enterprise Active Defense**: Dedicated 24/7 CSIRT, full red-teaming, custom zero-trust deployment & guaranteed 15-minute SLA.

Would you like to schedule a confidential security discovery session? You can share your details directly in this chat or visit our [Contact Page](/contact).`,
    quickReplies: ['Book Discovery Session', 'Get a Custom Quote', 'Talk to Sales']
  },
  {
    id: 'stats_company',
    triggers: [/who are you/i, /about cybersec/i, /stats/i, /track record/i, /clients/i, /satisfaction/i, /experience/i],
    title: 'CyberSec Company Overview & Performance',
    badge: 'TRACK RECORD',
    reply: `**About CyberSec: Engineered for Total Resilience**

CyberSec is an elite cybersecurity engineering and threat intelligence firm:

• **300+ Enterprise Clients** protected across FinTech, HealthTech, Defense, and SaaS.
• **99% Client Satisfaction** with zero uncontained breaches across all managed environments.
• **$5M+ Protected Infrastructure Value** across global multi-cloud workloads.
• **Sub-5 Minute Incident Containment** powered by autonomous SOC telemetry.

Our security architecture is built directly into every layer of your software stack.`,
    quickReplies: ['View Our Services', 'Schedule Consultation', 'Run Threat Scan']
  },
  {
    id: 'ransomware_defense',
    triggers: [/ransomware/i, /malware/i, /encrypt/i, /extortion/i, /data breach/i],
    title: 'Ransomware Prevention & Recovery',
    badge: 'THREAT DEFENSE',
    reply: `**Ransomware Prevention & Rapid Recovery Protocol**

Ransomware attacks inflict average recovery costs exceeding $4.5M. CyberSec protects your enterprise through:

• **Immutable Air-Gapped Backups**: Cryptographically isolated backups that cannot be modified or encrypted by attackers.
• **Behavioral EDR / XDR**: Terminates ransomware encryption routines within milliseconds of first file modification attempt.
• **Active Directory Hardening**: Blocks Tier-0 domain controller takeover and privileged token theft (Kerberoasting / Pass-the-Hash).
• **Breach Warranty & CSIRT**: Immediate forensic deployment to neutralize extortion attempts.`,
    quickReplies: ['Ransomware Readiness Audit', 'Book CSIRT Consultation', 'Scan a File/Link']
  }
];

// ── GREETING & FALLBACK RESPONSES ──
const GREETINGS = [
  `Greetings. I am **AEGIS-AI**, CyberSec's autonomous security intelligence assistant. 

How can I assist your defense posture today?

• Ask me about **Zero-Trust Architecture**, **Managed SOC**, or **Penetration Testing**.
• Paste a **suspicious URL, email, or domain** to run a live threat scan.
• Request an **enterprise consultation or custom security audit**.`,
];

const SCAN_PROMPT_REPLY = `🛡️ **Interactive Live Threat Scanner Ready**

Paste any suspicious email content, URL link, sender header, or domain into the chat. I will immediately analyze:
1. Typosquatting / Lookalike Brand impersonation
2. Social engineering & urgency lures
3. Phishing domain reputation & suspicious TLDs
4. Hidden credential harvesting traps`;

/**
 * Perform direct text / URL threat scan
 */
function scanContent(content) {
  if (!content || typeof content !== 'string') {
    return {
      threat_score: 0,
      threat_level: 'safe',
      is_phishing: false,
      phishing_reasons: [],
      malicious_links: [],
      suspicious_attachments: [],
      leaked_secrets: [],
      auth_issues: [],
      summary: { overview: 'No content provided for scan.', verdict: 'Empty input.' }
    };
  }

  // Build simulated email object to feed into threatScanner
  const isUrl = /^https?:\/\/[^\s]+$/i.test(content.trim());
  const emailPayload = {
    subject: isUrl ? `URL Scan: ${content.trim()}` : (content.length > 50 ? content.slice(0, 50) + '...' : content),
    sender: isUrl ? `security-scan@${content.replace(/^https?:\/\//i, '').split('/')[0]}` : 'user-submitted@scan.local',
    body_text: content,
    attachments: []
  };

  const result = scanEmailThreats(emailPayload);

  let parsedSummary = {};
  try {
    parsedSummary = JSON.parse(result.summary);
  } catch (e) {
    parsedSummary = { overview: content.slice(0, 100), verdict: 'Scan completed.' };
  }

  return {
    threat_score: result.threat_score,
    threat_level: result.threat_level,
    is_phishing: result.is_phishing === 1,
    phishing_reasons: JSON.parse(result.phishing_reasons || '[]'),
    malicious_links: JSON.parse(result.malicious_links || '[]'),
    suspicious_attachments: JSON.parse(result.suspicious_attachments || '[]'),
    leaked_secrets: JSON.parse(result.leaked_secrets || '[]'),
    auth_issues: JSON.parse(result.auth_issues || '[]'),
    summary: parsedSummary
  };
}

/**
 * Format threat scan result as rich markdown
 */
function formatScanMarkdown(scan, rawQuery) {
  const levelEmoji = {
    critical: '🚨 CRITICAL THREAT DETECTED',
    high: '⚠️ HIGH RISK DETECTED',
    medium: '⚡ MEDIUM RISK DETECTED',
    safe: '🛡️ VERIFIED SAFE'
  }[scan.threat_level] || '🛡️ VERIFIED SAFE';

  let md = `### ${levelEmoji} (Threat Score: ${scan.threat_score}/100)\n\n`;
  
  if (scan.summary && scan.summary.verdict) {
    md += `**Verdict**: ${scan.summary.verdict}\n\n`;
  }

  if (scan.phishing_reasons && scan.phishing_reasons.length > 0) {
    md += `**Detected Risk Factors**:\n`;
    scan.phishing_reasons.forEach(r => {
      md += `• 🚩 ${r}\n`;
    });
    md += `\n`;
  }

  if (scan.malicious_links && scan.malicious_links.length > 0) {
    md += `**Flagged Links / Domains**:\n`;
    scan.malicious_links.forEach(l => {
      md += `• \`${l.url || l.domain || l}\` — *${l.reason || 'Suspicious domain characteristics'}*\n`;
    });
    md += `\n`;
  }

  if (scan.leaked_secrets && scan.leaked_secrets.length > 0) {
    md += `**Sensitive Data Discovered**:\n`;
    scan.leaked_secrets.forEach(s => {
      md += `• 🔐 *${s.type || 'Secret'}*: \`${s.match || s.preview || 'Redacted'}\`\n`;
    });
    md += `\n`;
  }

  if (scan.threat_score >= 35) {
    md += `> **Security Recommendation**: Do not enter credentials, click hyperlinks, or download attached payloads from this source.`;
  } else {
    md += `> **Security Recommendation**: No critical threat signatures detected. Always practice zero-trust hygiene before sharing confidential data.`;
  }

  return md;
}

/**
 * Main conversational processing engine
 */
async function processChatMessage({ message, conversationHistory = [] }) {
  const text = (message || '').trim();
  if (!text) {
    return {
      reply: GREETINGS[0],
      quickReplies: ['Zero-Trust Architecture', '24/7 Managed SOC', 'Scan Suspicious Link', 'Book Security Audit'],
      actions: []
    };
  }

  // 1. Check if user is asking to trigger the scanner tool
  if (/^(scan|analyze|check|test)\s*(url|link|email|domain|text)?$/i.test(text) || text.toLowerCase() === 'scan' || text.toLowerCase() === 'scan suspicious link' || text.toLowerCase() === 'scan suspicious link now') {
    return {
      reply: SCAN_PROMPT_REPLY,
      quickReplies: ['http://paypal-security-update.xyz/login', 'https://cybersec.com', 'Schedule Consultation'],
      actions: [{ type: 'FOCUS_SCAN_INPUT' }]
    };
  }

  // 2. Check if the message itself is a URL or explicit threat snippet to scan
  const hasUrl = /https?:\/\/[^\s]+/i.test(text) || /www\.[^\s]+/i.test(text) || /\b[a-zA-Z0-9-]+\.(xyz|top|tk|ml|ga|cf|gq|buzz|club|work|loan|stream)\b/i.test(text);
  const explicitScanRequest = /(analyze|scan|check this|is this safe|phishing|virus|malware|suspicious)/i.test(text) && text.length > 15;
  const isSuspiciousContent = /password will expire|urgent payment|wire transfer|account suspended|verify your account|claim your prize/i.test(text);

  if ((hasUrl || explicitScanRequest || isSuspiciousContent) && text.length > 5) {
    const scanReport = scanContent(text);
    if (scanReport.threat_score > 0 || hasUrl || explicitScanRequest) {
      return {
        reply: formatScanMarkdown(scanReport, text),
        quickReplies: ['Scan Another Link', 'How to Block Phishing', 'Book Security Audit'],
        threatReport: scanReport,
        actions: [{ type: 'DISPLAY_THREAT_REPORT', data: scanReport }]
      };
    }
  }

  // 3. Check for consultation / lead intent
  if (/(schedule|book|demo|consult|meeting|hire|quote|talk to (sales|human|engineer)|sales team|contact form|fill contact form)/i.test(text)) {
    return {
      reply: `**Schedule an Enterprise Security Discovery Session**

Our senior cyber defense engineers can evaluate your security perimeter, review active compliance requirements, and demonstrate our 24/7 SOC telemetry.

Please fill out our instant consultation form below:`,
      quickReplies: ['View Pricing Tiers', 'Explore Services', 'Scan a Link'],
      actions: [{ type: 'SHOW_LEAD_FORM' }]
    };
  }

  // 4. Check Knowledge Base Triggers
  for (const item of KNOWLEDGE_BASE) {
    for (const trigger of item.triggers) {
      if (trigger.test(text)) {
        return {
          reply: item.reply,
          quickReplies: item.quickReplies,
          badge: item.badge,
          actions: []
        };
      }
    }
  }

  // 5. Check for General Greetings
  if (/^(hi|hello|hey|greetings|morning|afternoon|evening|help|what can you do)/i.test(text)) {
    return {
      reply: `Hello! I am **AEGIS-AI**, your dedicated cyber defense assistant. 

Here are a few ways I can help you:
• 🛡️ **Threat & URL Scanner**: Paste any email, link, or domain to detect phishing and malware indicators.
• ⚡ **Architecture Advice**: Learn about Zero-Trust, API Security, and Cloud Posture.
• 🔍 **Services & Pricing**: Explore our Managed SOC, Penetration Testing, and Compliance audits.
• 📅 **Schedule a Consultation**: Connect directly with our cybersecurity engineering team.

What would you like to explore?`,
      quickReplies: ['Zero-Trust Architecture', '24/7 Managed SOC', 'Scan Suspicious Link', 'Book Security Audit'],
      actions: []
    };
  }

  // 6. Intelligent Fallback with Adaptive Context
  return {
    reply: `**AEGIS Defense Query Analysis**

I've processed your query regarding: *"${text.length > 60 ? text.slice(0, 57) + '...' : text}"*.

CyberSec provides end-to-end security architecture across all system layers. Here are relevant defense vectors you might be interested in:

• **Autonomous Email & Phishing Scanner**: Real-time analysis of domain spoofing, urgency heuristics & credential traps.
• **Zero-Trust Network Access (ZTNA)**: Cryptographic identity verification and least-privilege microsegmentation.
• **Offensive Penetration Testing**: Deep OWASP & infrastructure assessments with actionable remediation playbooks.
• **24/7 Managed SOC**: Sub-5 minute threat isolation with active defensive telemetry.

Would you like to analyze a specific system, run a scan, or speak with an engineer?`,
    quickReplies: ['Scan a Link / Email', 'Schedule Audit', 'Explore Zero-Trust', 'Contact Sales'],
    actions: []
  };
}

module.exports = {
  processChatMessage,
  scanContent,
  KNOWLEDGE_BASE
};
