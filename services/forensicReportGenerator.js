/**
 * CyberSec Advanced Forensic Threat Report & Intelligence Generator
 * Produces enterprise-grade, MITRE ATT&CK-mapped, actionable incident investigation reports
 */

// ── MITRE ATT&CK Tactic & Technique Catalog ──
const MITRE_CATALOG = {
  spearphishing_link: {
    id: 'T1566.002',
    tactic: 'Initial Access (TA0001)',
    name: 'Phishing: Spearphishing Link',
    description: 'Adversaries send spearphishing emails with malicious links to lure targets into credential harvesting pages or drive-by payload drop sites.'
  },
  spearphishing_attachment: {
    id: 'T1566.001',
    tactic: 'Initial Access (TA0001)',
    name: 'Phishing: Spearphishing Attachment',
    description: 'Adversaries attach weaponized files (macro documents, script containers, executables) designed to execute upon user interaction.'
  },
  user_execution_link: {
    id: 'T1204.001',
    tactic: 'Execution (TA0002)',
    name: 'User Execution: Malicious Link',
    description: 'Relies on social engineering pretexting to induce user interaction with an external deceptive link.'
  },
  user_execution_file: {
    id: 'T1204.002',
    tactic: 'Execution (TA0002)',
    name: 'User Execution: Malicious File',
    description: 'Victim opens a malicious attachment leading to arbitrary script or binary code execution on the endpoint.'
  },
  typosquatting: {
    id: 'T1583.001',
    tactic: 'Resource Development (TA0042)',
    name: 'Acquire Infrastructure: Domains / Typosquatting',
    description: 'Adversaries register domains visually or phonetically similar to trusted brands (homoglyphs, letter substitution, subdomains) to evade human inspection.'
  },
  masquerading: {
    id: 'T1036.005',
    tactic: 'Defense Evasion (TA0005)',
    name: 'Masquerading: Match Legitimate Name or Host',
    description: 'Adversary manipulates display names and header metadata to match reputable organizations, bypassing initial visual scrutiny.'
  },
  credential_phishing: {
    id: 'T1056.001',
    tactic: 'Credential Access (TA0006)',
    name: 'Input Capture: Credential Phishing',
    description: 'Adversary deploys fake authentication portals mimicking single sign-on (SSO), Microsoft 365, Google, or banking portals to harvest plain passwords and tokens.'
  },
  aitm: {
    id: 'T1557',
    tactic: 'Credential Access (TA0006)',
    name: 'Adversary-in-the-Middle (AiTM)',
    description: 'Reverse proxy frameworks (e.g. Evilginx) capture session cookies and dynamic MFA one-time codes in transit.'
  },
  secret_exposure: {
    id: 'T1552.001',
    tactic: 'Credential Access (TA0006)',
    name: 'Unsecured Credentials: Credentials in Files / Communications',
    description: 'Cleartext secrets, cloud keys, or private cryptographic keys exposed across unencrypted or unmonitored communication channels.'
  },
  defense_evasion_redirect: {
    id: 'T1564',
    tactic: 'Defense Evasion (TA0005)',
    name: 'Hide Artifacts: URL Obfuscation & Open Redirects',
    description: 'Adversaries use shorteners or open redirects to obscure true payload destinations from static reputation engines.'
  }
};

/**
 * Generate a comprehensive, well-researched cybersecurity incident investigation report
 */
function generateForensicReport(scan) {
  const threatScore = Number(scan.threat_score || 0);
  const threatLevel = scan.threat_level || (threatScore >= 60 ? 'high' : threatScore >= 35 ? 'medium' : 'safe');
  const isPhishing = Boolean(scan.is_phishing);
  
  let summaryObj = {};
  try {
    summaryObj = typeof scan.summary === 'string' ? JSON.parse(scan.summary) : (scan.summary || {});
  } catch (_) {
    summaryObj = {};
  }

  let phishingReasons = [];
  try {
    phishingReasons = typeof scan.phishing_reasons === 'string' ? JSON.parse(scan.phishing_reasons) : (scan.phishing_reasons || []);
  } catch (_) { phishingReasons = []; }

  let maliciousLinks = [];
  try {
    maliciousLinks = typeof scan.malicious_links === 'string' ? JSON.parse(scan.malicious_links) : (scan.malicious_links || []);
  } catch (_) { maliciousLinks = []; }

  let suspiciousAttachments = [];
  try {
    suspiciousAttachments = typeof scan.suspicious_attachments === 'string' ? JSON.parse(scan.suspicious_attachments) : (scan.suspicious_attachments || []);
  } catch (_) { suspiciousAttachments = []; }

  let leakedSecrets = [];
  try {
    leakedSecrets = typeof scan.leaked_secrets === 'string' ? JSON.parse(scan.leaked_secrets) : (scan.leaked_secrets || []);
  } catch (_) { leakedSecrets = []; }

  let authIssues = [];
  try {
    authIssues = typeof scan.auth_issues === 'string' ? JSON.parse(scan.auth_issues) : (scan.auth_issues || []);
  } catch (_) { authIssues = []; }

  // ── 1. Incident Classification ──
  let attackType = 'Legitimate Electronic Communication';
  let cvssVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N';
  let cvssScore = 0.0;

  if (threatLevel === 'critical' || threatScore >= 80) {
    if (leakedSecrets.length > 0) {
      attackType = 'Critical Data Exfiltration & Plaintext Secret Exposure';
      cvssVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H';
      cvssScore = 9.8;
    } else if (maliciousLinks.some(l => l.severity === 'critical') || authIssues.some(a => /impersonate|brand/i.test(a))) {
      attackType = 'Adversary-in-the-Middle (AiTM) / Brand Impersonation Credential Harvest';
      cvssVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N';
      cvssScore = 9.3;
    } else if (suspiciousAttachments.length > 0) {
      attackType = 'Targeted Malware Weaponization & Dropper Lure';
      cvssVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H';
      cvssScore = 9.6;
    } else {
      attackType = 'High-Urgency Social Engineering Pretexting Campaign';
      cvssVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N';
      cvssScore = 8.8;
    }
  } else if (threatLevel === 'high' || threatScore >= 60) {
    attackType = 'Credential Harvesting & External Domain Spoofing Attempt';
    cvssVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:M/A:N';
    cvssScore = 7.5;
  } else if (threatLevel === 'medium' || threatScore >= 35) {
    attackType = 'Suspicious Pretexting / Anomalous Routing Activity';
    cvssVector = 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N';
    cvssScore = 5.3;
  } else if (threatScore > 0) {
    attackType = 'Low-Risk External Communication (Minor Telemetry Indicators)';
    cvssVector = 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N';
    cvssScore = 2.5;
  }

  // ── 2. MITRE ATT&CK Matrix Mapping ──
  const mitreTechniques = [];
  if (maliciousLinks.length > 0) {
    mitreTechniques.push(MITRE_CATALOG.spearphishing_link);
    mitreTechniques.push(MITRE_CATALOG.user_execution_link);
  }
  if (suspiciousAttachments.length > 0) {
    mitreTechniques.push(MITRE_CATALOG.spearphishing_attachment);
    mitreTechniques.push(MITRE_CATALOG.user_execution_file);
  }
  if (authIssues.some(a => /impersonate|brand/i.test(a)) || phishingReasons.some(r => /impersonat/i.test(r))) {
    mitreTechniques.push(MITRE_CATALOG.masquerading);
    mitreTechniques.push(MITRE_CATALOG.typosquatting);
  }
  if (phishingReasons.some(r => /credential|password|login|verify/i.test(r)) || isPhishing) {
    mitreTechniques.push(MITRE_CATALOG.credential_phishing);
    if (threatScore >= 75) {
      mitreTechniques.push(MITRE_CATALOG.aitm);
    }
  }
  if (leakedSecrets.length > 0) {
    mitreTechniques.push(MITRE_CATALOG.secret_exposure);
  }
  if (maliciousLinks.some(l => /shorten|masking|tld/i.test(l.reason))) {
    mitreTechniques.push(MITRE_CATALOG.defense_evasion_redirect);
  }

  // ── 3. Forensic Evidence Breakdown ──
  const senderEmail = (scan.sender || '').toLowerCase().trim();
  const senderDomain = senderEmail.includes('@') ? senderEmail.split('@')[1] : 'unknown';
  const senderName = scan.sender_name || 'Unspecified';

  const forensics = {
    senderAnalysis: {
      displayName: senderName,
      claimedEmail: senderEmail,
      rootDomain: senderDomain,
      spoofVerdict: authIssues.length > 0 ? 'SUSPECT / SPOOFED' : 'VALID / UNTAMPERED',
      authFindings: authIssues.length > 0 ? authIssues : ['No anomalous header rewriting detected. Display name and domain envelope align.']
    },
    linksAnalysis: maliciousLinks.map(l => ({
      url: l.url,
      severity: l.severity || 'high',
      threatCategory: /ip address/i.test(l.reason) ? 'Bypassing DNS (Raw IP Host)' : /lookalike/i.test(l.reason) ? 'Homoglyph / Typosquatted Domain' : /shortened/i.test(l.reason) ? 'Evasive Redirector (URL Shortener)' : 'High-Risk TLD Phishing Campaign',
      tacticalRisk: l.reason
    })),
    attachmentsAnalysis: suspiciousAttachments.map(a => ({
      filename: a.filename,
      extension: a.extension,
      riskLevel: 'CRITICAL',
      payloadVector: a.risk || 'Potentially weaponized payload capable of arbitrary code execution upon double-click.'
    })),
    dataLeaksAnalysis: leakedSecrets.map(s => ({
      secretType: s.type,
      maskedSample: s.sample,
      impact: 'Immediate revocation and secret rotation strictly mandatory. Public or adversary-accessible exposure facilitates unauthorized account/API takeover.'
    })),
    psychologicalTriggers: phishingReasons.map(r => ({
      tactic: r.split('(')[0].trim(),
      context: r.includes('matched:') ? r.split('matched:')[1].replace(/[")]/g, '').trim() : 'Heuristic match',
      intent: /suspension|expire|urgent|immediately/i.test(r) ? 'Coercive Urgency & Panic Induction' : /verify|password|identity/i.test(r) ? 'Fake Administrative Pretexting' : 'Social Engineering Lure'
    }))
  };

  // ── 4. Impact Assessment & Blast Radius ──
  let blastRadius = {
    scope: 'Negligible (Internal Benign)',
    dataExposureRisk: 'None',
    lateralMovementRisk: 'None',
    complianceImpact: 'None'
  };

  if (threatLevel === 'critical' || threatLevel === 'high') {
    blastRadius = {
      scope: 'Enterprise Infrastructure & Identity Tier',
      dataExposureRisk: leakedSecrets.length > 0 ? 'HIGH: Cloud tokens or corporate credentials actively exposed.' : 'CRITICAL: Single Sign-On (SSO) credential theft risking entire enterprise suite.',
      lateralMovementRisk: 'HIGH: Compromised accounts can be leveraged for internal spearphishing and privilege escalation.',
      complianceImpact: 'GDPR / SOC2 / ISO 27001 notification requirements triggered if credentials are used in unauthorized access.'
    };
  } else if (threatLevel === 'medium') {
    blastRadius = {
      scope: 'Workstation / Endpoint Level',
      dataExposureRisk: 'MODERATE: User interaction could expose telemetry or prompt spam.',
      lateralMovementRisk: 'LOW: No active payload execution verified; defense evasion triggers present.',
      complianceImpact: 'Internal security log retention required.'
    };
  }

  // ── 5. Standard Operating Procedure (SOP) & Containment Playbook ──
  const containmentPlaybook = [];
  if (threatScore >= 35) {
    containmentPlaybook.push({
      phase: 'Phase 1: Immediate Triage & Mailbox Quarantine',
      priority: 'P0 - CRITICAL',
      action: `Execute perimeter mail gateway block on domain "${senderDomain}". Quarantine message across all enterprise mailboxes using Message-ID "${scan.message_id || 'N/A'}".`
    });
    containmentPlaybook.push({
      phase: 'Phase 2: Identity & Session Invalidation',
      priority: 'P0 - CRITICAL',
      action: `Check proxy and DNS logs for outbound requests to flagged domains. If target (${scan.recipient || 'recipient'}) clicked links, immediately revoke active IdP sessions, terminate OAuth refresh tokens, and enforce password change.`
    });
    if (maliciousLinks.length > 0) {
      containmentPlaybook.push({
        phase: 'Phase 3: Threat Intelligence Feeds & Perimeter Sinkholing',
        priority: 'P1 - HIGH',
        action: `Add flagged domains to corporate firewall sinkhole list. Submit phishing URLs (${maliciousLinks.map(l => l.url).slice(0, 2).join(', ')}) to Google Safe Browsing and Microsoft Defender Security Intelligence.`
      });
    }
    if (leakedSecrets.length > 0) {
      containmentPlaybook.push({
        phase: 'Phase 4: Cryptographic Secret Revocation',
        priority: 'P0 - CRITICAL',
        action: `Immediately invalidate exposed secrets in AWS IAM / GitHub Developer Settings. Audit CloudTrail and API access logs for anomalous calls made with exposed keys within the last 72 hours.`
      });
    }
    containmentPlaybook.push({
      phase: 'Phase 5: User Communication & Security Awareness',
      priority: 'P2 - MEDIUM',
      action: `Send automated security briefing to ${scan.recipient || 'recipient'} advising them of the neutralized phishing lure and reinforcing protocols on credential verification.`
    });
  } else {
    containmentPlaybook.push({
      phase: 'Phase 1: Verification & Telemetry Audit',
      priority: 'P3 - LOW',
      action: 'No active threat markers detected. Maintain standard SPF/DKIM/DMARC perimeter filtering.'
    });
    containmentPlaybook.push({
      phase: 'Phase 2: Standard Handling',
      priority: 'P3 - LOW',
      action: 'Email classified as authentic business communication. Safe for recipient review.'
    });
  }

  // Case identifier
  const caseId = `CS-IR-${new Date(scan.date || scan.scanned_at || Date.now()).getFullYear()}-${String(scan.id).padStart(5, '0')}`;

  return {
    caseId,
    generatedAt: new Date().toISOString(),
    analystEngine: 'AEGIS CyberSec Neural Threat Analyzer v3.4',
    classification: {
      threatLevel,
      threatScore,
      isPhishing,
      attackType,
      cvssScore,
      cvssVector
    },
    metadata: {
      subject: scan.subject || '(No Subject)',
      sender: senderEmail,
      senderName,
      recipient: scan.recipient || 'Internal Enterprise Recipient',
      timestamp: scan.date || scan.scanned_at || new Date().toISOString(),
      messageId: scan.message_id || `msg-${scan.id}`
    },
    executiveSummary: {
      verdict: summaryObj.verdict || `${threatLevel.toUpperCase()} THREAT DETECTED`,
      intent: summaryObj.intent || 'Suspicious Communication',
      overview: summaryObj.overview || scan.snippet || 'Forensic threat analysis conducted by CyberSec security engine.',
      technicalNarrative: threatScore >= 50
        ? `Adversary leveraged sophisticated social engineering lures mimicking ${senderName || senderDomain}. The communication was crafted to deceive human and automated filters by introducing artificial urgency (${phishingReasons.length} linguistic triggers) coupled with evasive infrastructure (${maliciousLinks.length} flagged URLs). The primary objective is categorized as unauthorized credential harvesting and sensitive token exfiltration.`
        : `Email underwent comprehensive heuristic and cryptographic inspection. No critical indicators of compromise, brand spoofing, or deceptive payloads were detected. Sender domain exhibits legitimate characteristics conforming to normal operational parameters.`
    },
    mitreTechniques,
    forensics,
    blastRadius,
    containmentPlaybook,
    rawArtifacts: {
      snippet: scan.snippet || '',
      bodyExcerpt: (scan.body_text || '').slice(0, 1500)
    }
  };
}

module.exports = {
  generateForensicReport,
  MITRE_CATALOG
};
