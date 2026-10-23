/**
 * CyberSec Email Threat Radar - Gmail Content Script (Manifest V3)
 * Injects non-intrusive threat scanning controls and live forensic dossiers into Gmail.
 */

(() => {
  // Prevent duplicate injection in the same isolated world
  if (window.__CYBERSEC_RADAR_INJECTED__) return;
  window.__CYBERSEC_RADAR_INJECTED__ = true;

  // Prevent duplicate injection across multiple extension instances (e.g. if loaded twice in Chrome)
  if (document.documentElement.dataset.cybersecRadarActive === 'true') {
    return;
  }
  document.documentElement.dataset.cybersecRadarActive = 'true';

  console.log('🛡️ CyberSec Email Threat Radar initialized on Gmail.');

  let observer = null;
  let debounceTimer = null;
  let autoScanEnabled = false;
  const scannedMessages = new Set(); // Prevent duplicate auto-scans for same message element

  // Load configuration from extension storage
  chrome.storage.local.get(['autoScanEnabled'], (res) => {
    autoScanEnabled = Boolean(res?.autoScanEnabled);
  });

  // Listen for storage changes
  chrome.storage.onChanged.addListener((changes) => {
    if (changes.autoScanEnabled) {
      autoScanEnabled = Boolean(changes.autoScanEnabled.newValue);
    }
  });

  /**
   * Official 4-axis crosshair radar shield SVG mark
   * Shared with Landing Page, Admin Dashboard, and Extension Popup
   */
  function getBrandSvg(cls = 'cybersec-trigger-svg', stroke = 'currentColor') {
    return `<svg class="${cls}" viewBox="0 0 46 46" fill="none" xmlns="http://www.w3.org/2000/svg">
      <g stroke="${stroke}" stroke-width="3" stroke-linecap="butt"><line x1="23" y1="0" x2="23" y2="19.5"/><polyline points="14,10.2 23,19.2 32,10.2" fill="none"/></g>
      <g stroke="${stroke}" stroke-width="3" stroke-linecap="butt" transform="rotate(90,23,23)"><line x1="23" y1="0" x2="23" y2="19.5"/><polyline points="14,10.2 23,19.2 32,10.2" fill="none"/></g>
      <g stroke="${stroke}" stroke-width="3" stroke-linecap="butt" transform="rotate(180,23,23)"><line x1="23" y1="0" x2="23" y2="19.5"/><polyline points="14,10.2 23,19.2 32,10.2" fill="none"/></g>
      <g stroke="${stroke}" stroke-width="3" stroke-linecap="butt" transform="rotate(270,23,23)"><line x1="23" y1="0" x2="23" y2="19.5"/><polyline points="14,10.2 23,19.2 32,10.2" fill="none"/></g>
    </svg>`;
  }

  /**
   * Safe DOM helper: Synchronous updates to prevent race conditions
   */
  function safeAppend(parent, child) {
    if (parent && child && !parent.contains(child)) {
      parent.appendChild(child);
    }
  }

  function safeInsertBefore(parent, child, reference) {
    if (parent && child && !parent.contains(child)) {
      parent.insertBefore(child, reference);
    }
  }

  /**
   * Extract email details from a Gmail message container
   */
  function extractEmailData(messageEl) {
    if (!messageEl) return null;

    // 1. Subject extraction
    let subject = '';
    const subjectEl = document.querySelector('h2.hP') ||
                      messageEl.closest('[role="main"]')?.querySelector('h2.hP') ||
                      document.querySelector('[data-thread-perm-id] h2') ||
                      document.querySelector('h2[data-legacy-thread-id]');
    if (subjectEl) {
      subject = subjectEl.innerText.trim();
    }

    // 2. Sender extraction
    let senderEmail = '';
    let senderName = '';

    // Sender email is reliably in span[email] or data-hovercard-id
    const senderEmailEl = messageEl.querySelector('span[email]') ||
                          messageEl.querySelector('.gD') ||
                          messageEl.querySelector('[data-hovercard-id]');
    if (senderEmailEl) {
      senderEmail = senderEmailEl.getAttribute('email') || senderEmailEl.getAttribute('data-hovercard-id') || senderEmailEl.innerText.trim();
      senderName = senderEmailEl.innerText.trim() || senderEmailEl.getAttribute('name') || '';
    }

    // 3. Body text & html extraction
    let bodyText = '';
    let bodyHtml = '';
    const bodyEl = messageEl.querySelector('.a3s.aiL') ||
                   messageEl.querySelector('div[dir="ltr"]') ||
                   messageEl.querySelector('.ii.gt');
    if (bodyEl) {
      bodyText = bodyEl.innerText.trim();
      bodyHtml = bodyEl.innerHTML;
    }

    // 4. Links extraction
    const links = [];
    if (bodyEl) {
      const linkNodes = bodyEl.querySelectorAll('a[href]');
      linkNodes.forEach(a => {
        const href = a.getAttribute('href');
        if (href && !href.startsWith('mailto:') && !href.startsWith('javascript:')) {
          links.push(href);
        }
      });
    }

    // 5. Attachments extraction
    const attachments = [];
    const attNodes = messageEl.querySelectorAll('.a3I, .aZo, [download_url], .aQy');
    attNodes.forEach(att => {
      const name = att.innerText?.trim() || att.getAttribute('download_url') || 'attachment';
      if (name) attachments.push({ filename: name });
    });

    return {
      sender: senderEmail,
      senderName,
      subject,
      bodyText,
      bodyHtml,
      links,
      attachments
    };
  }

  /**
   * Scan an email and display the Threat Dossier
   */
  async function performScan(messageEl, triggerBtn) {
    if (!messageEl) return;

    const emailData = extractEmailData(messageEl);
    if (!emailData || (!emailData.bodyText && !emailData.subject)) {
      alert('CyberSec Radar: Could not read open email content. Please ensure an email is fully opened.');
      return;
    }

    // Update button to scanning state
    if (triggerBtn) {
      triggerBtn.classList.add('cybersec-btn-loading');
      triggerBtn.innerHTML = `
        <span class="cybersec-spinner"></span>
        <span>Scanning Threats...</span>
      `;
    }

    try {
      const response = await chrome.runtime.sendMessage({
        type: 'SCAN_EMAIL',
        data: emailData
      });

      if (!response || !response.success) {
        showErrorBanner(messageEl, response?.error || 'Unable to connect to local CyberSec analysis engine.');
        return;
      }

      // Display the full threat dossier card
      renderThreatDossier(messageEl, response, emailData);

      // Highlight malicious links inside email body
      if (response.maliciousLinks && response.maliciousLinks.length > 0) {
        highlightMaliciousLinks(messageEl, response.maliciousLinks);
      }
    } catch (err) {
      console.error('CyberSec scan error:', err);
      showErrorBanner(messageEl, 'Extension communication error: ' + err.message);
    } finally {
      if (triggerBtn) {
        triggerBtn.classList.remove('cybersec-btn-loading');
        triggerBtn.innerHTML = `
          ${getBrandSvg('cybersec-trigger-svg')}
          <span>Re-Scan Email</span>
        `;
      }
    }
  }

  /**
   * Render the floating or inline Threat Dossier Card
   */
  function renderThreatDossier(messageEl, report, emailData) {
    // Remove any existing dossier in this message
    const existing = messageEl.querySelector('.cybersec-threat-card');
    if (existing) existing.remove();

    const score = report.threatScore || 0;
    const isCritical = score >= 60 || report.isPhishing;
    const isSuspicious = score >= 35 && score < 60;
    const isSafe = score < 35;

    let levelBadge = '';
    let badgeClass = '';
    let icon = '';

    if (isCritical) {
      badgeClass = 'cybersec-card-critical';
      levelBadge = 'CRITICAL PHISHING RISK';
      icon = '🚨';
    } else if (isSuspicious) {
      badgeClass = 'cybersec-card-warning';
      levelBadge = 'SUSPICIOUS EMAIL';
      icon = '⚡';
    } else {
      badgeClass = 'cybersec-card-safe';
      levelBadge = 'VERIFIED SAFE';
      icon = '🛡️';
    }

    const card = document.createElement('div');
    card.className = `cybersec-threat-card ${badgeClass}`;

    const flagsCount = (report.phishingReasons?.length || 0) +
                       (report.maliciousLinks?.length || 0) +
                       (report.authIssues?.length || 0);

    const verdictText = report.summary?.verdict ||
      (isCritical ? 'High-risk security threats detected. Do not click links or provide credentials.' : 'No active malicious patterns detected.');

    let flagsHtml = '';
    if (report.phishingReasons && report.phishingReasons.length > 0) {
      flagsHtml += `
        <div class="cybersec-card-section">
          <div class="cybersec-section-title">⚠️ Threat Indicators (${report.phishingReasons.length})</div>
          <ul class="cybersec-flags-list">
            ${report.phishingReasons.map(r => `<li>${escapeHtml(r)}</li>`).join('')}
          </ul>
        </div>
      `;
    }

    if (report.maliciousLinks && report.maliciousLinks.length > 0) {
      flagsHtml += `
        <div class="cybersec-card-section">
          <div class="cybersec-section-title">🔗 Malicious / Lookalike URLs (${report.maliciousLinks.length})</div>
          <ul class="cybersec-links-list">
            ${report.maliciousLinks.map(l => `
              <li>
                <span class="cybersec-link-url">${escapeHtml(l.url)}</span>
                <span class="cybersec-link-reason">${escapeHtml(l.reason)}</span>
              </li>
            `).join('')}
          </ul>
        </div>
      `;
    }

    if (report.leakedSecrets && report.leakedSecrets.length > 0) {
      flagsHtml += `
        <div class="cybersec-card-section">
          <div class="cybersec-section-title">🔑 Sensitive Data / Leaked Credentials (${report.leakedSecrets.length})</div>
          <ul class="cybersec-flags-list">
            ${report.leakedSecrets.map(s => `<li>Exposed: ${escapeHtml(s.type)}</li>`).join('')}
          </ul>
        </div>
      `;
    }

    const classification = report.classification || {};
    let classificationPill = '';
    if (classification && classification.category) {
      const catLabels = {
        phishing: 'Phishing',
        bec_fraud: 'BEC Fraud',
        malware: 'Malware',
        spam: 'Spam',
        legitimate: 'Legitimate'
      };
      const catName = catLabels[classification.category] || classification.category;
      const confText = classification.confidence !== undefined ? ` (${Math.round(classification.confidence * 100)}%)` : '';
      classificationPill = `
        <span class="cybersec-class-pill cybersec-class-${classification.category}" title="${escapeHtml(classification.description || '')}">
          ${classification.icon || '🎯'} ${catName}${confText}
        </span>
      `;
    }

    card.innerHTML = `
      <div class="cybersec-card-header">
        <div class="cybersec-card-badge-row">
          <span class="cybersec-status-pill ${badgeClass}">
            <span class="cybersec-pulse-dot"></span>
            ${icon} ${levelBadge}
          </span>
          ${classificationPill}
          <div class="cybersec-score-meter">
            <span class="cybersec-score-val">${score}</span>
            <span class="cybersec-score-max">/100 RISK</span>
          </div>
        </div>
        <button class="cybersec-close-btn" title="Dismiss">&times;</button>
      </div>

      <div class="cybersec-card-verdict">
        ${escapeHtml(verdictText)}
      </div>

      ${flagsHtml}

      <div class="cybersec-card-actions">
        <a href="${report.reportUrl || 'http://localhost:3000/admin/email-scanner'}" target="_blank" class="cybersec-card-btn">
          <span>View Full Forensic Dossier →</span>
        </a>
        <span class="cybersec-engine-tag">CyberSec AI Engine</span>
      </div>
    `;

    // Hook close button
    const closeBtn = card.querySelector('.cybersec-close-btn');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => card.remove());
    }

    // Insert card above the email body
    const bodyEl = messageEl.querySelector('.a3s.aiL') || messageEl.querySelector('div[dir="ltr"]');
    if (bodyEl && bodyEl.parentNode) {
      safeInsertBefore(bodyEl.parentNode, card, bodyEl);
    } else {
      safeAppend(messageEl, card);
    }
  }

  /**
   * Highlight dangerous links directly in email body
   */
  function highlightMaliciousLinks(messageEl, maliciousLinks) {
    const urls = maliciousLinks.map(l => l.url.toLowerCase());
    const bodyEl = messageEl.querySelector('.a3s.aiL') || messageEl.querySelector('div[dir="ltr"]');
    if (!bodyEl) return;

    const links = bodyEl.querySelectorAll('a[href]');
    links.forEach(a => {
      const href = (a.getAttribute('href') || '').toLowerCase();
      if (urls.some(u => href.includes(u) || u.includes(href))) {
        a.classList.add('cybersec-malicious-link-highlight');
        a.setAttribute('data-cybersec-warning', 'MALICIOUS LINK - DO NOT CLICK');
        a.title = '⚠️ WARNING: CyberSec detected this link as a high-risk phishing/malicious destination!';
      }
    });
  }

  /**
   * Show error banner if backend is unreachable
   */
  function showErrorBanner(messageEl, errorMsg) {
    const existing = messageEl.querySelector('.cybersec-threat-card');
    if (existing) existing.remove();

    const banner = document.createElement('div');
    banner.className = 'cybersec-threat-card cybersec-card-error';
    banner.innerHTML = `
      <div class="cybersec-card-header">
        <span class="cybersec-status-pill cybersec-card-error">
          ⚠️ CyberSec Radar Offline
        </span>
        <button class="cybersec-close-btn">&times;</button>
      </div>
      <div class="cybersec-card-verdict">
        ${escapeHtml(errorMsg)}
      </div>
      <div class="cybersec-card-actions">
        <span class="cybersec-engine-tag">Please ensure server is running: <code>npm run dev</code> at <code>http://localhost:3000</code></span>
      </div>
    `;

    const closeBtn = banner.querySelector('.cybersec-close-btn');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => banner.remove());
    }

    const bodyEl = messageEl.querySelector('.a3s.aiL') || messageEl.querySelector('div[dir="ltr"]');
    if (bodyEl && bodyEl.parentNode) {
      safeInsertBefore(bodyEl.parentNode, banner, bodyEl);
    } else {
      safeAppend(messageEl, banner);
    }
  }

  /**
   * Inject scan buttons into active Gmail messages
   */
  function injectRadarButtons() {
    // Locate message cards in Gmail thread views.
    // '.adn' is Gmail's canonical top-level message container in thread views.
    const messages = document.querySelectorAll('.adn');
    if (!messages || messages.length === 0) return;

    // Track header action toolbars we've already injected in this pass
    const processedHeaders = new Set();

    messages.forEach((messageEl) => {
      // Find the message header action toolbar (reply, more options, etc.)
      const headerActions = messageEl.querySelector('.gH .gE.iv.gt') ||
                            messageEl.querySelector('.gH') ||
                            messageEl.querySelector('.ha');
      if (!headerActions) return;

      // Prevent duplicate processing in the same pass
      if (processedHeaders.has(headerActions)) return;
      processedHeaders.add(headerActions);

      // Clean up any duplicate scan buttons if more than one exists in this header
      const existingWrappers = headerActions.querySelectorAll('.cybersec-scan-trigger-wrapper');
      if (existingWrappers.length > 1) {
        for (let i = 1; i < existingWrappers.length; i++) {
          existingWrappers[i].remove();
        }
      }

      // If already has a scan trigger or marked as injected, skip
      if (headerActions.querySelector('.cybersec-scan-trigger') || headerActions.dataset.cybersecInjected === 'true') {
        return;
      }

      // Synchronously mark as injected immediately to prevent race conditions
      headerActions.dataset.cybersecInjected = 'true';

      const btnContainer = document.createElement('div');
      btnContainer.className = 'cybersec-scan-trigger-wrapper';

      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'cybersec-scan-trigger';
      btn.innerHTML = `
        ${getBrandSvg('cybersec-trigger-svg')}
        <span>Scan with CyberSec</span>
      `;

      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        e.preventDefault();
        performScan(messageEl, btn);
      });

      btnContainer.appendChild(btn);
      headerActions.appendChild(btnContainer);

      // Auto-scan if enabled in extension settings
      const msgId = messageEl.getAttribute('data-message-id') || messageEl.innerText.substring(0, 50);
      if (autoScanEnabled && !scannedMessages.has(msgId)) {
        scannedMessages.add(msgId);
        setTimeout(() => performScan(messageEl, btn), 600);
      }
    });

    // Clean up any stray or unstyled floating radar pills
    const floatingPills = document.querySelectorAll('.cybersec-floating-radar');
    if (floatingPills.length > 0) {
      floatingPills.forEach((p) => p.remove());
    }
  }

  /**
   * Inject AI Email Writer button into active Gmail Compose windows (both popups and inline replies)
   */
  function injectComposeButtons() {
    // Look for all editable message bodies in Gmail
    const bodyBoxes = document.querySelectorAll(
      'div[aria-label="Message Body"], div[role="textbox"][g_editable="true"], div.Am.Al.editable'
    );
    if (!bodyBoxes || bodyBoxes.length === 0) return;

    const processedToolbars = new Set();

    bodyBoxes.forEach((bodyBox) => {
      // Find the compose window or dialog container
      const container = bodyBox.closest('.AD, [role="dialog"], .M9, .aoI, .ip, .gA') ||
                        bodyBox.closest('form') ||
                        bodyBox.parentElement;
      if (!container) return;

      // Find the action toolbar near the Send button
      const sendCell = container.querySelector('.btC .gU.Up, td.gU.Up, .gU.Up');
      const sendBtn = container.querySelector('div[role="button"][data-tooltip*="Send"], div.T-I-atl, .aoO');
      const toolbarRow = container.querySelector('tr.btC, .btC, [role="toolbar"], .aDh');

      let targetSlot = null;
      let shouldWrapInTd = false;

      if (sendCell) {
        targetSlot = sendCell;
      } else if (sendBtn && sendBtn.parentElement) {
        targetSlot = sendBtn.parentElement;
      } else if (toolbarRow) {
        if (toolbarRow.tagName === 'TR') {
          targetSlot = toolbarRow;
          shouldWrapInTd = true;
        } else {
          targetSlot = toolbarRow;
        }
      }

      if (!targetSlot) return;

      // Deduplicate toolbar slot in the same pass
      if (processedToolbars.has(targetSlot)) return;
      processedToolbars.add(targetSlot);

      // Clean up any duplicate writer buttons if more than one exists in this toolbar
      const existingTriggers = targetSlot.querySelectorAll('.cybersec-writer-trigger');
      if (existingTriggers.length > 1) {
        for (let i = 1; i < existingTriggers.length; i++) {
          existingTriggers[i].remove();
        }
      }

      // If already injected or marked, skip
      if (targetSlot.querySelector('.cybersec-writer-trigger') || targetSlot.dataset.cybersecWriterInjected === 'true') {
        return;
      }

      targetSlot.dataset.cybersecWriterInjected = 'true';
      container.dataset.cybersecWriterInjected = 'true';

      // Create writer button
      const writerBtn = document.createElement('button');
      writerBtn.type = 'button';
      writerBtn.className = 'cybersec-writer-trigger';
      writerBtn.title = 'Compose or refine this email with CyberSec AI';
      writerBtn.innerHTML = `
        ${getBrandSvg('cybersec-trigger-svg')}
        <span>AI Writer</span>
      `;

      writerBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        e.preventDefault();
        openWriterModal(container);
      });

      if (shouldWrapInTd) {
        const td = document.createElement('td');
        td.className = 'gU cybersec-writer-cell';
        td.style.verticalAlign = 'middle';
        td.appendChild(writerBtn);
        targetSlot.appendChild(td);
      } else {
        targetSlot.appendChild(writerBtn);
      }
    });
  }

  /**
   * Open AI Email Writer Sidebar for a specific Compose container
   * Full-featured panel with direct Gemini generation, purpose presets,
   * tone/audience/length pickers, editable output, and API key management.
   */
  function openWriterModal(composeContainer) {
    const existing = document.querySelector('.cybersec-writer-overlay');
    if (existing) existing.remove();

    const subjInput = composeContainer.querySelector('input[name="subjectbox"]');
    const bodyBox = composeContainer.querySelector('div[aria-label="Message Body"]') ||
                    composeContainer.querySelector('div[role="textbox"][g_editable="true"]') ||
                    composeContainer.querySelector('.Am.Al.editable');

    const currentSubj = subjInput ? subjInput.value.trim() : '';

    // Try to auto-detect recipient from the "To:" field
    const toField = composeContainer.querySelector('input[name="to"], textarea[name="to"], [data-hovercard-id]');
    const detectedRecipient = toField ? (toField.value || toField.innerText || '').split(/[,<]/)[0].trim() : '';

    const overlay = document.createElement('div');
    overlay.className = 'cybersec-writer-overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-label', 'CyberSec AI Email Writer');

    overlay.innerHTML = `
      <div class="csw-panel">

        <!-- ── Panel Header ── -->
        <div class="csw-header">
          <div class="csw-header-left">
            ${getBrandSvg('csw-brand-svg', '#ffffff')}
            <div>
              <div class="csw-title">AI Email Writer</div>
              <div class="csw-subtitle" id="cswEngineLabel"><span style="color:#10b981;font-weight:600">● Connected</span> · Gemini AI Active</div>
            </div>
          </div>
          <button type="button" class="csw-close" id="cswCloseBtn" title="Close (Esc)">✕</button>
        </div>

        <!-- ── Scrollable Body ── -->
        <div class="csw-body" id="cswBody">

          <!-- No-key notice (shown when key missing) -->
          <div class="csw-key-notice" id="cswKeyNotice" style="display:none">
            <div class="csw-key-notice-icon">🔑</div>
            <div class="csw-key-notice-text">Add your Gemini API key to generate emails directly — no server needed.</div>
            <button type="button" class="csw-key-notice-btn" id="cswShowKeySetup">Configure Key →</button>
          </div>

          <!-- Key Setup Panel -->
          <div class="csw-key-setup" id="cswKeySetup" style="display:none">
            <div class="csw-section-label">Gemini API Key</div>
            <input type="password" class="csw-input" id="cswKeyInput" placeholder="Paste your key: AIzaSy... or AQ.Ab8..." autocomplete="off" />
            <div class="csw-key-help">Get a free key at <a href="https://aistudio.google.com" target="_blank" rel="noopener">aistudio.google.com</a></div>
            <div style="display:flex;gap:8px;margin-top:8px">
              <button type="button" class="csw-btn csw-btn-primary" id="cswSaveKey">Save Key</button>
              <button type="button" class="csw-btn csw-btn-ghost" id="cswCancelKey">Cancel</button>
            </div>
          </div>

          <!-- ── Purpose Presets ── -->
          <div class="csw-section-label">📌 Email Type</div>
          <div class="csw-chips" id="cswPurposeChips">
            <button type="button" class="csw-chip active" data-p="general">✍️ Custom</button>
            <button type="button" class="csw-chip" data-p="follow_up">⏳ Follow-up</button>
            <button type="button" class="csw-chip" data-p="meeting_request">📅 Meeting</button>
            <button type="button" class="csw-chip" data-p="sales_outreach">🤝 Outreach</button>
            <button type="button" class="csw-chip" data-p="incident_alert">🚨 Incident</button>
            <button type="button" class="csw-chip" data-p="executive_briefing">💼 Briefing</button>
            <button type="button" class="csw-chip" data-p="phishing_training">🎯 Security Drill</button>
            <button type="button" class="csw-chip" data-p="project_update">📊 Status Update</button>
          </div>

          <!-- ── Prompt ── -->
          <div class="csw-section-label" style="margin-top:14px">💬 What should this email communicate?</div>
          <textarea class="csw-textarea" id="cswPrompt" rows="3"
            placeholder="e.g. Follow up on the security audit proposal sent last Monday — ask if they have any questions and suggest a 20-min call this week...">${escapeHtml(currentSubj ? `Subject context: ${currentSubj}` : '')}</textarea>
          <div class="csw-char-count" id="cswCharCount">0 chars</div>

          <!-- ── Controls Row ── -->
          <div class="csw-controls-row">
            <div class="csw-control-group">
              <label class="csw-micro-label">Tone</label>
              <select class="csw-select" id="cswTone">
                <option value="professional">Professional</option>
                <option value="urgent">Urgent</option>
                <option value="friendly">Friendly</option>
                <option value="formal">Formal</option>
                <option value="persuasive">Persuasive</option>
                <option value="reassuring">Reassuring</option>
              </select>
            </div>
            <div class="csw-control-group">
              <label class="csw-micro-label">Length</label>
              <select class="csw-select" id="cswLength">
                <option value="balanced">Balanced</option>
                <option value="concise">Concise</option>
                <option value="detailed">Detailed</option>
              </select>
            </div>
            <div class="csw-control-group">
              <label class="csw-micro-label">Audience</label>
              <select class="csw-select" id="cswAudience">
                <option value="general">General</option>
                <option value="executive">Executive</option>
                <option value="technical">Technical</option>
                <option value="client">Client</option>
                <option value="employees">Employees</option>
                <option value="partner">Partner</option>
              </select>
            </div>
          </div>

          <!-- ── Optional Fields ── -->
          <div class="csw-optional-row">
            <input type="text" class="csw-input-sm" id="cswRecipient" placeholder="Recipient name (optional)" value="${escapeHtml(detectedRecipient)}" />
            <input type="text" class="csw-input-sm" id="cswCta" placeholder="Call to action (optional)" />
          </div>

          <!-- ── Error box ── -->
          <div class="csw-error" id="cswError" style="display:none"></div>

          <!-- ── Generate Button ── -->
          <button type="button" class="csw-btn csw-btn-generate" id="cswGenBtn">
            <span class="csw-gen-spinner" id="cswSpinner" style="display:none"></span>
            <span id="cswGenLabel">Generate with Gemini</span>
          </button>

          <!-- ── Output Section ── -->
          <div class="csw-output" id="cswOutput" style="display:none">

            <div class="csw-divider"></div>

            <!-- Subject Line Picker -->
            <div class="csw-section-label">📧 Select Subject Line</div>
            <div class="csw-subj-list" id="cswSubjList"></div>

            <div class="csw-section-label" style="margin-top:10px">Subject (Editable)</div>
            <input type="text" class="csw-input" id="cswSubjEdit" placeholder="Subject line" />

            <!-- Body Editor -->
            <div class="csw-section-label" style="margin-top:10px">
              Email Body (Editable)
              <span class="csw-word-count" id="cswWordCount"></span>
            </div>
            <textarea class="csw-body-editor" id="cswBodyEdit" rows="10"></textarea>

            <!-- Quick Refine -->
            <div class="csw-section-label" style="margin-top:10px">🔧 Quick Refine</div>
            <div class="csw-refine-chips">
              <button type="button" class="csw-refine-chip" data-tone="urgent">⚡ More Urgent</button>
              <button type="button" class="csw-refine-chip" data-tone="formal">👔 More Formal</button>
              <button type="button" class="csw-refine-chip" data-tone="friendly">🤝 More Friendly</button>
              <button type="button" class="csw-refine-chip" data-len="concise">✂️ Shorten</button>
              <button type="button" class="csw-refine-chip" data-len="detailed">📝 Expand</button>
            </div>

            <!-- Engine tag -->
            <div class="csw-engine-tag" id="cswEngineTag"></div>

            <!-- Action Buttons -->
            <div class="csw-action-row">
              <button type="button" class="csw-btn csw-btn-insert" id="cswInsertBtn">
                📥 Insert into Gmail
              </button>
              <button type="button" class="csw-btn csw-btn-copy" id="cswCopyBtn">
                📋 Copy
              </button>
            </div>
          </div>

          <!-- ── Settings Footer (shown only when no key connected) ── -->
          <div class="csw-footer-actions" id="cswFooterActions" style="display:none">
            <button type="button" class="csw-ghost-link" id="cswManageKeyBtn" style="display:none">⚙️ Configure API Key</button>
          </div>

        </div><!-- /csw-body -->
      </div><!-- /csw-panel -->
    `;

    document.body.appendChild(overlay);

    // ── Refs ──
    const $  = (id) => overlay.querySelector(`#${id}`);
    const promptEl   = $('cswPrompt');
    const charCount  = $('cswCharCount');
    const genBtn     = $('cswGenBtn');
    const genLabel   = $('cswGenLabel');
    const spinner    = $('cswSpinner');
    const errorBox   = $('cswError');
    const output     = $('cswOutput');
    const subjList   = $('cswSubjList');
    const subjEdit   = $('cswSubjEdit');
    const bodyEdit   = $('cswBodyEdit');
    const wordCount  = $('cswWordCount');
    const insertBtn  = $('cswInsertBtn');
    const copyBtn    = $('cswCopyBtn');
    const toneEl     = $('cswTone');
    const lengthEl   = $('cswLength');
    const audienceEl = $('cswAudience');
    const recipientEl= $('cswRecipient');
    const ctaEl      = $('cswCta');
    const engineLabel= $('cswEngineLabel');
    const engineTag  = $('cswEngineTag');
    const keyNotice  = $('cswKeyNotice');
    const keySetup   = $('cswKeySetup');
    const keyInput   = $('cswKeyInput');
    const showKeySetupBtn = $('cswShowKeySetup');
    const saveKeyBtn = $('cswSaveKey');
    const cancelKeyBtn=$('cswCancelKey');
    const manageKeyBtn=$('cswManageKeyBtn');

    let activePurpose = 'general';
    let generatedEmail = null;
    let selectedSubject = '';

    const footerActions = $('cswFooterActions');

    function updateKeyVisibility(isConnected, label) {
      if (isConnected) {
        engineLabel.innerHTML = `<span style="color:#10b981;font-weight:600">● Connected</span> · ${escapeHtml(label || 'Gemini Flash Active')}`;
        keyNotice.style.display = 'none';
        keySetup.style.display = 'none';
        if (footerActions) footerActions.style.display = 'none';
        if (manageKeyBtn) manageKeyBtn.style.display = 'none';
      } else {
        engineLabel.innerHTML = `<span style="color:#f59e0b;font-weight:600">○ No Key</span> · Setup Required`;
        keyNotice.style.display = 'flex';
        keySetup.style.display = 'none';
        if (footerActions) footerActions.style.display = 'flex';
        if (manageKeyBtn) manageKeyBtn.style.display = 'inline-block';
      }
    }

    // ── Check if API key is already stored or available on backend ──
    chrome.runtime.sendMessage({ type: 'GET_GEMINI_KEY' }, (res) => {
      if (res && res.key) {
        updateKeyVisibility(true, 'Gemini Direct Active');
      } else {
        // Check if local CyberSec server has Gemini key configured
        fetch('http://localhost:3000/api/writer/presets')
          .then(r => r.json())
          .then(d => {
            if (d && d.hasGeminiKey) {
              updateKeyVisibility(true, 'Gemini Engine Active');
            } else {
              updateKeyVisibility(false);
            }
          })
          .catch(() => {
            updateKeyVisibility(false);
          });
      }
    });

    // ── Character counter ──
    promptEl.addEventListener('input', () => {
      charCount.textContent = `${promptEl.value.length} chars`;
      hideError();
    });
    charCount.textContent = `${promptEl.value.length} chars`;

    // ── Body editor word count ──
    bodyEdit.addEventListener('input', () => {
      const wc = bodyEdit.value.split(/\s+/).filter(Boolean).length;
      wordCount.textContent = `${wc} words`;
    });

    // ── Purpose chips ──
    const samplePrompts = {
      follow_up: 'Follow up on our security audit proposal sent last Monday — ask if there are questions and suggest a 20-min call this week.',
      meeting_request: 'Request a 30-minute strategy sync with the security architecture team to finalize the zero-trust rollout milestones for Q4.',
      sales_outreach: 'Introduce our 24/7 managed SOC services to this enterprise client — offer a complimentary threat radar evaluation at no cost.',
      incident_alert: 'Notify internal leadership that unauthorized credential use was detected and isolated on server node-04. Password rotation complete. No data exfiltration identified.',
      executive_briefing: 'Summarize this quarter\'s cyber defense telemetry: 99.98% uptime, 0 successful breaches, 412 automated phishing containments.',
      phishing_training: 'Share key lessons from this morning\'s simulated phishing drill. Highlight how to spot lookalike domains and urge reporting.',
      project_update: 'Update stakeholders that the Gmail threat extension v1.2 has been deployed to staging with 100% test pass rate.',
    };

    overlay.querySelectorAll('.csw-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        overlay.querySelectorAll('.csw-chip').forEach(c => c.classList.remove('active'));
        chip.classList.add('active');
        activePurpose = chip.dataset.p;
        if (!promptEl.value.trim() && samplePrompts[activePurpose]) {
          promptEl.value = samplePrompts[activePurpose];
          charCount.textContent = `${promptEl.value.length} chars`;
        }
        hideError();
      });
    });

    // ── Refine chips ──
    overlay.querySelectorAll('.csw-refine-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        if (chip.dataset.tone) toneEl.value = chip.dataset.tone;
        if (chip.dataset.len) lengthEl.value = chip.dataset.len;
        triggerGenerate();
      });
    });

    // ── Key management ──
    function showKeySetupPanel() {
      keyNotice.style.display = 'none';
      keySetup.style.display = 'block';
      keyInput.focus();
    }
    function hideKeySetupPanel() {
      keySetup.style.display = 'none';
    }
    showKeySetupBtn.addEventListener('click', showKeySetupPanel);
    manageKeyBtn.addEventListener('click', showKeySetupPanel);
    cancelKeyBtn.addEventListener('click', hideKeySetupPanel);
    saveKeyBtn.addEventListener('click', () => {
      const key = keyInput.value.trim();
      if (!key) { keyInput.focus(); return; }
      chrome.runtime.sendMessage({ type: 'SAVE_GEMINI_KEY', key }, () => {
        updateKeyVisibility(true, 'Gemini Direct Active');
        hideKeySetupPanel();
        showWriterToast('✅ Gemini API key connected!');
      });
    });

    // ── Close ──
    function closeModal() {
      window.removeEventListener('keydown', onKeydown);
      overlay.remove();
    }
    const onKeydown = (e) => {
      if (e.key === 'Escape' && document.body.contains(overlay)) closeModal();
    };
    window.addEventListener('keydown', onKeydown);
    $('cswCloseBtn').addEventListener('click', closeModal);
    overlay.addEventListener('click', (e) => { if (e.target === overlay) closeModal(); });

    // ── Helpers ──
    function showError(msg) {
      errorBox.textContent = msg;
      errorBox.style.display = 'block';
    }
    function hideError() {
      errorBox.style.display = 'none';
      errorBox.textContent = '';
    }
    function setGenerating(on) {
      genBtn.disabled = on;
      spinner.style.display = on ? 'inline-block' : 'none';
      genLabel.textContent = on ? 'Composing (~1.5s)...' : (output.style.display !== 'none' ? 'Re-Generate' : 'Generate with Gemini');
    }

    // ── Generate ──
    async function triggerGenerate() {
      hideError();
      const promptVal = promptEl.value.trim();
      if (!promptVal) {
        showError('Please describe what this email should communicate.');
        promptEl.focus();
        return;
      }
      setGenerating(true);

      const params = {
        prompt: promptVal,
        purpose: activePurpose,
        tone: toneEl.value,
        length: lengthEl.value,
        audience: audienceEl.value,
        recipientName: recipientEl.value.trim(),
        callToAction: ctaEl.value.trim()
      };

      let response = null;

      // 1. Primary: Direct Gemini via background worker
      try {
        response = await chrome.runtime.sendMessage({
          type: 'GENERATE_EMAIL_GEMINI',
          data: params
        });
      } catch (e) {
        console.warn('Background messaging failed:', e);
      }

      // 2. If no direct key configured in extension, or direct failed: try local backend server
      if (!response || !response.success) {
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 8000);
          const res = await fetch('http://localhost:3000/api/writer/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(params),
            signal: controller.signal
          });
          clearTimeout(timeoutId);
          if (res.ok) {
            response = await res.json();
          }
        } catch (_) {}
      }

      setGenerating(false);

      // 3. If still no valid response because of no key
      if (!response || !response.success || !response.email) {
        if (response?.error === 'NO_KEY') {
          updateKeyVisibility(false);
          showError('Please configure your Gemini API key to activate instant AI drafting.');
          showKeySetupPanel();
          return;
        }
        showError(response?.error || response?.message || 'Generation timed out. Please check your Gemini API key or backend server.');
        return;
      }

      renderOutput(response.email);
    }

    genBtn.addEventListener('click', triggerGenerate);

    // ── Render Output ──
    function renderOutput(email) {
      generatedEmail = email;
      const subjects = email.subjectLines || ['Your Email'];
      selectedSubject = subjects[0];

      // Subject pill picker
      subjList.innerHTML = '';
      subjects.forEach((s, i) => {
        const pill = document.createElement('div');
        pill.className = `csw-subj-pill${i === 0 ? ' active' : ''}`;
        pill.textContent = s;
        pill.addEventListener('click', () => {
          subjList.querySelectorAll('.csw-subj-pill').forEach(p => p.classList.remove('active'));
          pill.classList.add('active');
          selectedSubject = s;
          subjEdit.value = s;
        });
        subjList.appendChild(pill);
      });

      subjEdit.value = selectedSubject;
      bodyEdit.value = email.bodyText || '';
      const wc = (email.bodyText || '').split(/\s+/).filter(Boolean).length;
      wordCount.textContent = `${wc} words`;

      if (email.engine) {
        engineTag.textContent = `⚡ Powered by ${email.engine}`;
        engineTag.style.display = 'block';
      }

      output.style.display = 'block';
      // Scroll to output smoothly
      output.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    // ── Insert into Gmail ──
    insertBtn.addEventListener('click', () => {
      if (!generatedEmail) return;
      const chosenSubj = subjEdit.value.trim() || selectedSubject;
      const chosenText = bodyEdit.value;
      const chosenHtml = chosenText
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/\n\n/g, '</p><p>')
        .replace(/\n/g, '<br>')
        .replace(/^/, '<p>')
        .replace(/$/, '</p>');

      // Insert subject
      const liveSubj = composeContainer.querySelector('input[name="subjectbox"]') ||
                       subjInput ||
                       document.querySelector('input[name="subjectbox"]');
      if (liveSubj && chosenSubj) {
        liveSubj.focus();
        liveSubj.value = chosenSubj;
        liveSubj.dispatchEvent(new Event('input', { bubbles: true }));
        liveSubj.dispatchEvent(new Event('change', { bubbles: true }));
      }

      // Insert body into Gmail contenteditable
      const liveBody = composeContainer.querySelector('div[aria-label="Message Body"]') ||
                       composeContainer.querySelector('div[role="textbox"][g_editable="true"]') ||
                       composeContainer.querySelector('.Am.Al.editable') ||
                       bodyBox ||
                       document.querySelector('div[aria-label="Message Body"]');
      if (liveBody) {
        liveBody.focus();
        try {
          const sel = window.getSelection();
          const range = document.createRange();
          range.selectNodeContents(liveBody);
          sel.removeAllRanges();
          sel.addRange(range);
          if (!document.execCommand('insertHTML', false, chosenHtml)) {
            liveBody.innerHTML = chosenHtml;
          }
        } catch (_) {
          liveBody.innerHTML = chosenHtml;
        }
        liveBody.dispatchEvent(new Event('input', { bubbles: true }));
        liveBody.dispatchEvent(new Event('change', { bubbles: true }));
      }

      showWriterToast('✅ Email inserted into Gmail compose window!');
      closeModal();
    });

    // ── Copy ──
    copyBtn.addEventListener('click', () => {
      const subj = subjEdit.value.trim();
      const body = bodyEdit.value;
      const full = subj ? `Subject: ${subj}\n\n${body}` : body;
      navigator.clipboard.writeText(full).then(() => {
        showWriterToast('📋 Email copied to clipboard!');
      }).catch(() => {
        const ta = document.createElement('textarea');
        ta.value = full;
        ta.style.cssText = 'position:fixed;left:-9999px;top:-9999px';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        showWriterToast('📋 Email copied!');
      });
    });

    // ── Focus prompt ──
    setTimeout(() => promptEl.focus(), 120);
  }




  function showWriterToast(msg) {
    const existing = document.querySelector('.cybersec-writer-toast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.className = 'cybersec-writer-toast';
    toast.textContent = msg;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3500);
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  /**
   * Start DOM observer with debounce
   */
  function startObserver() {
    if (observer) observer.disconnect();

    observer = new MutationObserver(() => {
      if (debounceTimer) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        injectRadarButtons();
        injectComposeButtons();
      }, 350);
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });

    // Initial check
    injectRadarButtons();
    injectComposeButtons();
  }

  // Initialize once Gmail UI is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', startObserver);
  } else {
    startObserver();
  }
})();
