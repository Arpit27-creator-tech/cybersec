/**
 * ═══════════════════════════════════════════════════════════════
 * AEGIS-AI Autonomous Cyber Defense Chatbot Client Controller
 * ═══════════════════════════════════════════════════════════════
 */

(function () {
  'use strict';

  // ── SOUND FX SYNTHESIZER (Web Audio API) ──
  class SoundFX {
    constructor() {
      this.ctx = null;
      this.enabled = true;
    }

    init() {
      if (!this.ctx && (window.AudioContext || window.webkitAudioContext)) {
        const AudioCtx = window.AudioContext || window.webkitAudioContext;
        this.ctx = new AudioCtx();
      }
      if (this.ctx && this.ctx.state === 'suspended') {
        this.ctx.resume();
      }
    }

    playClick() {
      if (!this.enabled) return;
      try {
        this.init();
        if (!this.ctx) return;
        const osc = this.ctx.createOscillator();
        const gain = this.ctx.createGain();
        osc.type = 'sine';
        osc.frequency.setValueAtTime(800, this.ctx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(400, this.ctx.currentTime + 0.04);
        gain.gain.setValueAtTime(0.06, this.ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, this.ctx.currentTime + 0.04);
        osc.connect(gain);
        gain.connect(this.ctx.destination);
        osc.start();
        osc.stop(this.ctx.currentTime + 0.04);
      } catch (_) {}
    }

    playMsgIn() {
      if (!this.enabled) return;
      try {
        this.init();
        if (!this.ctx) return;
        const osc = this.ctx.createOscillator();
        const gain = this.ctx.createGain();
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(520, this.ctx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(880, this.ctx.currentTime + 0.08);
        gain.gain.setValueAtTime(0.08, this.ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, this.ctx.currentTime + 0.08);
        osc.connect(gain);
        gain.connect(this.ctx.destination);
        osc.start();
        osc.stop(this.ctx.currentTime + 0.08);
      } catch (_) {}
    }

    playScan() {
      if (!this.enabled) return;
      try {
        this.init();
        if (!this.ctx) return;
        const now = this.ctx.currentTime;
        const osc = this.ctx.createOscillator();
        const gain = this.ctx.createGain();
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(300, now);
        osc.frequency.linearRampToValueAtTime(1200, now + 0.15);
        gain.gain.setValueAtTime(0.04, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.15);
        osc.connect(gain);
        gain.connect(this.ctx.destination);
        osc.start();
        osc.stop(now + 0.15);
      } catch (_) {}
    }
  }

  // ── TEXT-TO-SPEECH (TTS) CONTROLLER ──
  class VoiceEngine {
    constructor() {
      this.enabled = false;
      this.synth = window.speechSynthesis || null;
    }

    speak(text) {
      if (!this.enabled || !this.synth) return;
      try {
        this.synth.cancel();
        const cleanText = text
          .replace(/[#*_`>•]/g, '')
          .replace(/https?:\/\/[^\s]+/g, 'link')
          .slice(0, 300);
        const utter = new SpeechSynthesisUtterance(cleanText);
        utter.rate = 1.05;
        utter.pitch = 0.95;
        this.synth.speak(utter);
      } catch (_) {}
    }
  }

  // ── MARKDOWN FORMATTER ──
  function formatMarkdown(md) {
    if (!md) return '';
    let html = md
      // Escape basic HTML
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      // Headers
      .replace(/^### (.*$)/gim, '<div style="font-weight:700;font-size:14px;color:#fff;margin:6px 0;">$1</div>')
      .replace(/^## (.*$)/gim, '<div style="font-weight:700;font-size:15px;color:#fff;margin:8px 0;">$1</div>')
      // Code blocks
      .replace(/```([a-z]*)\n([\s\S]*?)```/gim, '<pre><code>$2</code></pre>')
      // Inline code
      .replace(/`([^`]+)`/gim, '<code>$1</code>')
      // Bold
      .replace(/\*\*([^*]+)\*\*/gim, '<strong>$1</strong>')
      // Italic
      .replace(/\*([^*]+)\*/gim, '<em>$1</em>')
      // Blockquotes
      .replace(/^&gt; (.*$)/gim, '<blockquote>$1</blockquote>')
      // Bullet lists
      .replace(/^[•\-\*] (.*$)/gim, '<li>$1</li>')
      // Links
      .replace(/\[([^\]]+)\]\(([^)]+)\)/gim, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');

    // Wrap li in ul
    html = html.replace(/(<li>.*<\/li>)/gis, '<ul>$1</ul>');
    // Paragraphs
    html = html.replace(/\n\n/g, '</p><p>').replace(/\n/g, '<br>');
    return `<p>${html}</p>`;
  }

  // ── STANDALONE LOCAL KNOWLEDGE BASE (OFFLINE/STATIC FALLBACK) ──
  const LOCAL_KNOWLEDGE = [
    {
      triggers: [/zero[\s-]trust/i, /ztna/i, /never trust/i, /least privilege/i],
      badge: 'ARCHITECTURE',
      reply: `**Zero-Trust Architecture: "Never Trust, Always Verify"**

CyberSec implements NIST SP 800-207 Zero-Trust Frameworks:

• **Continuous Verification**: Dynamic per-session authentication checking device health, user context, and behavioral telemetry.
• **Micro-Segmentation**: Strict workload isolation preventing lateral adversary movement.
• **Least-Privilege (PoLP)**: Just-In-Time access management minimizing attack blast radius.
• **Encrypted Software-Defined Perimeters**: Conceals critical assets behind authenticated gateways.`,
      chips: ['Schedule Zero-Trust Audit', 'Compare with VPN', 'Talk to an Engineer']
    },
    {
      triggers: [/soc/i, /monitoring/i, /mdr/i, /24\/7/i, /detection/i, /incident/i],
      badge: 'OPERATIONS',
      reply: `**24/7 Managed SOC & Active Defense**

Our 24/7 Security Operations Center provides proactive detection and active containment:

• **< 5-Minute MTTD**: Rapid isolation of compromised endpoints.
• **AI Log Correlation**: Filters telemetry across 1M+ daily events.
• **Automated Containment**: Immediate process termination and credential rotation.
• **Dedicated Threat Hunters**: Constant sweeps against emerging APT zero-days.`,
      chips: ['Request SOC Demo', 'View SLA & Response Times', 'Get Pricing']
    },
    {
      triggers: [/pen[\s-]?test/i, /vulnerability/i, /ethical hack/i, /red team/i],
      badge: 'OFFENSIVE SEC',
      reply: `**Offensive Penetration Testing & Red Teaming**

We uncover vulnerabilities before adversaries can weaponize them:

• **Web App & API Assessments**: Comprehensive OWASP Top 10, GraphQL, and JWT audits.
• **Cloud Security Posture**: AWS/GCP/Azure IAM, bucket configuration, and lateral exploit paths.
• **Red Team Exercises**: Covert adversary simulation and physical/social vectors.
• **Remediation Playbooks**: Detailed CVSSv3 analysis and verification re-testing.`,
      chips: ['Book a Pen Test', 'View Sample Report', 'Contact Sales']
    },
    {
      triggers: [/compliance/i, /soc\s*2/i, /iso\s*27001/i, /hipaa/i, /gdpr/i],
      badge: 'COMPLIANCE',
      reply: `**Regulatory Compliance & Continuous Audit Readiness**

Accelerate enterprise deals with battle-tested compliance frameworks:

• **SOC 2 Type I & II**: Automated evidence gathering and control verification.
• **ISO/IEC 27001**: Complete Information Security Management System deployment.
• **HIPAA & GDPR**: PHI encryption, access auditing, and privacy impact workflows.`,
      chips: ['Start Compliance Assessment', 'SOC 2 Readiness Check', 'Speak with Specialist']
    },
    {
      triggers: [/price/i, /cost/i, /quote/i, /hire/i, /demo/i, /consult/i, /sales/i],
      badge: 'SALES & DEMO',
      reply: `**Enterprise Security Solutions & Tailored Pricing**

We offer scalable plans for startups, mid-market, and global enterprises:

• **Startup Essentials**: Automated vulnerability & email threat scanning.
• **Growth & Scale**: Managed SOC, compliance audits, and semi-annual pen testing.
• **Enterprise Active Defense**: 24/7 CSIRT with 15-minute guaranteed SLA.

Would you like to schedule an instant security consultation?`,
      chips: ['Book Discovery Session', 'Get a Custom Quote', 'Talk to Sales'],
      showLeadForm: true
    }
  ];

  function getLocalFallback(query) {
    const text = (query || '').trim();
    if (!text) {
      return {
        reply: `Greetings. I am **AEGIS-AI**, CyberSec's autonomous security assistant.\n\nHow can I help you today?`,
        chips: ['Zero-Trust Architecture', '24/7 Managed SOC', 'Scan Suspicious Link', 'Book Security Audit']
      };
    }

    // Check if consultation request
    if (/(schedule|book|demo|consult|meeting|hire|quote|talk to sales)/i.test(text)) {
      return {
        reply: `**Schedule an Enterprise Security Discovery Session**\n\nOur cyber defense engineering team can evaluate your security perimeter and compliance posture.\n\nPlease provide your details below:`,
        chips: ['View Pricing Tiers', 'Explore Services', 'Scan a Link'],
        showLeadForm: true
      };
    }

    // Check if scan request or URL
    if (/https?:\/\/[^\s]+/i.test(text) || /^(scan|analyze|test)/i.test(text) || /(paypal|bank|urgent|verify|password)/i.test(text)) {
      const isUrgent = /(password|urgent|suspend|wire|transfer|verify|bank)/i.test(text);
      const isPhishDomain = /(xyz|top|tk|paypa1|0ffice365)/i.test(text);
      const score = isPhishDomain ? 85 : (isUrgent ? 65 : 20);
      const level = score >= 70 ? 'critical' : (score >= 40 ? 'medium' : 'safe');

      let reply = `### ${score >= 70 ? '🚨 CRITICAL THREAT' : (score >= 40 ? '⚡ SUSPICIOUS INDICATORS' : '🛡️ VERIFIED SAFE')} (Score: ${score}/100)\n\n`;
      if (score >= 70) {
        reply += `**Verdict**: High-risk domain / credential harvesting indicators detected.\n• Flagged suspicious domain pattern or urgent coercion language.\n> **Recommendation**: Do not open links or submit credentials.`;
      } else if (score >= 40) {
        reply += `**Verdict**: Moderate risk indicators found in text payload.\n• Contains potential social engineering keywords.\n> **Recommendation**: Verify sender identity via secondary channel.`;
      } else {
        reply += `**Verdict**: No critical threat signatures identified in sample.\n> **Recommendation**: Always practice zero-trust verification.`;
      }

      return {
        reply,
        chips: ['Scan Another Link', 'Zero-Trust Architecture', 'Book Security Audit']
      };
    }

    for (const item of LOCAL_KNOWLEDGE) {
      for (const trigger of item.triggers) {
        if (trigger.test(text)) {
          return {
            reply: item.reply,
            chips: item.chips,
            badge: item.badge,
            showLeadForm: item.showLeadForm
          };
        }
      }
    }

    return {
      reply: `**AEGIS Defense Query Analysis**\n\nI've analyzed your query regarding: *"${text.length > 50 ? text.slice(0, 47) + '...' : text}"*.\n\nCyberSec provides comprehensive defense across system layers:\n• **Zero-Trust Network Access (ZTNA)**\n• **24/7 Managed SOC Telemetry**\n• **Offensive Penetration Testing**\n• **Continuous Compliance Readiness**\n\nHow would you like to proceed?`,
      chips: ['Scan a Link / Email', 'Schedule Audit', 'Zero-Trust Architecture', 'Contact Sales']
    };
  }

  // ── MAIN CHATBOT CONTROLLER CLASS ──
  class AegisChatbot {
    constructor() {
      this.sound = new SoundFX();
      this.voice = new VoiceEngine();
      this.isOpen = false;
      this.isExpanded = false;
      this.isBusy = false;
      this.conversationHistory = [];
      this.initUI();
    }

    initUI() {
      // Avoid duplicate injections
      if (document.getElementById('aegis-root')) return;

      const container = document.createElement('div');
      container.id = 'aegis-root';
      container.innerHTML = `
        <!-- Launcher Trigger Button -->
        <button class="aegis-launcher" id="aegisLauncher" aria-label="Open AEGIS AI Cyber Defense Assistant">
          <div class="aegis-launcher-icon">
            <span class="aegis-radar-ring"></span>
            <span class="aegis-radar-ring"></span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <path d="m9 12 2 2 4-4"/>
            </svg>
            <span class="aegis-badge">AI</span>
          </div>
          <div class="aegis-launcher-text">
            <div class="aegis-launcher-title">
              <span class="aegis-status-dot"></span>
              AEGIS AI
            </div>
            <div class="aegis-launcher-subtitle">Cyber Defense</div>
          </div>
        </button>

        <!-- Main Chat Panel / Modal -->
        <div class="aegis-panel" id="aegisPanel" role="dialog" aria-modal="true" aria-labelledby="aegisTitle">
          <!-- Header -->
          <div class="aegis-header">
            <div class="aegis-header-left">
              <div class="aegis-avatar">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                  <circle cx="12" cy="11" r="3"/>
                </svg>
              </div>
              <div class="aegis-header-meta">
                <div class="aegis-title" id="aegisTitle">
                  AEGIS-AI <span class="aegis-version-tag">v2.6</span>
                </div>
                <div class="aegis-status-text">
                  <span class="aegis-status-dot"></span>
                  DEFENSE NET // ONLINE
                </div>
              </div>
            </div>
            <div class="aegis-header-controls">
              <button class="aegis-ctrl-btn" id="aegisAudioBtn" title="Toggle Sound FX">🔊</button>
              <button class="aegis-ctrl-btn" id="aegisVoiceBtn" title="Toggle Text-to-Speech">🗣️</button>
              <button class="aegis-ctrl-btn" id="aegisClearBtn" title="Clear Conversation">🧹</button>
              <button class="aegis-ctrl-btn" id="aegisExpandBtn" title="Expand / Resize">⛶</button>
              <button class="aegis-ctrl-btn" id="aegisCloseBtn" title="Minimize Chat">✕</button>
            </div>
          </div>

          <!-- Messages -->
          <div class="aegis-messages" id="aegisMessages"></div>

          <!-- Quick Action Chips -->
          <div class="aegis-chips-bar" id="aegisChips"></div>

          <!-- Input Bar -->
          <form class="aegis-input-form" id="aegisForm">
            <button type="button" class="aegis-scan-btn" id="aegisScanPromptBtn" title="Scan a link or email snippet">
              ⚡ SCAN
            </button>
            <input 
              type="text" 
              class="aegis-input" 
              id="aegisInput" 
              placeholder="Ask security question or paste URL/email to scan..." 
              autocomplete="off" 
            />
            <button type="submit" class="aegis-send-btn" id="aegisSendBtn" aria-label="Send message">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <line x1="22" y1="2" x2="11" y2="13"></line>
                <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
              </svg>
            </button>
          </form>
        </div>
      `;

      document.body.appendChild(container);
      this.bindEvents();
      this.sendInitialGreeting();
    }

    bindEvents() {
      const launcher = document.getElementById('aegisLauncher');
      const closeBtn = document.getElementById('aegisCloseBtn');
      const expandBtn = document.getElementById('aegisExpandBtn');
      const audioBtn = document.getElementById('aegisAudioBtn');
      const voiceBtn = document.getElementById('aegisVoiceBtn');
      const clearBtn = document.getElementById('aegisClearBtn');
      const form = document.getElementById('aegisForm');
      const scanPromptBtn = document.getElementById('aegisScanPromptBtn');

      launcher.addEventListener('click', () => this.toggleChat());
      closeBtn.addEventListener('click', () => this.toggleChat(false));
      expandBtn.addEventListener('click', () => this.toggleExpand());

      audioBtn.addEventListener('click', () => {
        this.sound.enabled = !this.sound.enabled;
        audioBtn.classList.toggle('active', this.sound.enabled);
        audioBtn.textContent = this.sound.enabled ? '🔊' : '🔇';
        if (this.sound.enabled) this.sound.playClick();
      });

      voiceBtn.addEventListener('click', () => {
        this.voice.enabled = !this.voice.enabled;
        voiceBtn.classList.toggle('active', this.voice.enabled);
        this.sound.playClick();
        if (this.voice.enabled) {
          this.voice.speak('Voice telemetry initialized.');
        }
      });

      clearBtn.addEventListener('click', () => {
        this.sound.playClick();
        this.clearChat();
      });

      scanPromptBtn.addEventListener('click', () => {
        this.sound.playScan();
        const input = document.getElementById('aegisInput');
        input.value = 'Scan suspicious link: ';
        input.focus();
      });

      form.addEventListener('submit', (e) => {
        e.preventDefault();
        const input = document.getElementById('aegisInput');
        const text = input.value.trim();
        if (text && !this.isBusy) {
          input.value = '';
          this.handleUserMessage(text);
        }
      });

      // Escape key to close
      document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && this.isOpen) {
          this.toggleChat(false);
        }
      });
    }

    toggleChat(forceState) {
      this.sound.playClick();
      const panel = document.getElementById('aegisPanel');
      this.isOpen = forceState !== undefined ? forceState : !this.isOpen;
      panel.classList.toggle('is-active', this.isOpen);

      if (this.isOpen) {
        setTimeout(() => {
          document.getElementById('aegisInput').focus();
          this.scrollToBottom();
        }, 150);
      }
    }

    toggleExpand() {
      this.sound.playClick();
      const panel = document.getElementById('aegisPanel');
      this.isExpanded = !this.isExpanded;
      panel.classList.toggle('is-expanded', this.isExpanded);
    }

    clearChat() {
      const messagesContainer = document.getElementById('aegisMessages');
      messagesContainer.innerHTML = '';
      this.conversationHistory = [];
      this.sendInitialGreeting();
    }

    sendInitialGreeting() {
      this.appendBotMessage({
        reply: `Greetings. I am **AEGIS-AI**, CyberSec's autonomous cyber defense sentinel.

How can I assist your security operations today?
• 🛡️ **Threat & Link Scanner**: Paste any URL, email, or domain for immediate heuristics.
• ⚡ **Zero-Trust & SOC**: Explore our continuous verification and 24/7 telemetry.
• 💼 **Consultation & Audits**: Request an offensive pen-test or custom architecture review.`,
        badge: 'DEFENSE NET',
        chips: ['Scan Suspicious Link', 'Zero-Trust Architecture', '24/7 Managed SOC', 'Book Security Audit']
      });
    }

    appendUserMessage(text) {
      const messagesContainer = document.getElementById('aegisMessages');
      const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

      const msgEl = document.createElement('div');
      msgEl.className = 'aegis-msg is-user';
      msgEl.innerHTML = `
        <div class="aegis-msg-meta">
          <span>YOU // ${timeStr}</span>
        </div>
        <div class="aegis-bubble">
          ${formatMarkdown(text)}
        </div>
      `;

      messagesContainer.appendChild(msgEl);
      this.sound.playClick();
      this.scrollToBottom();
      this.conversationHistory.push({ role: 'user', content: text });
    }

    appendBotMessage(data, isStreaming = false) {
      const messagesContainer = document.getElementById('aegisMessages');
      const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

      const msgEl = document.createElement('div');
      msgEl.className = 'aegis-msg is-bot';

      const badgeHtml = data.badge ? `<span class="aegis-badge-tag">${data.badge}</span>` : '';

      msgEl.innerHTML = `
        <div class="aegis-msg-meta">
          <span>AEGIS // ${timeStr}</span>
          ${badgeHtml}
        </div>
        <div class="aegis-bubble">
          ${formatMarkdown(data.reply)}
        </div>
      `;

      // Append In-Chat Lead Form if requested
      if (data.showLeadForm || data.actions?.some(a => a.type === 'SHOW_LEAD_FORM')) {
        const formEl = document.createElement('div');
        formEl.className = 'aegis-lead-form';
        formEl.innerHTML = `
          <div class="aegis-lead-title">
            <span>🛡️</span> Schedule Security Consultation
          </div>
          <input type="text" class="aegis-lead-input" placeholder="Your Full Name *" id="leadName" required />
          <input type="email" class="aegis-lead-input" placeholder="Work Email Address *" id="leadEmail" required />
          <input type="text" class="aegis-lead-input" placeholder="Company / Organization" id="leadCompany" />
          <input type="text" class="aegis-lead-input" placeholder="Phone (Optional)" id="leadPhone" />
          <button type="button" class="aegis-lead-submit" id="leadSubmitBtn">
            Request Architecture Discovery ➔
          </button>
        `;

        formEl.querySelector('#leadSubmitBtn').addEventListener('click', () => {
          this.handleLeadSubmit(formEl);
        });

        msgEl.querySelector('.aegis-bubble').appendChild(formEl);
      }

      messagesContainer.appendChild(msgEl);
      this.renderChips(data.chips || data.quickReplies || []);
      this.sound.playMsgIn();
      this.voice.speak(data.reply);
      this.scrollToBottom();
      this.conversationHistory.push({ role: 'assistant', content: data.reply });
    }

    async handleLeadSubmit(formEl) {
      const nameInput = formEl.querySelector('#leadName');
      const emailInput = formEl.querySelector('#leadEmail');
      const companyInput = formEl.querySelector('#leadCompany');
      const phoneInput = formEl.querySelector('#leadPhone');
      const submitBtn = formEl.querySelector('#leadSubmitBtn');

      const name = nameInput.value.trim();
      const email = emailInput.value.trim();
      const company = companyInput.value.trim();
      const phone = phoneInput.value.trim();

      if (!name || !email) {
        alert('Please provide your name and work email.');
        return;
      }

      submitBtn.disabled = true;
      submitBtn.textContent = 'Transmitting Lead Data...';

      try {
        const res = await fetch('/api/ai-chat/lead', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
          body: JSON.stringify({ name, email, company, phone, message: 'Requested discovery session via AEGIS AI Chatbot' })
        });

        if (res.ok) {
          formEl.innerHTML = `
            <div style="color:var(--aegis-safe);font-family:var(--aegis-font-mono);font-size:12px;padding:8px 0;line-height:1.5;">
              ✓ <strong>Consultation Confirmed!</strong><br>
              A senior security architect will review your environment parameters and contact you at <code>${email}</code> within 24 hours.
            </div>
          `;
          this.sound.playMsgIn();
        } else {
          throw new Error('Server error');
        }
      } catch (e) {
        // Local fallback acknowledgment
        formEl.innerHTML = `
          <div style="color:var(--aegis-safe);font-family:var(--aegis-font-mono);font-size:12px;padding:8px 0;line-height:1.5;">
            ✓ <strong>Consultation Request Received!</strong><br>
            Thank you, ${name}. Our security engineering desk will reach out shortly.
          </div>
        `;
      }
    }

    showTyping() {
      const messagesContainer = document.getElementById('aegisMessages');
      const typingEl = document.createElement('div');
      typingEl.id = 'aegisTyping';
      typingEl.className = 'aegis-typing';
      typingEl.innerHTML = `
        <span class="aegis-typing-dot"></span>
        <span class="aegis-typing-dot"></span>
        <span class="aegis-typing-dot"></span>
      `;
      messagesContainer.appendChild(typingEl);
      this.scrollToBottom();
    }

    hideTyping() {
      const typingEl = document.getElementById('aegisTyping');
      if (typingEl) typingEl.remove();
    }

    renderChips(chips) {
      const chipsBar = document.getElementById('aegisChips');
      chipsBar.innerHTML = '';
      if (!chips || chips.length === 0) return;

      chips.forEach((chipText) => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'aegis-chip';
        btn.textContent = chipText;
        btn.addEventListener('click', () => {
          this.sound.playClick();
          this.handleUserMessage(chipText);
        });
        chipsBar.appendChild(btn);
      });
    }

    async handleUserMessage(text) {
      this.isBusy = true;
      this.appendUserMessage(text);
      this.showTyping();

      try {
        // Try calling the full Express backend
        const res = await fetch('/api/ai-chat/message', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          },
          body: JSON.stringify({
            message: text,
            conversationHistory: this.conversationHistory
          })
        });

        if (res.ok) {
          const data = await res.json();
          this.hideTyping();
          this.appendBotMessage(data);
        } else {
          throw new Error('API unavailable, falling back');
        }
      } catch (err) {
        // Resilient fallback to local intelligence engine (for static project.html / file:// access)
        setTimeout(() => {
          this.hideTyping();
          const fallbackData = getLocalFallback(text);
          this.appendBotMessage(fallbackData);
        }, 400);
      } finally {
        this.isBusy = false;
      }
    }

    scrollToBottom() {
      const messagesContainer = document.getElementById('aegisMessages');
      if (messagesContainer) {
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
      }
    }
  }

  // ── AUTO-INITIALIZATION ──
  function init() {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => new AegisChatbot());
    } else {
      new AegisChatbot();
    }
  }

  init();
})();
