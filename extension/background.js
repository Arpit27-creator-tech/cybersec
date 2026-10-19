/**
 * CyberSec Email Threat Radar - Background Service Worker (Manifest V3)
 * Orchestrates secure communication between Gmail content scripts and local CyberSec backend.
 * v1.1.0: Added direct Gemini 3.8 Flash API integration for in-Gmail AI Email Writer.
 */

const API_BASE_URL = 'http://localhost:3000/api/extension';
const GEMINI_CANDIDATE_MODELS = [
  'gemini-flash-lite-latest',
  'gemini-3.5-flash-lite',
  'gemini-3.1-flash-lite',
  'gemini-3.8-flash'
];
const GEMINI_API_BASE = 'https://generativelanguage.googleapis.com/v1beta/models';

// Set initial badge
chrome.runtime.onInstalled.addListener(async () => {
  await chrome.action.setBadgeText({ text: 'ON' });
  await chrome.action.setBadgeBackgroundColor({ color: '#00E5FF' });
  await chrome.storage.local.set({
    autoScanEnabled: false,
    installedAt: Date.now()
  });
  console.log('🛡️ CyberSec Email Threat Radar Extension v1.1.0 installed.');
});

// Message listener for content scripts & popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    try {
      if (message.type === 'SCAN_EMAIL') {
        const response = await handleEmailScan(message.data);
        sendResponse(response);
      } else if (message.type === 'GENERATE_EMAIL') {
        const response = await handleGenerateEmail(message.data);
        sendResponse(response);
      } else if (message.type === 'GENERATE_EMAIL_GEMINI') {
        // Direct Gemini generation — no backend server required
        const response = await handleGenerateEmailGemini(message.data);
        sendResponse(response);
      } else if (message.type === 'CHECK_STATUS') {
        const status = await checkServerStatus();
        sendResponse(status);
      } else if (message.type === 'OPEN_REPORT') {
        if (message.url) {
          await chrome.tabs.create({ url: message.url });
          sendResponse({ success: true });
        }
      } else if (message.type === 'SAVE_GEMINI_KEY') {
        await chrome.storage.local.set({ geminiApiKey: message.key });
        sendResponse({ success: true });
      } else if (message.type === 'GET_GEMINI_KEY') {
        const data = await chrome.storage.local.get(['geminiApiKey']);
        sendResponse({ success: true, key: data.geminiApiKey || '' });
      } else {
        sendResponse({ success: false, error: 'Unknown message type: ' + message.type });
      }
    } catch (err) {
      console.error('Service worker error handling message:', err);
      sendResponse({
        success: false,
        error: err.message || 'Internal extension service worker error'
      });
    }
  })();

  // Return true to keep message port open for async response
  return true;
});

/**
 * Handle email scan request via CyberSec local API
 */
async function handleEmailScan(emailData) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 12000);

    const res = await fetch(`${API_BASE_URL}/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(emailData),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!res.ok) {
      const errText = await res.text();
      let errMsg = `Server returned HTTP ${res.status}`;
      try {
        const parsed = JSON.parse(errText);
        if (parsed.error) errMsg = parsed.error;
      } catch (_) {}
      return { success: false, error: errMsg };
    }

    const report = await res.json();

    // Update extension action badge based on threat score
    const score = report.threatScore || 0;
    if (score >= 60 || report.isPhishing) {
      await chrome.action.setBadgeText({ text: '!' });
      await chrome.action.setBadgeBackgroundColor({ color: '#EF4444' });
    } else if (score >= 35) {
      await chrome.action.setBadgeText({ text: 'WARN' });
      await chrome.action.setBadgeBackgroundColor({ color: '#F59E0B' });
    } else {
      await chrome.action.setBadgeText({ text: 'SAFE' });
      await chrome.action.setBadgeBackgroundColor({ color: '#10B981' });
    }

    // Persist latest scan summary in storage
    await chrome.storage.local.set({
      lastScan: {
        scanId: report.scanId,
        subject: emailData.subject,
        sender: emailData.sender,
        threatScore: score,
        threatLevel: report.threatLevel,
        isPhishing: report.isPhishing,
        scannedAt: Date.now()
      }
    });

    return report;
  } catch (err) {
    if (err.name === 'AbortError') {
      return {
        success: false,
        error: 'Scan request timed out. Please check if CyberSec server is responding at http://localhost:3000.'
      };
    }
    return {
      success: false,
      error: 'Cannot connect to CyberSec backend at http://localhost:3000. Please ensure the local server is running.'
    };
  }
}

/**
 * Check if the local CyberSec server is alive
 */
async function checkServerStatus() {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000);

    const res = await fetch(`${API_BASE_URL}/status`, {
      method: 'GET',
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      return { online: true, ...data };
    }
    return { online: false, status: res.status };
  } catch (err) {
    return { online: false, error: err.message };
  }
}

/**
 * Handle AI Email Writer generation request (via local CyberSec backend)
 */
async function handleGenerateEmail(writerData) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 20000);

    const res = await fetch('http://localhost:3000/api/writer/generate', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(writerData),
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      throw new Error(errBody.error || `Server responded with ${res.status}`);
    }

    const data = await res.json();
    return data;
  } catch (err) {
    console.error('Error generating email with AI:', err);
    return {
      success: false,
      error: err.name === 'AbortError'
        ? 'Generation timed out. Please check backend server.'
        : `Cannot connect to CyberSec Writer: ${err.message}`
    };
  }
}

/**
 * Direct Gemini 3.8 Flash email generation — no backend server required.
 * Called by the in-Gmail AI Writer overlay in content.js.
 */
async function handleGenerateEmailGemini(params) {
  try {
    // Retrieve stored API key
    const stored = await chrome.storage.local.get(['geminiApiKey']);
    const apiKey = (stored.geminiApiKey || '').trim();

    if (!apiKey) {
      return {
        success: false,
        error: 'NO_KEY',
        message: 'Gemini API key not configured. Please enter your key in the AI Writer settings.'
      };
    }

    // ── Per-tone voice guide ──
    const toneGuide = {
      professional: 'Polished, confident, clear. Sentence variety. No corporate jargon.',
      urgent: 'Short sharp sentences. Action words. Immediate. No fluff.',
      friendly: 'Warm, like talking to a colleague you like. Light conversational touches.',
      formal: 'Precise, measured language. Structured paragraphs. No contractions.',
      persuasive: 'Lead with the benefit. Evidence-backed. End with a compelling ask.',
      reassuring: 'Calm, empathetic, transparent. Acknowledge concerns. Offer clarity.'
    }[params.tone] || 'Professional and clear.';

    // ── Audience context ──
    const audienceContext = {
      executive: 'Reader is C-suite. Lead with business impact. Skip technical detail.',
      technical: 'Reader is engineering/IT. Precise terms OK. Include specifics.',
      employees: 'Reader is internal staff. Plain language, clear action items.',
      client: 'Reader is an external paying client. Polite, client-first framing.',
      partner: 'Reader is a vendor or regulator. Professional partnership tone.',
      general: 'Mixed audience. Keep it accessible and clear for anyone.'
    }[params.audience] || 'General professional audience.';

    // ── Length guide ──
    const lengthGuide = {
      concise: '60–90 words in the body. Be brief, direct.',
      balanced: '150–220 words in the body. Enough detail to be clear.',
      detailed: '280–380 words in the body. Thorough with context.'
    }[params.length] || '150–220 words in the body.';

    const systemInstruction = `You are a senior communications professional who writes emails that sound \
like a real person wrote them — not a chatbot or template.

CRITICAL RULES:
- NEVER use: "I hope this email finds you well", "As per our conversation", "Please don't hesitate", \
"I am writing to", "herewith", "kindly", "Please find attached", "touch base", "synergize", \
"leverage", "moving forward", "going forward", "to that end", "I trust this clarifies".
- Do NOT start with a compliment or pleasantry unless tone is "friendly".
- Write like a person who knows what they want to say and just says it.
- Use natural contractions (I've, we'll, it's) unless tone is "formal".
- Vary sentence length for rhythm. Every sentence should earn its place.
- Do NOT mention that you are an AI or reference the user's prompt.

VOICE: ${toneGuide}
AUDIENCE: ${audienceContext}
LENGTH: ${lengthGuide}
${params.recipientName ? `Address recipient as: ${params.recipientName}` : ''}
${params.senderName ? `Sign off as: ${params.senderName}` : ''}
${params.callToAction ? `End with CTA: ${params.callToAction}` : ''}

Return ONLY valid JSON (no markdown, no code fences):
{
  "subjectLines": ["<direct>", "<action-oriented>", "<curiosity/urgency>", "<punchy>"],
  "bodyText": "<plaintext with paragraphs separated by \\n\\n>",
  "bodyHtml": "<same content in clean HTML with <p>, <strong>, <ul><li>>",
  "suggestedNextSteps": ["<step 1>", "<step 2>"],
  "estimatedReadTime": "<e.g. 1 min read>"
}`;

    const userContent = `Write a real email:
PURPOSE: ${params.purpose || 'general'}
WHAT IT NEEDS TO COMMUNICATE: ${params.prompt || 'A professional communication'}
${params.keyPoints ? `KEY POINTS: ${params.keyPoints}` : ''}
${params.callToAction ? `CTA: ${params.callToAction}` : ''}

Write the actual email now. Do not describe what you will do — just write it.`;

    const payload = {
      system_instruction: {
        parts: [{ text: systemInstruction }]
      },
      contents: [
        {
          role: 'user',
          parts: [{ text: userContent }]
        }
      ],
      generationConfig: {
        temperature: 0.75,
        maxOutputTokens: 1500,
        responseMimeType: 'application/json'
      }
    };

    let lastError = null;

    for (const model of GEMINI_CANDIDATE_MODELS) {
      const url = `${GEMINI_API_BASE}/${model}:generateContent?key=${apiKey}`;
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000);

      try {
        const res = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
          signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (!res.ok) {
          const errText = await res.text();
          console.warn(`Gemini model ${model} returned HTTP ${res.status}, trying fallback...`);
          lastError = new Error(`Gemini (${model}) error ${res.status}: ${errText}`);
          continue;
        }

        const data = await res.json();
        const rawText = data.candidates?.[0]?.content?.parts?.[0]?.text;
        if (!rawText) {
          console.warn(`Gemini model ${model} returned empty content, trying fallback...`);
          continue;
        }

        // Robust JSON extraction
        let cleanJson = rawText.trim();
        if (cleanJson.startsWith('```')) {
          cleanJson = cleanJson.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '').trim();
        }

        let parsed;
        try {
          parsed = JSON.parse(cleanJson);
        } catch (_) {
          const match = cleanJson.match(/\{[\s\S]*\}/);
          if (match) {
            parsed = JSON.parse(match[0]);
          } else {
            console.warn(`Gemini model ${model} malformed JSON, trying fallback...`);
            continue;
          }
        }

        const bodyText = parsed.bodyText || '';
        return {
          success: true,
          email: {
            engine: `Gemini Flash (${model.includes('lite') ? 'Lightning' : 'Pro'})`,
            engineType: 'gemini-direct',
            modelUsed: model,
            subjectLines: parsed.subjectLines || ['Important Update'],
            bodyText,
            bodyHtml: parsed.bodyHtml || bodyText.replace(/\n\n/g, '</p><p>').replace(/\n/g, '<br>').replace(/^/, '<p>').replace(/$/, '</p>'),
            suggestedNextSteps: parsed.suggestedNextSteps || ['Review before sending'],
            metadata: {
              wordCount: bodyText.split(/\s+/).filter(Boolean).length,
              estimatedReadTime: parsed.estimatedReadTime || '1 min read',
              tone: params.tone,
              purpose: params.purpose
            }
          }
        };
      } catch (err) {
        clearTimeout(timeoutId);
        console.warn(`Gemini model ${model} fetch failed (${err.message}), trying next model...`);
        lastError = err;
      }
    }

    return {
      success: false,
      error: lastError ? (lastError.message || 'Gemini generation failed') : 'All Gemini models failed'
    };
  } catch (err) {
    return { success: false, error: err.message || 'Gemini generation failed' };
  }
}
