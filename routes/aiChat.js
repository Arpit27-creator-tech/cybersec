const express = require('express');
const router = express.Router();
const db = require('../database/db');
const { processChatMessage, scanContent, KNOWLEDGE_BASE } = require('../services/aiChatService');
const { isValidEmail, sanitize } = require('../middleware/validate');

/**
 * POST /api/ai-chat/message
 * Conversational endpoint
 */
router.post('/message', async (req, res) => {
  try {
    const { message, conversationHistory } = req.body;
    const response = await processChatMessage({ message, conversationHistory });
    return res.json({
      success: true,
      ...response
    });
  } catch (err) {
    console.error('AI Chat Error:', err);
    return res.status(500).json({
      success: false,
      error: 'An internal error occurred while processing the security query.',
      reply: '⚠️ **System Notice**: Temporary telemetry disruption. Please re-try your request or contact our team directly.',
      quickReplies: ['Retry Query', 'Contact Support', 'Zero-Trust Info']
    });
  }
});

/**
 * POST /api/ai-chat/scan
 * Dedicated live threat scanning endpoint
 */
router.post('/scan', (req, res) => {
  try {
    const { content } = req.body;
    if (!content) {
      return res.status(400).json({ success: false, error: 'No content provided to scan.' });
    }

    const scanResult = scanContent(content);
    return res.json({
      success: true,
      scan: scanResult
    });
  } catch (err) {
    console.error('AI Scan Error:', err);
    return res.status(500).json({ success: false, error: 'Failed to scan payload.' });
  }
});

/**
 * POST /api/ai-chat/lead
 * Direct in-chat consultation booking and CRM lead capture
 */
router.post('/lead', (req, res) => {
  try {
    const { name, email, company, phone, message } = req.body;

    if (!name || sanitize(name).length < 2 || !email) {
      return res.status(400).json({ success: false, error: 'Name and email are required.' });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ success: false, error: 'Please provide a valid email address.' });
    }

    const leadMessage = message ? sanitize(message) : 'Requested security consultation via AEGIS-AI Chatbot.';

    const result = db.prepare(`
      INSERT INTO contacts (name, email, company, phone, message, source, status)
      VALUES (?, ?, ?, ?, ?, 'ai_chatbot', 'new')
    `).run(
      sanitize(name),
      sanitize(email).toLowerCase(),
      company ? sanitize(company) : null,
      phone ? sanitize(phone) : null,
      leadMessage
    );

    return res.json({
      success: true,
      leadId: Number(result.lastInsertRowid),
      message: 'Consultation request logged successfully! A senior cybersecurity architect will reach out within 24 hours.'
    });
  } catch (err) {
    console.error('AI Lead Capture Error:', err);
    return res.status(500).json({ success: false, error: 'Failed to record consultation request.' });
  }
});

/**
 * GET /api/ai-chat/quick-topics
 * Returns preset cybersecurity inquiry topics
 */
router.get('/quick-topics', (req, res) => {
  const topics = KNOWLEDGE_BASE.map(k => ({
    id: k.id,
    title: k.title,
    badge: k.badge
  }));
  return res.json({ success: true, topics });
});

module.exports = router;
