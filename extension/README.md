# 🛡️ CyberSec Email Threat Radar & AI Writer — Chrome Extension

A unified Manifest V3 Chrome Extension that integrates both:
1. **Real-time Threat & Phishing Radar** — Inspect incoming emails in Gmail for brand spoofing, malicious links, and urgency coercion.
2. **Gemini 3.8 Flash in-Gmail AI Email Writer** — Draft and refine authentic, human-sounding, purpose-built emails directly inside the Gmail compose window.

---

## 🚀 How to Install & Load (30 Seconds)

1. Open **Google Chrome** (or Brave / Edge / Opera).
2. Navigate to `chrome://extensions` in the address bar.
3. Toggle on **Developer mode** in the top-right corner.
4. Click the **Load unpacked** button in the top-left corner.
5. Select either:
   - The `extension` folder located inside your cloned `cybersec` repository (e.g. `<path-to-cybersec>/extension`), OR
   - Download the pre-packaged zip from the CyberSec Dashboard (`/admin/email-scanner` -> "Download Extension (.zip)"), extract it anywhere on your PC, and select that extracted folder.
6. The extension is now loaded and active!

---

## ✍️ How to Use the in-Gmail AI Email Writer

1. Open [Gmail](https://mail.google.com).
2. Click **Compose** (or click **Reply** / **Forward** on an existing email thread).
3. In the compose action toolbar (next to the blue "Send" button), click the **`[ ✨ AI Writer ]`** button.
4. An interactive CyberSec composer overlay appears right inside Gmail:
   - **Gemini API Key**: If not already saved, click the settings gear or key prompt to enter your Google Gemini API key (stored securely in local extension storage; no external servers required).
   - **Purpose Selector**: Pick your email purpose (e.g., *Security Advisory*, *Incident Notice*, *Meeting Request*, *Follow-up*, *Project Update*, *Partnership/Sales*, *Executive Briefing*, or *Custom*).
   - **Tone & Audience**: Choose between *Professional & Authoritative*, *Urgent & Direct*, *Friendly & Warm*, *Formal*, *Persuasive*, or *Reassuring*, and match your audience (*General*, *Executive*, *Technical*, *Employees*, *Client*, *Partner*).
   - **Length & Call-to-Action**: Select *Concise* (<100 words), *Balanced* (150–250 words), or *Detailed* (300+ words).
   - **Your Prompt**: Type what you want to communicate in bullet points, rough notes, or full sentences.
5. Click **"✨ Generate with Gemini"**:
   - The AI generates natural, human-sounding copy tailored to your purpose.
   - Built-in prompt engineering explicitly eliminates cliché robotic phrases (no *"I hope this email finds you well"*, no *"Please don't hesitate to reach out"*, no *"touch base"*).
   - Provides multiple selectable **Subject Line** options.
   - Shows word count, estimated read time, and strategic next steps.
6. Click **"Insert into Gmail"**:
   - The chosen subject is automatically placed into the Gmail Subject field.
   - The body is inserted directly into your active Gmail composer window ready for review and sending!
   - You can also click **"Copy to Clipboard"** at any time.

---

## 🛡️ How to Use the Threat Radar

1. With your local CyberSec server running (`npm run dev` or `node server.js`):
2. Open any incoming email in [Gmail](https://mail.google.com).
3. Click the **`[ 🛡️ Scan with CyberSec ]`** button in the email header.
4. Instantly view threat scores, phishing verdict, SPF/DKIM verification, sender reputation, and malicious link analysis rendered in a live dossier above the email.

---

## ⚙️ Architecture & Features

- **Dual Mode Operation**:
  - **Standalone Direct**: Communicates directly with Google's Gemini API via Chrome background service worker. Works even without the local backend.
  - **Backend Synchronized**: Connects to the local CyberSec server at `http://localhost:3000` for deep threat scanning and web studio synchronization.
- **Manifest V3 Compliant**: Uses modern service worker architecture, declarative permissions, and ephemeral local storage.
- **Web Studio Available**: Access the full-featured desktop AI Email Writer Studio anytime at `http://localhost:3000/admin/email-writer`.
