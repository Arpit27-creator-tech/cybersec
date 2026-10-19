# Chrome Web Store Documentation & Permissions Justification
**CyberSec Email Threat Radar**  
*Last Updated: 2026-10-18*

---

## 1. Extension Overview

- **Extension Name**: CyberSec Email Threat Radar
- **Version**: 1.0.0
- **Manifest Version**: 3
- **Primary Category**: Productivity / Developer Tools & Security
- **Short Description (Max 132 chars)**: Real-time AI email threat scanner, phishing analyzer, and forensic radar for Gmail.
- **Support / Dashboard URL**: `http://localhost:3000/admin/email-scanner`

---

## 2. Permissions Justification

| Permission / Host | Why It Is Strictly Needed |
| :--- | :--- |
| `storage` | Stores user scan preferences (such as auto-scan toggle) and caches the latest threat summary for fast popup inspection without re-fetching. |
| `http://localhost:3000/*` | Communicates with the local CyberSec security backend API (`/api/extension/scan` and `/api/extension/status`) to execute heuristic threat scanning, link lookalike verification, and credential leak detection. |
| `https://mail.google.com/*` | Injects the non-intrusive `[ 🛡️ Scan with CyberSec ]` action button and threat dossier banner directly into the active Gmail reading pane when an email is opened. |

---

## 3. Privacy & Data Use Disclosures

- **Authentication Data**: The extension does **not** collect, store, or transmit Google account passwords, session cookies, or Google OAuth refresh tokens.
- **Email Content Processing**: Email subject, sender, and body text are transmitted **strictly to the user's own local CyberSec server instance** (`http://localhost:3000`) for heuristic threat analysis. No data is ever sent to third-party ad networks or external tracking telemetry.
- **Local Storage**: Preferences are stored locally on the user's browser device via `chrome.storage.local`.

---

## 4. Store Listing Description

### Detailed Description (Markdown formatted)
Protect your inbox against sophisticated phishing attacks, typosquatting domains, credential harvest lures, and covert data leaks.

**CyberSec Email Threat Radar** embeds an enterprise-grade forensic analysis engine directly into Gmail:
- **1-Click Forensic Scan**: Instantly inspect any open email with a single click from the Gmail header bar.
- **Lookalike Brand & Typosquatting Radar**: Automatically unmasks display name spoofing (e.g. "PayPal Security" sent from lookalike or suspicious domains).
- **Deceptive Link Analyzer**: Highlights hidden phishing destinations, URL shorteners, and credential phishing links directly inside the email body.
- **Urgency & Social Engineering Detection**: Flags high-pressure coercion phrases, fake password expiration lures, and invoice scam pretexting.
- **Zero-Credential Operation**: Works natively inside your browser without sharing your Google password, creating app passwords, or configuring Google Cloud Console projects.

---

## 5. Local Developer Installation (Unpacked)

1. Open Chrome and go to `chrome://extensions`.
2. Toggle on **Developer mode** in the top-right corner.
3. Click **Load unpacked**.
4. Select the `extension/` directory located inside this repository:
   ```
   /Users/arpi85222707gmail.com/Documents/cybersec/extension
   ```
5. Open [Gmail](https://mail.google.com) and click on any email to begin scanning!
