/**
 * CyberSec Threat Radar - Popup Script (Manifest V3)
 */

document.addEventListener('DOMContentLoaded', async () => {
  const statusPill = document.getElementById('statusPill');
  const statusText = document.getElementById('statusText');
  const totalScansCount = document.getElementById('totalScansCount');
  const threatsBlockedCount = document.getElementById('threatsBlockedCount');
  const autoScanToggle = document.getElementById('autoScanToggle');
  const openDashboardBtn = document.getElementById('openDashboardBtn');
  const checkConnectionBtn = document.getElementById('checkConnectionBtn');
  const recentScanCard = document.getElementById('recentScanCard');
  const recentBadge = document.getElementById('recentBadge');
  const recentSubject = document.getElementById('recentSubject');
  const recentSender = document.getElementById('recentSender');

  // Load preferences and recent scan from storage
  const storage = await chrome.storage.local.get(['autoScanEnabled', 'lastScan']);

  // Sync toggle state
  if (autoScanToggle) {
    autoScanToggle.checked = Boolean(storage.autoScanEnabled);
    autoScanToggle.addEventListener('change', async (e) => {
      await chrome.storage.local.set({ autoScanEnabled: e.target.checked });
    });
  }

  // Render recent scan if available
  if (storage.lastScan && recentScanCard) {
    const last = storage.lastScan;
    recentScanCard.style.display = 'block';
    recentSubject.textContent = last.subject || '(No Subject)';
    recentSender.textContent = last.sender || 'Unknown Sender';

    const score = last.threatScore || 0;
    if (score >= 60 || last.isPhishing) {
      recentBadge.textContent = 'CRITICAL';
      recentBadge.className = 'recent-badge badge-critical';
    } else if (score >= 35) {
      recentBadge.textContent = 'SUSPICIOUS';
      recentBadge.className = 'recent-badge badge-warning';
    } else {
      recentBadge.textContent = 'SAFE';
      recentBadge.className = 'recent-badge badge-safe';
    }
  }

  // Open AI Email Writer Studio
  const openWriterBtn = document.getElementById('openWriterBtn');
  if (openWriterBtn) {
    openWriterBtn.addEventListener('click', async () => {
      await chrome.tabs.create({ url: 'https://cybersec-crm.onrender.com/admin/email-writer' });
    });
  }

  // Open CyberSec Web Dashboard
  if (openDashboardBtn) {
    openDashboardBtn.addEventListener('click', async () => {
      await chrome.tabs.create({ url: 'https://cybersec-crm.onrender.com/admin/email-scanner' });
    });
  }

  // Re-check server health connection
  if (checkConnectionBtn) {
    checkConnectionBtn.addEventListener('click', async () => {
      await refreshStatus();
    });
  }

  // Initial connection check
  await refreshStatus();

  /**
   * Ping backend and update UI stats
   */
  async function refreshStatus() {
    statusPill.className = 'status-pill status-loading';
    statusText.textContent = 'Connecting...';

    try {
      const response = await chrome.runtime.sendMessage({ type: 'CHECK_STATUS' });

      if (response && response.online) {
        statusPill.className = 'status-pill status-online';
        statusText.textContent = 'Online';

        if (response.stats) {
          totalScansCount.textContent = response.stats.totalScans ?? 0;
          threatsBlockedCount.textContent = response.stats.threatsBlocked ?? 0;
        }
      } else {
        markOffline();
      }
    } catch (err) {
      console.warn('Backend check failed:', err);
      markOffline();
    }
  }

  function markOffline() {
    statusPill.className = 'status-pill status-offline';
    statusText.textContent = 'Offline';
    totalScansCount.textContent = '!';
    threatsBlockedCount.textContent = '!';
  }
});
