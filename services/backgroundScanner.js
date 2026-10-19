const db = require('../database/db');
const { fetchAndScanImapEmails } = require('./imapService');
const { fetchAndScanGmail, getAuthenticatedClient } = require('./gmailService');
const { decryptToken } = require('./tokenCrypto');

let timerHandle = null;
let isScanning = false;
let nextRunAt = null;

/**
 * Run a full automated scanning cycle across all connected accounts
 */
async function runScanCycle() {
  if (isScanning) {
    console.log('⏳ [Auto-Scan] Scan cycle already in progress, skipping overlapping run.');
    return;
  }

  isScanning = true;
  const startedAt = new Date();
  console.log(`🛡️ [Auto-Scan] Starting autonomous inbox threat scan at ${startedAt.toLocaleTimeString()}...`);

  let totalItemsScanned = 0;
  let totalThreatsDetected = 0;
  let cycleStatus = 'success';

  try {
    const connectedAccounts = db.prepare("SELECT * FROM email_accounts WHERE status = 'connected'").all();

    if (connectedAccounts.length === 0) {
      console.log('ℹ️ [Auto-Scan] No active Gmail accounts linked. Autonomous radar standing by.');
      cycleStatus = 'idle';
    } else {
      for (const account of connectedAccounts) {
        try {
          const decryptedToken = decryptToken(account.access_token);
          if (!decryptedToken) {
            console.warn(`⚠️ [Auto-Scan] Unable to decrypt credentials for ${account.email}. Skipping.`);
            continue;
          }

          let reports = [];

          if (account.refresh_token === 'imap') {
            // IMAP via App Password
            reports = await fetchAndScanImapEmails(account.email, decryptedToken, account.id, 15);
          } else {
            // Google OAuth 2.0
            const authClient = getAuthenticatedClient({
              access_token: decryptedToken,
              refresh_token: account.refresh_token,
              expiry_date: account.token_expiry
            });
            if (authClient) {
              reports = await fetchAndScanGmail(authClient, account.id, 15);
            }
          }

          totalItemsScanned += reports.length;
          const threatCount = reports.filter(r => (r.threat_score || 0) >= 40 || r.is_phishing).length;
          totalThreatsDetected += threatCount;

          if (threatCount > 0) {
            console.warn(`🚨 [Auto-Scan ALERT] Detected ${threatCount} suspicious communication(s) for ${account.email}!`);
          } else {
            console.log(`✓ [Auto-Scan] Clean telemetry for ${account.email}. (${reports.length} messages inspected)`);
          }
        } catch (accErr) {
          console.error(`❌ [Auto-Scan Error] Failed scanning ${account.email}:`, accErr.message);
          cycleStatus = 'warning';
        }
      }
    }

    // Update scanner_daemon telemetry in database
    db.prepare(`
      UPDATE scanner_daemon SET
        last_run_at = CURRENT_TIMESTAMP,
        last_status = ?,
        last_items_scanned = ?,
        last_threats_detected = ?
      WHERE id = 1
    `).run(cycleStatus, totalItemsScanned, totalThreatsDetected);

  } catch (err) {
    console.error('❌ [Auto-Scan Fatal Error]:', err);
    cycleStatus = 'error';
    try {
      db.prepare("UPDATE scanner_daemon SET last_status = 'error', last_run_at = CURRENT_TIMESTAMP WHERE id = 1").run();
    } catch (_) {}
  } finally {
    isScanning = false;
    const daemonSettings = getDaemonSettings();
    if (daemonSettings && daemonSettings.is_enabled) {
      const intervalMs = (daemonSettings.interval_minutes || 5) * 60 * 1000;
      nextRunAt = new Date(Date.now() + intervalMs).toISOString();
    } else {
      nextRunAt = null;
    }
  }

  return {
    status: cycleStatus,
    itemsScanned: totalItemsScanned,
    threatsDetected: totalThreatsDetected
  };
}

/**
 * Read daemon configuration from SQLite
 */
function getDaemonSettings() {
  try {
    return db.prepare('SELECT * FROM scanner_daemon WHERE id = 1').get() || {
      is_enabled: 1,
      interval_minutes: 5,
      last_status: 'idle',
      last_items_scanned: 0,
      last_threats_detected: 0
    };
  } catch (err) {
    return { is_enabled: 1, interval_minutes: 5, last_status: 'idle' };
  }
}

/**
 * Start or restart the background interval timer
 */
function startDaemon(intervalMinutes) {
  const current = getDaemonSettings();
  const mins = intervalMinutes || current.interval_minutes || 5;

  if (timerHandle) {
    clearInterval(timerHandle);
    timerHandle = null;
  }

  db.prepare(`
    UPDATE scanner_daemon SET
      is_enabled = 1,
      interval_minutes = ?
    WHERE id = 1
  `).run(mins);

  const ms = mins * 60 * 1000;
  nextRunAt = new Date(Date.now() + ms).toISOString();

  timerHandle = setInterval(() => {
    runScanCycle();
  }, ms);

  console.log(`⚡ [Auto-Scan] Background Daemon ACTIVE — scanning every ${mins} minute(s).`);
  return getStatus();
}

/**
 * Stop the background interval timer
 */
function stopDaemon() {
  if (timerHandle) {
    clearInterval(timerHandle);
    timerHandle = null;
  }
  nextRunAt = null;

  db.prepare('UPDATE scanner_daemon SET is_enabled = 0 WHERE id = 1').run();
  console.log('⏸️ [Auto-Scan] Background Daemon PAUSED.');
  return getStatus();
}

/**
 * Get comprehensive runtime & telemetry status of the scanner
 */
function getStatus() {
  const settings = getDaemonSettings();
  const connectedCount = db.prepare("SELECT COUNT(*) as count FROM email_accounts WHERE status = 'connected'").get().count;

  return {
    isEnabled: Boolean(settings.is_enabled),
    intervalMinutes: settings.interval_minutes || 5,
    lastRunAt: settings.last_run_at || null,
    nextRunAt: nextRunAt,
    lastStatus: settings.last_status || 'idle',
    lastItemsScanned: settings.last_items_scanned || 0,
    lastThreatsDetected: settings.last_threats_detected || 0,
    isScanning,
    connectedAccountsCount: connectedCount
  };
}

/**
 * Initialize background daemon on server boot
 */
function initBackgroundScanner() {
  const settings = getDaemonSettings();
  if (settings.is_enabled) {
    startDaemon(settings.interval_minutes);
  } else {
    console.log('ℹ️ [Auto-Scan] Background Daemon is currently paused in settings.');
  }
}

module.exports = {
  initBackgroundScanner,
  startDaemon,
  stopDaemon,
  runScanCycle,
  getStatus
};
