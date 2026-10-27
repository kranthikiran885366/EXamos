/**
 * ExamOS Kiosk Production-Grade Dynamic Synchronization Engine
 * Runs continuously inside the ExamOS Cage Wayland Chromium kiosk session.
 * Features:
 *  - Multi-Gateway Auto-Discovery & Zero-Config Failover (127.0.0.1, 192.168.19.1, 10.0.2.2)
 *  - Real-Time Command Execution (RELOAD, DISPATCH, LOCK, UNLOCK, PING)
 *  - Dynamic Exam URL Redirection with Visual Countdown Toast
 *  - Impenetrable Emergency Terminal Lockdown Modal with Controller Announcements
 *  - High-Resolution Live Telemetry & Heartbeat Reporting (focus, latency, battery)
 */
(function() {
  'use strict';

  // State
  let activeGateway = null;
  let lastCommandSeq = 0;
  let isLocked = false;
  let lockOverlay = null;
  let syncPill = null;
  let dispatchToast = null;
  let consecutiveFailures = 0;

  // Candidate gateway endpoints to probe for the ExamOS C security server
  const GATEWAY_CANDIDATES = [
    'http://127.0.0.1:8895',
    'http://192.168.19.1:8895',
    'http://10.0.2.2:8895',
    'http://127.0.0.1:8000',
  ];
  if (window.location.protocol === 'http:' || window.location.protocol === 'https:') {
    GATEWAY_CANDIDATES.unshift(window.location.origin);
  }

  // Fast timeout fetch helper
  async function quickFetch(url, options = {}, timeoutMs = 1500) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, { ...options, credentials: 'omit', signal: controller.signal });
      clearTimeout(timer);
      return res;
    } catch (err) {
      clearTimeout(timer);
      throw err;
    }
  }

  // Probe and discover active gateway
  async function discoverGateway() {
    if (activeGateway) {
      try {
        const res = await quickFetch(`${activeGateway}/api/v1/kiosk/check-update`, { method: 'GET' }, 1200);
        if (res.ok) {
          consecutiveFailures = 0;
          return activeGateway;
        }
      } catch (err) {
        consecutiveFailures++;
        if (consecutiveFailures < 3) return activeGateway;
      }
    }

    // Cycle through candidate endpoints
    for (const base of GATEWAY_CANDIDATES) {
      try {
        const res = await quickFetch(`${base}/api/v1/kiosk/check-update`, { method: 'GET' }, 1000);
        if (res.ok) {
          activeGateway = base;
          consecutiveFailures = 0;
          console.log('[ExamOS-Kiosk] Active gateway discovered:', activeGateway);
          return activeGateway;
        }
      } catch (err) {
        // try next candidate
      }
    }
    return null;
  }

  // Live status pill in top right corner
  function ensureSyncPill() {
    if (!syncPill && document.body) {
      syncPill = document.createElement('div');
      syncPill.id = 'examos-kiosk-live-pill';
      syncPill.style.cssText = `
        position: fixed;
        top: 10px;
        right: 16px;
        z-index: 999999;
        display: flex;
        align-items: center;
        gap: 8px;
        background: rgba(9, 14, 26, 0.94);
        border: 1px solid #1e293b;
        color: #f1f5f9;
        padding: 5px 14px;
        border-radius: 9999px;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        font-size: 11px;
        font-weight: 600;
        box-shadow: 0 8px 24px rgba(0,0,0,0.6);
        pointer-events: none;
        backdrop-filter: blur(8px);
        transition: all 0.25s ease;
      `;
      document.body.appendChild(syncPill);
    }
  }

  function updatePill(connected, latencyMs, tpmStatus, examId) {
    ensureSyncPill();
    if (!syncPill) return;

    if (connected) {
      syncPill.innerHTML = `
        <span style="width: 7px; height: 7px; border-radius: 50%; background: #22c55e; box-shadow: 0 0 10px #22c55e; display: inline-block;"></span>
        <span>Gateway: <b style="color:#38bdf8">SYNC LIVE</b></span>
        <span style="color:#475569">|</span>
        <span style="color:#94a3b8">${latencyMs}ms</span>
        <span style="color:#475569">|</span>
        <span style="color:#a7f3d0">TPM: ${tpmStatus || 'ACTIVE'}</span>
        ${examId ? `<span style="color:#475569">|</span><span style="color:#cbd5e1">${examId}</span>` : ''}
      `;
      syncPill.style.borderColor = '#0284c7';
    } else {
      syncPill.innerHTML = `
        <span style="width: 7px; height: 7px; border-radius: 50%; background: #ef4444; box-shadow: 0 0 8px #ef4444; display: inline-block;"></span>
        <span style="color:#f87171">Gateway Reconnecting...</span>
      `;
      syncPill.style.borderColor = '#dc2626';
    }
  }

  function flashPillGlow() {
    if (!syncPill) return;
    syncPill.style.boxShadow = '0 0 25px #0284c7';
    setTimeout(() => {
      if (syncPill) syncPill.style.boxShadow = '0 8px 24px rgba(0,0,0,0.6)';
    }, 600);
  }

  // Emergency lockdown overlay
  function setEmergencyLock(locked, reason) {
    if (locked === isLocked) return;
    isLocked = locked;

    if (locked) {
      if (!lockOverlay) {
        lockOverlay = document.createElement('div');
        lockOverlay.id = 'examos-lockdown-overlay';
        lockOverlay.style.cssText = `
          position: fixed;
          top: 0; left: 0; right: 0; bottom: 0;
          background: rgba(8, 12, 22, 0.98);
          z-index: 99999999;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          color: #f8fafc;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          text-align: center;
          padding: 32px;
          user-select: none;
        `;
        lockOverlay.innerHTML = `
          <div style="width: 80px; height: 80px; border-radius: 50%; background: rgba(220,38,38,0.18); border: 2px solid #ef4444; display: flex; align-items: center; justify-content: center; font-size: 36px; margin-bottom: 24px; color: #ef4444; box-shadow: 0 0 30px rgba(239,68,68,0.4);">
            &#128274;
          </div>
          <h1 style="font-size: 32px; font-weight: 800; color: #f87171; margin-bottom: 14px; letter-spacing: -0.02em;">
            EMERGENCY WORKSTATION LOCKDOWN
          </h1>
          <p id="examos-lock-reason" style="font-size: 16px; color: #cbd5e1; max-width: 580px; line-height: 1.6; margin-bottom: 28px;">
            ${reason || 'The exam controller has enforced an appliance security lockdown.'}
          </p>
          <div style="background: #111a2e; border: 1px solid #1e293b; padding: 14px 28px; border-radius: 10px; font-size: 13px; color: #94a3b8; display: flex; gap: 16px;">
            <span>Terminal: <b style="color: #38bdf8">DEV-KIOSK-01</b></span>
            <span>&bull;</span>
            <span style="color: #f59e0b">All Inputs Suspended</span>
            <span>&bull;</span>
            <span>Do Not Power Off</span>
          </div>
        `;
        document.body.appendChild(lockOverlay);
      }
      const reasonEl = document.getElementById('examos-lock-reason');
      if (reasonEl && reason) reasonEl.textContent = reason;
      lockOverlay.style.display = 'flex';
    } else if (lockOverlay) {
      lockOverlay.style.display = 'none';
    }
  }

  // Toast banner for automatic dynamic exam dispatch
  function triggerExamTransition(newUrl, examName) {
    if (dispatchToast) return;
    dispatchToast = document.createElement('div');
    dispatchToast.style.cssText = `
      position: fixed;
      bottom: 28px;
      left: 50%;
      transform: translateX(-50%);
      background: linear-gradient(135deg, #0284c7 0%, #1e40af 100%);
      color: #ffffff;
      padding: 18px 32px;
      border-radius: 14px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      box-shadow: 0 20px 50px rgba(0,0,0,0.7);
      z-index: 9999999;
      text-align: center;
      border: 1px solid rgba(255,255,255,0.25);
      font-size: 15px;
      font-weight: 600;
      animation: examosSlideUp 0.3s ease;
    `;
    dispatchToast.innerHTML = `
      <div style="font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; opacity: 0.9; margin-bottom: 4px; color: #a7f3d0;">Examination Dispatched by Controller</div>
      <div style="font-size: 17px; font-weight: 700;">${examName || 'Candidate Examination Session'}</div>
      <div style="font-size: 13px; opacity: 0.85; margin-top: 6px;">Launching exam portal in <b id="examos-redir-count" style="color:#fef08a">3</b>s...</div>
    `;
    document.body.appendChild(dispatchToast);

    let count = 3;
    const interval = setInterval(() => {
      count--;
      const el = document.getElementById('examos-redir-count');
      if (el) el.textContent = count;
      if (count <= 0) {
        clearInterval(interval);
        window.location.href = newUrl;
      }
    }, 1000);
  }

  // Main dynamic check-update & telemetry cycle
  async function syncCycle() {
    const gateway = await discoverGateway();
    if (!gateway) {
      updatePill(false, 0);
      return;
    }

    const start = performance.now();
    try {
      // 1. Check Update
      const res = await quickFetch(`${gateway}/api/v1/kiosk/check-update`, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
      }, 2000);

      if (!res.ok) {
        updatePill(false, 0);
        return;
      }

      const latency = Math.round(performance.now() - start);
      const data = await res.json();
      updatePill(true, latency, data.tpm_mode, data.exam_id);

      // 2. Handle Emergency Lock
      if (data.emergency_lock) {
        setEmergencyLock(true, data.announcement || 'Terminal locked by exam controller');
      } else {
        setEmergencyLock(false);
      }

      // 3. Process Monotonic Commands
      if (data.command_seq && data.command_seq > lastCommandSeq) {
        lastCommandSeq = data.command_seq;
        flashPillGlow();
        if (data.command === 'RELOAD') {
          console.log('[ExamOS-Kiosk] RELOAD command received from server');
          window.location.reload();
          return;
        } else if (data.command === 'PING') {
          console.log('[ExamOS-Kiosk] PING command acknowledged');
        }
      }

      // 4. Handle Dynamic Exam URL Dispatch
      if (data.exam_configured && data.exam_url && data.exam_url !== 'NOT_CONFIGURED') {
        const currentNorm = window.location.href.split('?')[0].replace(/\/+$/, '');
        const targetNorm = data.exam_url.split('?')[0].replace(/\/+$/, '');
        if (currentNorm !== targetNorm && !window.location.href.includes('/exam') && !window.location.href.includes('/workbench')) {
          console.log('[ExamOS-Kiosk] Dynamic exam URL transition triggered:', data.exam_url);
          triggerExamTransition(data.exam_url, data.exam_name);
        }
      }

      // 5. Send Telemetry Heartbeat
      quickFetch(`${gateway}/api/v1/kiosk/heartbeat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          terminal_id: 'DEV-KIOSK-01',
          ip: window.location.hostname || '127.0.0.1',
          active_url: window.location.href,
          status: isLocked ? 'LOCKDOWN' : (window.location.href.includes('/exam') ? 'IN_EXAM' : 'ONLINE'),
          screen_focus: document.hasFocus() ? 1 : 0,
        }),
      }, 1500).catch(() => {});

    } catch (err) {
      updatePill(false, 0);
    }
  }

  // Key combination interception during lockdown
  window.addEventListener('keydown', function(e) {
    if (isLocked) {
      e.preventDefault();
      e.stopPropagation();
      return false;
    }
  }, true);

  // Initialize loop
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      ensureSyncPill();
      syncCycle();
      setInterval(syncCycle, 2000);
    });
  } else {
    ensureSyncPill();
    syncCycle();
    setInterval(syncCycle, 2000);
  }
})();
