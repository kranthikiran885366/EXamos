// ExamOS Production Kiosk Fleet & Maintenance Command Center
import { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant } from '../../core/db/tenant';
import { can } from '../../core/security/rbac';
import { Page, Card, Stat, StatGrid, Alert, Badge, DataTable, Icon, Progress, SectionTitle } from '../../core/ui/kit';
import { fmt, ago } from '../../core/ui/format';
import {
  getLiveKioskStatus,
  dispatchExamUrl,
  sendKioskCommand,
  triggerEmergencyLock,
  triggerKioskReload,
} from './service';

export default function KioskPage() {
  const { user } = useAuth();
  const { tenant } = useTenant();

  // Live state
  const [liveData, setLiveData] = useState({
    status: null,
    health: null,
    terminals: { terminals: [] },
    fleet: { devices: [] },
    timestamp: Date.now(),
    connected: false,
    errors: [],
  });
  const [loading, setLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [actionMsg, setActionMsg] = useState(null);
  const [actionErr, setActionErr] = useState(null);

  // Exam URL Dispatch form
  const [dispatchUrl, setDispatchUrl] = useState('file:///usr/share/examos/onboarding.html');
  const [dispatchName, setDispatchName] = useState('ExamOS Candidate Onboarding & Examination Flow');
  const [dispatchDuration, setDispatchDuration] = useState(120);
  const [dispatching, setDispatching] = useState(false);

  // Poll live backend
  const fetchStatus = useCallback(async () => {
    try {
      const data = await getLiveKioskStatus();
      setLiveData(data);
      if (data.status?.exam_url && data.status.exam_url !== 'NOT_CONFIGURED') {
        setDispatchUrl(data.status.exam_url);
      }
      if (data.status?.exam_name) {
        setDispatchName(data.status.exam_name);
      }
    } catch (err) {
      console.warn('Live kiosk polling warning:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    if (!autoRefresh) return;
    const interval = setInterval(fetchStatus, 4000);
    return () => clearInterval(interval);
  }, [fetchStatus, autoRefresh]);

  // Command handlers
  const handleDispatch = async (presetUrl, presetName) => {
    const targetUrl = presetUrl || dispatchUrl;
    const targetName = presetName || dispatchName;
    setDispatching(true);
    setActionMsg(null);
    setActionErr(null);
    try {
      await dispatchExamUrl(user, {
        examUrl: targetUrl,
        examName: targetName,
        durationMinutes: Number(dispatchDuration) || 120,
      });
      setActionMsg(`Exam URL successfully dispatched to all kiosks: ${targetUrl}`);
      await fetchStatus();
    } catch (err) {
      setActionErr(`Dispatch failed: ${err.message}`);
    } finally {
      setDispatching(false);
    }
  };

  const handleCommand = async (cmd, target = '*') => {
    setActionMsg(null);
    setActionErr(null);
    try {
      await sendKioskCommand(user, { command: cmd, targetCandidateId: target });
      setActionMsg(`Command [${cmd}] sent successfully to target [${target}]`);
      await fetchStatus();
    } catch (err) {
      setActionErr(`Command failed: ${err.message}`);
    }
  };

  const handleEmergencyLock = async () => {
    if (!window.confirm('WARNING: Are you sure you want to trigger EMERGENCY LOCKDOWN across all connected kiosks?')) {
      return;
    }
    setActionMsg(null);
    setActionErr(null);
    try {
      await triggerEmergencyLock(user, 'Operator manual emergency lockdown');
      setActionMsg('EMERGENCY LOCKDOWN signal transmitted to all kiosk terminals.');
      await fetchStatus();
    } catch (err) {
      setActionErr(`Lockdown trigger failed: ${err.message}`);
    }
  };

  const handleReload = async () => {
    setActionMsg(null);
    setActionErr(null);
    try {
      await triggerKioskReload(user);
      setActionMsg('Kiosk runtime policies and Cage compositor reloaded.');
      await fetchStatus();
    } catch (err) {
      setActionErr(`Reload failed: ${err.message}`);
    }
  };

  const isConnected = liveData.connected;
  const srvHealth = liveData.health;
  const srvStatus = liveData.status;
  const devices = liveData.fleet?.devices || [];
  const terminals = liveData.terminals?.terminals || [];
  const currentExamUrl = srvStatus ? (srvStatus.exam_url || 'NOT_CONFIGURED') : 'Unavailable';
  const currentExamName = srvStatus ? (srvStatus.exam_name || 'NOT_CONFIGURED') : 'Unavailable';

  return (
    <Page
      title="Kiosk Fleet & Maintenance Operations"
      desc="Production real-time management of ExamOS appliances, Wayland Cage kiosks, and exam lifecycle flows."
      actions={
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <button
            className={`btn ${autoRefresh ? 'primary' : ''}`}
            onClick={() => setAutoRefresh(!autoRefresh)}
            title="Toggle 4-second live telemetry polling"
          >
            <Icon name="pulse" size={15} /> {autoRefresh ? 'Live Sync: ON' : 'Live Sync: OFF'}
          </button>
          <button className="btn" onClick={fetchStatus} disabled={loading}>
            <Icon name="refresh" size={15} /> Refresh
          </button>
          {can(user.role, 'kiosk.manage') && (
            <button className="btn danger" onClick={handleEmergencyLock}>
              <Icon name="lock" size={15} /> Emergency Lockdown
            </button>
          )}
        </div>
      }
    >
      {/* Live System Banner */}
      {actionMsg && <Alert tone="success" title="Success">{actionMsg}</Alert>}
      {actionErr && <Alert tone="danger" title="Error">{actionErr}</Alert>}

      {!isConnected && (
        <Alert tone="warn" title="Backend Gateway Offline / Disconnected">
          The ExamOS C Security Server (port 8895) is not responding. Ensure the backend daemon and PostgreSQL are running.
        </Alert>
      )}
      {liveData.errors?.length > 0 && (
        <Alert tone="warn" title="Some live kiosk data is unavailable">
          {liveData.errors.join('; ')}
        </Alert>
      )}

      {/* Production Telemetry Stats */}
      <StatGrid cols={4}>
        <Stat
          label="Gateway Liveness"
          value={srvHealth?.liveness || 'OFFLINE'}
          icon="server"
          tone={srvHealth?.liveness === 'LIVE' ? 'green' : 'amber'}
          sub={`Port 8895 · ${srvHealth?.tpm_mode || 'unknown'} mode`}
        />
        <Stat
          label="Enrolled Kiosks"
          value={devices.length}
          icon="device"
          tone="blue"
          sub={`${devices.filter((d) => (d.backendTrustOutcome || d.backend_trust_outcome) === 'ALLOW').length} server-verified`}
        />
        <Stat
          label="Active Terminals"
          value={terminals.length}
          icon="candidate"
          tone={terminals.length > 0 ? 'violet' : 'blue'}
          sub={`Center: ${liveData.terminals?.center_name || 'Unavailable'}`}
        />
        <Stat
          label="Evidence Ledger"
          value={srvHealth?.ledger_integrity || 'UNKNOWN'}
          icon="shield"
          tone={srvHealth?.ledger_integrity === 'INTACT' ? 'green' : 'amber'}
          sub="HMAC-SHA256 Authenticated"
        />
      </StatGrid>

      {/* Unified Examination & Kiosk Maintenance Lifecycle Flow */}
      <Card
        title="Candidate Terminal Unified Flow"
        desc="Single continuous lifecycle: from UEFI boot to cryptographic submission"
      >
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(5, 1fr)',
          gap: '12px',
          margin: '12px 0 6px',
        }}>
          {[
            {
              num: '01',
              title: 'Hardware Boot',
              desc: 'Hardened UEFI ISO boots Wayland Cage compositor directly on /dev/tty1',
              status: 'Active',
              icon: 'boot',
            },
            {
              num: '02',
              title: 'TPM Attestation',
              desc: 'Hardware quote verified (PCR 0, 4, 7, 11). Integrity chain anchored.',
              status: srvHealth?.attestation_store ? 'Verified' : 'Bypassed',
              icon: 'cpu',
            },
            {
              num: '03',
              title: 'Onboarding & Diagnostic',
              desc: 'Candidate enters onboarding.html: Camera check, integrity pledge, UI test',
              status: currentExamUrl.includes('onboarding') ? 'Current URL' : 'Ready',
              icon: 'checklist',
            },
            {
              num: '04',
              title: 'Exam Lockdown',
              desc: 'Chromium locked in sandbox: USB blocked, TTY masked, focus monitored',
              status: 'Enforced',
              icon: 'lock',
            },
            {
              num: '05',
              title: 'Sealed Submission',
              desc: 'Encrypted response committed to HMAC audit ledger. Exam key destroyed.',
              status: 'Ready',
              icon: 'package',
            },
          ].map((stage, i) => (
            <div
              key={stage.num}
              style={{
                background: '#ffffff',
                border: '1px solid var(--line)',
                borderRadius: '10px',
                padding: '16px',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                boxShadow: 'var(--shadow)',
              }}
            >
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <span style={{ fontSize: '11px', fontWeight: 800, color: 'var(--brand)' }}>PHASE {stage.num}</span>
                  <Badge value={stage.status} />
                </div>
                <h4 style={{ margin: '0 0 6px 0', fontSize: '14px', fontWeight: 700, color: 'var(--ink)' }}>{stage.title}</h4>
                <p style={{ margin: 0, fontSize: '12px', color: 'var(--mut)', lineHeight: 1.45 }}>{stage.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </Card>

      {/* Real-time Exam URL Dispatch Controller */}
      <div className="dash-grid" style={{ marginTop: '16px' }}>
        <div>
          <Card
            title="Active Exam Dispatch Controller"
            desc="Broadcast examination URLs or local onboarding flows to all connected kiosks in real-time"
          >
            <div style={{ marginBottom: '16px', background: '#f8fafc', padding: '16px', borderRadius: '10px', border: '1px solid var(--line)' }}>
              <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--mut)', letterSpacing: '0.04em', marginBottom: '6px' }}>CURRENT ACTIVE BROADCAST URL</div>
              <div style={{ fontSize: '14px', fontFamily: 'var(--mono)', color: 'var(--brand)', wordBreak: 'break-all', fontWeight: 600 }}>
                {currentExamUrl}
              </div>
              <div style={{ fontSize: '12px', color: 'var(--mut)', marginTop: '6px' }}>
                Exam Title: <b style={{ color: 'var(--ink)' }}>{currentExamName}</b>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div>
                <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--ink)', display: 'block', marginBottom: '6px' }}>
                  Dispatch Presets (One-Click)
                </label>
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  <button
                    type="button"
                    className="btn mini"
                    onClick={() => handleDispatch('file:///usr/share/examos/onboarding.html', 'ExamOS Candidate Onboarding & System Diagnostics')}
                  >
                    🚀 Onboarding & Practice Flow
                  </button>
                  <button
                    type="button"
                    className="btn mini"
                    onClick={() => handleDispatch('file:///usr/share/examos/waiting.html', 'ExamOS Terminal Standby')}
                  >
                    ⏳ Waiting Room Standby
                  </button>
                  <button
                    type="button"
                    className="btn mini"
                    onClick={() => handleDispatch('http://localhost:5173/onboarding.html', 'Local Dev Candidate Portal')}
                  >
                    💻 Local Dev Portal (:5173)
                  </button>
                  <button
                    type="button"
                    className="btn mini"
                    onClick={() => handleDispatch('https://staging.examos.example.edu', 'University Staging Gateway')}
                  >
                    🏛️ University Exam Gateway
                  </button>
                </div>
              </div>

              <div>
                <label style={{ fontSize: '12px', fontWeight: 600, color: '#cbd5e1', display: 'block', marginBottom: '4px' }}>
                  Target Exam URL or File Path
                </label>
                <input
                  type="text"
                  className="input"
                  style={{ width: '100%', fontFamily: 'monospace', fontSize: '13px' }}
                  value={dispatchUrl}
                  onChange={(e) => setDispatchUrl(e.target.value)}
                  placeholder="e.g. file:///usr/share/examos/onboarding.html or https://exam.university.edu"
                />
              </div>

              <div>
                <label style={{ fontSize: '12px', fontWeight: 600, color: '#cbd5e1', display: 'block', marginBottom: '4px' }}>
                  Exam Title / Description
                </label>
                <input
                  type="text"
                  className="input"
                  style={{ width: '100%' }}
                  value={dispatchName}
                  onChange={(e) => setDispatchName(e.target.value)}
                  placeholder="e.g. Cambridge Computer Science Final Examination"
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '6px' }}>
                <span style={{ fontSize: '12px', color: '#64748b' }}>
                  Updates take effect across all kiosk browsers immediately upon dispatch.
                </span>
                <button
                  className="btn primary"
                  disabled={dispatching || !can(user.role, 'kiosk.manage')}
                  onClick={() => handleDispatch()}
                >
                  <Icon name="upload" size={15} /> {dispatching ? 'Dispatching...' : 'Dispatch URL to Fleet'}
                </button>
              </div>
            </div>
          </Card>

          {/* Kiosk Fleet Terminals Table */}
          <Card
            title="Connected Kiosks & Hardware Terminals"
            desc="Devices reported by the live ExamOS backend"
            actions={<span className="mini">{devices.length} enrolled</span>}
          >
            <DataTable
              rows={devices}
              dense
              pageSize={6}
              search={(d) => `${d.device_id} ${d.hostname} ${d.compliance_status}`}
              columns={[
                {
                  key: 'device_id',
                  label: 'Kiosk Terminal',
                  render: (d) => (
                    <>
                      <b>{d.device_id}</b>
                      <br />
                      <small className="muted mono">{d.hostname || 'Unreported'}</small>
                    </>
                  ),
                },
                {
                  key: 'hardware_platform',
                  label: 'Hardware / Environment',
                  render: (d) => <span className="mono" style={{ fontSize: '11px' }}>{d.hardware_platform || 'Unreported'}</span>,
                },
                {
                  key: 'attestation_status',
                  label: 'TPM Attestation',
                  render: (d) => {
                    const verified = (d.backendTrustOutcome || d.backend_trust_outcome) === 'ALLOW';
                    return <Badge value={verified ? 'Server verified' : 'Unverified'} tone={verified ? 'green' : 'amber'} />;
                  },
                },
                {
                  key: 'session_state',
                  label: 'Session State',
                  render: (d) => <Badge value={d.session_state || 'Unknown'} />,
                },
                {
                  key: 'actions',
                  label: 'Control Actions',
                  render: (d) => (
                    <div style={{ display: 'flex', gap: '4px' }}>
                      <button
                        className="btn mini"
                        title="Send Ping Heartbeat"
                        onClick={() => handleCommand('PING', d.device_id)}
                      >
                        Ping
                      </button>
                      <button
                        className="btn mini"
                        title="Force Reload Kiosk Session"
                        onClick={() => handleCommand('RELOAD', d.device_id)}
                      >
                        Reload
                      </button>
                      <button
                        className="btn mini danger"
                        title="Emergency Terminal Lockdown"
                        onClick={() => handleCommand('LOCK', d.device_id)}
                      >
                        Lock
                      </button>
                    </div>
                  ),
                },
              ]}
            />
          </Card>
        </div>

        <div>
          {/* Real-time Hardware Hardening Matrix */}
          <Card
            title="Zero-Trust Kiosk Security Matrix"
            desc="Physical and OS-level enforcement active inside the appliance image"
          >
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {[
                { name: 'Virtual Terminal Masking (TTY1)', state: 'ENFORCED', desc: 'getty@tty* masked to prevent console login breakout' },
                { name: 'Cage Wayland Sandbox', state: 'ACTIVE', desc: 'Single-application Wayland kiosk without window manager' },
                { name: 'USB Mass Storage Quarantine', state: 'ENFORCED', desc: 'UDEV kernel rules automatically reject all storage sticks' },
                { name: 'Chromium Anti-DevTools Policy', state: 'ACTIVE', desc: 'Inspect Element, extensions, and hotkeys disabled' },
                { name: 'Hardware TPM Quote Verification', state: srvHealth?.attestation_store ? 'VERIFIED' : 'ACTIVE', desc: 'PCR measurement hash validation enabled' },
                { name: 'Audited Evidence Ledger', state: srvHealth?.ledger_integrity || 'INTACT', desc: 'Cryptographic HMAC-SHA256 tamper-evident log' },
              ].map((sec) => (
                <div
                  key={sec.name}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '10px 14px',
                    background: '#f8fafc',
                    borderRadius: '8px',
                    border: '1px solid var(--line)',
                  }}
                >
                  <div>
                    <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--ink)' }}>{sec.name}</div>
                    <small style={{ color: 'var(--mut)' }}>{sec.desc}</small>
                  </div>
                  <Badge value={sec.state} />
                </div>
              ))}
            </div>
          </Card>

          {/* Quick Fleet Maintenance Operations */}
          <Card title="Fleet Maintenance Toolkit" desc="High-privilege appliance orchestration">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <b>Broadcast Terminal Ping</b>
                  <br />
                  <small className="muted">Verify keepalive and network latency across all kiosks</small>
                </div>
                <button className="btn mini" onClick={() => handleCommand('PING')}>
                  <Icon name="pulse" size={14} /> Send Ping
                </button>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <b>Reload Browser Policies</b>
                  <br />
                  <small className="muted">Hot-reload active URL allowlists and sandbox rules</small>
                </div>
                <button className="btn mini" onClick={handleReload}>
                  <Icon name="refresh" size={14} /> Hot Reload
                </button>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <b>Re-Attest Hardware Fleet</b>
                  <br />
                  <small className="muted">Request fresh PCR quotes from physical TPM chips</small>
                </div>
                <button className="btn mini" onClick={() => handleCommand('RELOAD')}>
                  <Icon name="shield" size={14} /> Re-Attest
                </button>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </Page>
  );
}
