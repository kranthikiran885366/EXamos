import { useMemo, useState } from 'react';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant, useCol } from '../../core/db/tenant';
import {
  Page, Card, DataTable, Badge, Icon, Empty, Stat, StatGrid, Loading, Alert,
  Field, Select, useFlash, Flash, Tabs, CopyButton,
} from '../../core/ui/kit';
import { fmt, ago } from '../../core/ui/format';
import { usePerm } from '../../core/ui/hooks';
import { csvCell } from '../../core/security/sanitize';
import { CATALOG, GROUPS, buildReport, saveReport, reportStats } from './service';

const labelOf = (key) => CATALOG.find((c) => c.key === key)?.label || key;

export function ReportPreview({ type, tenantId, onExported }) {
  const { user } = useAuth();
  const [data, setData] = useState(null);
  const [busy, setBusy] = useState(false);
  const flash = useFlash();
  const perms = usePerm();

  const runBuild = async () => {
    setBusy(true);
    try { setData(await buildReport(type, tenantId)); flash.setMsg({ ok: true, text: 'Preview built.' }); }
    catch (e) { flash.setMsg({ ok: false, text: e.message || String(e) }); }
    setBusy(false);
  };

  const exportCsv = async () => {
    if (!data) return;
    setBusy(true);
    try {
      const csv = [data.cols, ...data.rows].map((r) => r.map(csvCell).join(',')).join('\n');
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }));
      a.download = `${type}-${Date.now()}.csv`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
      await saveReport(user, type, tenantId, data.rows);
      flash.setMsg({ ok: true, text: `Exported ${data.rows.length} rows. The export is recorded in the audit log.` });
      onExported?.();
    } catch (e) { flash.setMsg({ ok: false, text: e.message || String(e) }); }
    setBusy(false);
  };

  const previewRows = useMemo(() => (data ? data.rows.map((r, i) => ({ id: `row-${i}`, ...Object.fromEntries(data.cols.map((c, j) => [c, r[j]])) })) : []), [data]);
  const previewCols = useMemo(() => (data ? data.cols.map((c) => ({ key: c, label: c })) : []), [data]);

  return (
    <Card title={labelOf(type)} desc={CATALOG.find((c) => c.key === type)?.desc}
      actions={<div className="row">
        <button className="btn" onClick={runBuild} disabled={busy}><Icon name="refresh" size={15} /> {data ? 'Rebuild' : 'Build preview'}</button>
        <button className="btn primary" onClick={exportCsv} disabled={!data || busy || !perms('export') || !perms('report.generate')}><Icon name="download" size={15} /> Export CSV</button>
      </div>}>
      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />
      {!data ? <Empty icon="chart" title="No preview yet">Build the report to see live rows.</Empty> : (
        <>
          <div className="row wrap"><Badge value={`${data.rows.length} rows`} /><span className="muted sm">Computed from live records at generation time. Zero rows can mean no data or no telemetry.</span></div>
          <DataTable
            rows={previewRows} columns={previewCols} dense pageSize={50}
            empty={<Empty icon="chart" title="No rows">That does not prove nothing happened; check the source module.</Empty>}
          />
        </>
      )}
    </Card>
  );
}

export default function ReportsPage() {
  const { tenantId } = useTenant();
  const saved = useCol('reports', false);
  const [group, setGroup] = useState(GROUPS[0]);
  const [type, setType] = useState(CATALOG[0].key);
  const [tick, setTick] = useState(0);
  const rows = saved.filter((r) => !r.tenantId || r.tenantId === tenantId);
  const stats = reportStats([...rows]);
  const types = CATALOG.filter((c) => c.group === group);

  return (
    <Page title="Report hub" desc="Build, preview and export reports from live records. Every export is hashed and audited."
      wide>
      <StatGrid cols={4}>
        <Stat label="Generated reports" value={stats.generated} icon="chart" />
        <Stat label="Report types used" value={stats.types} icon="checklist" />
        <Stat label="Last generated" value={stats.lastAt ? ago(stats.lastAt) : '—'} icon="clock" sub={stats.lastAt ? fmt(stats.lastAt) : ''} />
        <Stat label="Catalog" value={CATALOG.length} icon="package" />
      </StatGrid>
      <Card title="Report catalog" desc="Choose a group, then build the report you need.">
        <Tabs value={group} onChange={(g) => { setGroup(g); setType(CATALOG.find((c) => c.group === g)?.key || type); }} tabs={GROUPS} />
        <div className="report-catalog">
          {types.map((c) => (
            <button key={c.key} className={'report-tile' + (type === c.key ? ' on' : '')} onClick={() => setType(c.key)}>
              <b>{c.label}</b>
              <span className="muted sm">{c.desc}</span>
            </button>
          ))}
        </div>
      </Card>
      <ReportPreview key={`${type}-${tick}`} type={type} tenantId={tenantId} onExported={() => setTick((n) => n + 1)} />
      <DataTable
        title="Generated reports" desc="Newest first. Hashes prove the exported rows were not altered."
        rows={[...rows].sort((a, b) => b.at - a.at)}
        search={(r) => `${labelOf(r.type)} ${r.by} ${r.hash}`}
        columns={[
          { key: 'at', label: 'Generated', sortable: true, render: (r) => fmt(r.at) },
          { key: 'type', label: 'Report', render: (r) => labelOf(r.type) },
          { key: 'count', label: 'Rows', sortable: true },
          { key: 'by', label: 'By', mono: true },
          { key: 'hash', label: 'SHA-256', render: (r) => <span className="mono sm">{r.hash ? `${r.hash.slice(0, 20)}…` : '—'}</span> },
        ]}
        empty={<Empty icon="chart" title="No reports generated" />}
      />
    </Page>
  );
}
