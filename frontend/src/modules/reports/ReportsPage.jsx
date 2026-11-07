import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTenant } from '../../core/db/tenant';
import {
  Page, Card, DataTable, Badge, Icon, Empty, Stat, StatGrid, Loading, Alert,
  Field, Input, Select, Tabs, useFlash, Flash,
} from '../../core/ui/kit';
import { fmt } from '../../core/ui/format';
import {
  getCatalog, getHub, getReport, getHistory, createExport, downloadExport,
  emptyFilters, dateStartEpoch, dateEndEpoch, findGroup, findReport,
  reportsForGroup, reportLabel, reportError, formatSummaryValue, formatValue,
  summaryLabel, DEFAULT_PAGE_SIZE,
} from './service';

/* -------------------------------------------------------------------- hooks */

/**
 * Minimal async loader. `deps` controls when the request is re-run; the
 * returned `reload` forces a refresh without changing the inputs.
 */
export function useApi(loader, deps = []) {
  const [state, setState] = useState({ data: null, error: null, loading: true });
  const [nonce, setNonce] = useState(0);
  useEffect(() => {
    let live = true;
    setState((s) => ({ ...s, loading: true, error: null }));
    Promise.resolve()
      .then(loader)
      .then((data) => { if (live) setState({ data, error: null, loading: false }); })
      .catch((error) => { if (live) setState({ data: null, error, loading: false }); });
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce]);
  return { ...state, reload: () => setNonce((n) => n + 1) };
}

/* ------------------------------------------------------------------- filters */

function FilterBar({ value, onChange, onRun, onReset, busy, pageSizes = false }) {
  const set = (key, next) => onChange({ ...value, [key]: next, page: 1 });
  return (
    <form
      className="report-filters"
      onSubmit={(e) => { e.preventDefault(); onRun(); }}
    >
      <Field label="Search">
        <Input
          value={value.q}
          maxLength={120}
          placeholder="Code, title, hostname, CVE…"
          onChange={(e) => set('q', e.target.value)}
        />
      </Field>
      <Field label="Status contains">
        <Input
          value={value.status}
          maxLength={40}
          placeholder="e.g. open"
          onChange={(e) => set('status', e.target.value)}
        />
      </Field>
      <Field label="Exam id" help="Optional; only reports that support exam filtering use it.">
        <Input
          value={value.examId}
          maxLength={64}
          placeholder="exam record id"
          onChange={(e) => set('examId', e.target.value)}
        />
      </Field>
      <Field label="From">
        <Input type="date" value={value.fromDate} onChange={(e) => set('fromDate', e.target.value)} />
      </Field>
      <Field label="To">
        <Input type="date" value={value.toDate} onChange={(e) => set('toDate', e.target.value)} />
      </Field>
      {pageSizes && (
        <Field label="Rows per page">
          <Select
            placeholder={false}
            value={value.pageSize}
            options={[25, 50, 100].map((n) => ({ v: n, l: `${n} / page` }))}
            onChange={(e) => onChange({ ...value, pageSize: Number(e.target.value), page: 1 })}
          />
        </Field>
      )}
      <div className="report-filter-actions">
        <button className="btn primary" type="submit" disabled={busy}>
          <Icon name="refresh" size={15} /> {busy ? 'Running…' : 'Run report'}
        </button>
        <button className="btn" type="button" onClick={onReset} disabled={busy}>Reset</button>
      </div>
    </form>
  );
}

/* ----------------------------------------------------------------- breakdown */

function Breakdown({ items, statusLabel }) {
  if (!items?.length) return null;
  const max = Math.max(1, ...items.map((i) => Number(i.value) || 0));
  return (
    <div className="report-breakdown">
      <div className="report-breakdown-title">{statusLabel || 'Distribution'}</div>
      {items.map((item) => {
        const value = Number(item.value) || 0;
        const width = Math.max(2, Math.round((value / max) * 100));
        return (
          <div className="report-bar" key={`${item.key}-${item.label}`}>
            <span className="report-bar-label" title={item.label}>{item.label || item.key}</span>
            <span className="report-bar-track"><i style={{ width: `${width}%` }} /></span>
            <b>{value.toLocaleString('en-IN')}</b>
          </div>
        );
      })}
    </div>
  );
}

/* --------------------------------------------------------------------- table */

const BADGE_COLUMNS = new Set([
  'status', 'severity', 'result', 'compatStatus', 'identity', 'deviceTrust',
  'deviceStatus', 'priority',
]);

function ReportTable({ data, busy, page, onPage, pageSize, onPageSize }) {
  const rows = useMemo(() => (data?.rows || []).map((row, index) => ({ ...row, __rowKey: `${index}-${row.id ?? row.key ?? ''}` })), [data]);
  const columns = useMemo(() => (data?.columns || []).map((col) => ({
    key: col.key,
    label: col.label,
    sortable: col.type === 'number' || col.type === 'epoch',
    render: (row) => {
      const value = row[col.key];
      const shown = formatValue(value, col.type);
      if (BADGE_COLUMNS.has(col.key) && value !== null && value !== undefined && value !== '') {
        return <Badge value={value} />;
      }
      return shown;
    },
  })), [data]);

  const total = data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const first = total ? (page - 1) * pageSize + 1 : 0;
  const last = Math.min(page * pageSize, total);

  return (
    <>
      <div className="report-pager">
        <span className="muted sm">
          {total ? `${first}–${last} of ${total.toLocaleString('en-IN')}` : '0 matching rows'}
          {busy ? ' · refreshing…' : ''}
        </span>
        <span className="grow" />
        <Select
          className="page-size"
          aria-label="Server rows per page"
          placeholder={false}
          value={pageSize}
          options={[25, 50, 100].map((n) => ({ v: n, l: `${n} / page` }))}
          onChange={(e) => onPageSize(Number(e.target.value))}
        />
        <div className="pager">
          <button className="mini" disabled={busy || page <= 1} onClick={() => onPage(page - 1)} aria-label="Previous page">‹</button>
          <span>{page} / {pages}</span>
          <button className="mini" disabled={busy || page >= pages} onClick={() => onPage(page + 1)} aria-label="Next page">›</button>
        </div>
      </div>
      <DataTable
        dense
        rowKey={(r) => r.__rowKey}
        rows={rows}
        columns={columns}
        pageSize={Math.max(rows.length, 1)}
        empty={<Empty icon="filter" title="No rows for these filters">Zero rows means the server found no matching records in your tenant scope. It does not prove the underlying activity did not happen.</Empty>}
      />
    </>
  );
}

/* --------------------------------------------------------------------- panel */

export function ReportPanel({ report, institutionId, onExported }) {
  const [draft, setDraft] = useState(emptyFilters);
  const [applied, setApplied] = useState(emptyFilters);
  const [exporting, setExporting] = useState('');
  const flash = useFlash();

  useEffect(() => {
    setDraft(emptyFilters());
    setApplied(emptyFilters());
    setExporting('');
    flash.setMsg(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [report.key, report.group]);

  const request = useApi(
    () => getReport(report.group, report.key, applied, institutionId),
    [report.group, report.key, applied, institutionId],
  );
  const data = request.data;

  const run = () => {
    const next = {
      ...draft,
      from: dateStartEpoch(draft.fromDate),
      to: dateEndEpoch(draft.toDate),
      page: 1,
    };
    setApplied(next);
  };

  const reset = () => {
    setDraft(emptyFilters());
    setApplied(emptyFilters());
  };

  const setPage = (page) => setApplied((current) => ({ ...current, page }));
  const setPageSize = (pageSize) => {
    setDraft((current) => ({ ...current, pageSize, page: 1 }));
    setApplied((current) => ({ ...current, pageSize, page: 1 }));
  };

  const runExport = async (format) => {
    setExporting(format);
    flash.setMsg(null);
    try {
      const exp = await createExport({
        report: report.key,
        group: report.group,
        format,
        filters: applied,
        institutionId,
      });
      downloadExport(exp);
      const truncated = exp.truncated ? ` — truncated from ${Number(exp.total).toLocaleString('en-IN')} to the ${Number(exp.rowCount).toLocaleString('en-IN')} row limit` : '';
      flash.setMsg({
        ok: true,
        text: `${String(exp.format).toUpperCase()} export downloaded with ${Number(exp.rowCount).toLocaleString('en-IN')} row(s)${truncated}. SHA-256 ${String(exp.sha256).slice(0, 16)}… · audit id ${exp.exportId}.`,
      });
      onExported?.();
    } catch (error) {
      flash.setMsg({ ok: false, text: reportError(error) });
    } finally {
      setExporting('');
    }
  };

  const summary = data?.summary || [];
  const definitions = data?.definitions || report.definitions;

  return (
    <Card
      title={report.label}
      desc={report.desc}
      actions={(
        <div className="row wrap">
          <button
            className="btn"
            onClick={() => runExport('csv')}
            disabled={!report.exportable || Boolean(exporting)}
            title={report.exportable ? 'Server-rendered CSV with spreadsheet-formula neutralisation' : 'Your role cannot export reports'}
          >
            <Icon name="download" size={15} /> {exporting === 'csv' ? 'Exporting…' : 'CSV'}
          </button>
          <button
            className="btn"
            onClick={() => runExport('json')}
            disabled={!report.exportable || Boolean(exporting)}
            title={report.exportable ? 'Server-rendered JSON rows' : 'Your role cannot export reports'}
          >
            <Icon name="download" size={15} /> {exporting === 'json' ? 'Exporting…' : 'JSON'}
          </button>
        </div>
      )}
    >
      <FilterBar
        value={draft}
        onChange={setDraft}
        onRun={run}
        onReset={reset}
        busy={request.loading}
        pageSizes
      />

      <Flash msg={flash.msg} onClose={() => flash.setMsg(null)} />

      {!report.exportable && (
        <Alert tone="warn" title="Preview only">
          Your role may view this report but not export it. Exports are denied by the server, not just hidden in the UI.
        </Alert>
      )}

      {request.loading && !data && <Loading label="Building report from authorized records…" />}

      {request.error && (
        <Alert tone="danger" title="Report unavailable">
          {reportError(request.error)}
          {request.error?.status === 403 && <div><Link to="/reports">Return to the report hub</Link></div>}
        </Alert>
      )}

      {data && (
        <>
          <div className="row wrap report-meta">
            <span className="muted sm">
              Generated {fmt(data.generatedAt)} · scope {data.scope?.global ? 'all institutions (platform owner)' : data.scope?.institutionId || 'institution'} · page {data.page} of {Math.max(1, Math.ceil((data.total || 0) / (data.pageSize || DEFAULT_PAGE_SIZE)))}
            </span>
            <span className="grow" />
            <span className="muted sm">{report.statusLabel}: filter uses the Status field above.</span>
          </div>

          {summary.length > 0 && (
            <StatGrid cols={Math.min(4, summary.length)}>
              {summary.map((item) => (
                <Stat
                  key={item.key}
                  label={summaryLabel(item.key)}
                  value={formatSummaryValue(item.key, item.value)}
                  sub={item.key === 'lastAt' ? 'Newest matching record' : undefined}
                />
              ))}
            </StatGrid>
          )}

          <Breakdown items={data.breakdown} statusLabel={report.statusLabel} />

          <ReportTable
            data={data}
            busy={request.loading}
            page={data.page}
            pageSize={data.pageSize || draft.pageSize}
            onPage={setPage}
            onPageSize={setPageSize}
          />
        </>
      )}

      {definitions && (
        <details className="report-defs">
          <summary>Metric definition and data provenance</summary>
          <dl>
            <dt>Source</dt><dd>{definitions.source}</dd>
            <dt>Calculation</dt><dd>{definitions.calculation}</dd>
            <dt>Included</dt><dd>{definitions.inclusion}</dd>
            <dt>Excluded</dt><dd>{definitions.exclusion}</dd>
          </dl>
        </details>
      )}
    </Card>
  );
}

/* ---------------------------------------------------------------------- hub */

const GROUP_PAGES = new Set(['exams', 'devices', 'security']);

function HubSummary({ hub, catalog }) {
  const groups = hub?.groups || [];
  if (!groups.length) {
    return <Empty icon="chart" title="No groups available">Your role has no report group permissions.</Empty>;
  }
  return (
    <StatGrid cols={Math.min(4, groups.length)}>
      {groups.map((group) => {
        const first = (group.summary || [])[0];
        return (
          <Stat
            key={group.key}
            label={`${findGroup(catalog, group.key)?.label || group.label} — ${first ? summaryLabel(first.key) : 'summary'}`}
            value={group.error ? '—' : first ? formatSummaryValue(first.key, first.value) : '—'}
            sub={group.error || (first ? `Source report: ${reportLabel(catalog, group.report)}` : 'No summary returned')}
            icon="chart"
            to={GROUP_PAGES.has(group.key) ? `/reports/${group.key}` : undefined}
          />
        );
      })}
    </StatGrid>
  );
}

function ExportHistory({ catalog, institutionId, refreshKey }) {
  const request = useApi(() => getHistory(institutionId), [institutionId, refreshKey]);
  const history = request.data?.items || [];

  return (
    <Card
      title="Export history"
      desc="Append-only audit rows written by the server before each export is returned. Newest first, last 200 per scope."
      actions={<button className="btn" onClick={request.reload} disabled={request.loading}><Icon name="refresh" size={15} /> Refresh</button>}
    >
      {request.loading && !request.data && <Loading label="Loading export history…" />}
      {request.error && <Alert tone="danger" title="Export history unavailable">{reportError(request.error)}</Alert>}
      {request.data && (
        <DataTable
          dense
          rows={history}
          search={(r) => `${r.report_key} ${r.generated_by} ${r.content_sha256 || ''} ${r.id}`}
          pageSize={10}
          columns={[
            { key: 'generated_at', label: 'Generated', sortable: true, render: (r) => fmt(r.generated_at) },
            { key: 'report_key', label: 'Report', render: (r) => reportLabel(catalog, r.report_key) },
            { key: 'report_group', label: 'Group' },
            { key: 'export_format', label: 'Format', render: (r) => <Badge value={String(r.export_format).toUpperCase()} /> },
            { key: 'row_count', label: 'Rows', sortable: true, render: (r) => Number(r.row_count || 0).toLocaleString('en-IN') },
            { key: 'generated_by', label: 'By', mono: true },
            { key: 'content_sha256', label: 'SHA-256', render: (r) => <span className="mono sm" title={r.content_sha256}>{r.content_sha256 ? `${r.content_sha256.slice(0, 16)}…` : '—'}</span> },
            { key: 'status', label: 'Status', render: (r) => <Badge value={r.status} /> },
            { key: 'id', label: 'Audit id', render: (r) => <span className="mono sm" title={r.id}>{String(r.id).slice(0, 14)}…</span> },
          ]}
          empty={<Empty icon="download" title="No exports recorded">Exports appear here after the server has generated and audited them.</Empty>}
        />
      )}
    </Card>
  );
}

/* ------------------------------------------------------------------ section */

/** A group page: one catalog group, its reports and the shared report panel. */
export function ReportSection({ group, title, desc, preferredKeys }) {
  const { tenantId } = useTenant();
  const catalogRequest = useApi(() => getCatalog(), []);
  const catalog = catalogRequest.data;
  const reports = useMemo(() => reportsForGroup(catalog, group, preferredKeys), [catalog, group, preferredKeys]);
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    if (!reports.length) return;
    if (!selected || !reports.some((r) => r.key === selected)) setSelected(reports[0].key);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [catalog, group]);

  const report = reports.find((r) => r.key === selected) || reports[0] || null;

  return (
    <Page
      title={title}
      desc={desc}
      actions={<Link className="btn" to="/reports"><Icon name="chart" size={15} /> Report hub</Link>}
      wide
    >
      {catalogRequest.loading && !catalog && <Loading label="Loading report catalog…" />}
      {catalogRequest.error && (
        <Alert tone="danger" title="Report catalog unavailable">{reportError(catalogRequest.error)}</Alert>
      )}
      {catalog && !findGroup(catalog, group) && (
        <Alert tone="danger" title="Not available for your role">
          The server did not include the {group} report group in your catalog. Ask an administrator for access.
        </Alert>
      )}
      {catalog && findGroup(catalog, group) && (
        <>
          <Card title="Choose a report" desc={`${reports.length} report(s) available in this group for your role.`}>
            <Tabs
              value={selected}
              onChange={setSelected}
              tabs={reports.map((r) => ({ key: r.key, label: r.label }))}
            />
            {report && <p className="muted sm">{report.desc}</p>}
          </Card>
          {report && (
            <ReportPanel
              key={`${report.group}:${report.key}`}
              report={report}
              institutionId={tenantId}
            />
          )}
        </>
      )}
    </Page>
  );
}

/* --------------------------------------------------------------------- page */

export default function ReportsPage() {
  const { tenantId } = useTenant();
  const catalogRequest = useApi(() => getCatalog(), []);
  const catalog = catalogRequest.data;

  const [hubDraft, setHubDraft] = useState(emptyFilters);
  const [hubApplied, setHubApplied] = useState(emptyFilters);
  const [group, setGroup] = useState(null);
  const [selected, setSelected] = useState(null);
  const [historyRefresh, setHistoryRefresh] = useState(0);

  const catalogGroups = catalog?.groups || [];
  const groupKey = group || catalogGroups[0]?.key || null;
  const reports = useMemo(
    () => reportsForGroup(catalog, groupKey),
    [catalog, groupKey],
  );
  const report = reports.find((r) => r.key === selected) || reports[0] || null;

  const hubRequest = useApi(
    () => getHub(hubApplied, tenantId),
    [hubApplied, tenantId],
  );

  useEffect(() => {
    if (!catalogGroups.length) return;
    if (!groupKey || !catalogGroups.some((g) => g.key === groupKey)) {
      setGroup(catalogGroups[0].key);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [catalog]);

  useEffect(() => {
    if (!reports.length) { setSelected(null); return; }
    if (!selected || !reports.some((r) => r.key === selected)) setSelected(reports[0].key);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [groupKey, catalog]);

  const runHub = () => {
    setHubApplied({
      ...hubDraft,
      from: dateStartEpoch(hubDraft.fromDate),
      to: dateEndEpoch(hubDraft.toDate),
      page: 1,
    });
  };

  return (
    <Page
      title="Report hub"
      desc="Server-side reports over authorized PostgreSQL records. Filters, tenant scope, exports and export history are enforced by the API."
      wide
    >
      {catalogRequest.loading && !catalog && <Loading label="Loading report catalog…" />}
      {catalogRequest.error && (
        <Alert tone="danger" title="Report catalog unavailable">{reportError(catalogRequest.error)}</Alert>
      )}

      {catalog && (
        <>
          <Card
            title="Scope filters"
            desc="These filters apply to the hub headline summaries. Each report below keeps its own filter set."
            actions={<span className="muted sm">Server-side aggregation · no client samples</span>}
          >
            <FilterBar
              value={hubDraft}
              onChange={setHubDraft}
              onRun={runHub}
              onReset={() => { setHubDraft(emptyFilters()); setHubApplied(emptyFilters()); }}
              busy={hubRequest.loading}
            />
          </Card>

          {hubRequest.error && <Alert tone="danger" title="Hub summary unavailable">{reportError(hubRequest.error)}</Alert>}
          {hubRequest.data && (
            <>
              <div className="row wrap report-meta">
                <span className="muted sm">
                  Summaries generated {fmt(hubRequest.data.generatedAt)} · scope {hubRequest.data.scope?.global ? 'all institutions (platform owner)' : hubRequest.data.scope?.institutionId}
                </span>
                <span className="grow" />
                <span className="muted sm">Capabilities: CSV + JSON · scheduled exports {catalog.capabilities?.scheduled ? 'enabled' : 'not supported'} · max export rows {Number(catalog.capabilities?.maxExportRows || 0).toLocaleString('en-IN')}</span>
              </div>
              <HubSummary hub={hubRequest.data} catalog={catalog} />
            </>
          )}

          <Card title="Report catalog" desc="Groups and reports are limited to what your server role may view.">
            <Tabs
              value={groupKey}
              onChange={(key) => { setGroup(key); setSelected(null); }}
              tabs={catalogGroups.map((g) => ({ key: g.key, label: g.label, count: (g.reports || []).length }))}
            />
            <div className="report-catalog">
              {reports.map((item) => (
                <button
                  key={item.key}
                  className={'report-tile' + (report?.key === item.key ? ' on' : '')}
                  onClick={() => setSelected(item.key)}
                >
                  <b>{item.label}</b>
                  <span className="muted sm">{item.desc}</span>
                </button>
              ))}
            </div>
          </Card>

          {report && (
            <ReportPanel
              key={`${report.group}:${report.key}`}
              report={report}
              institutionId={tenantId}
              onExported={() => setHistoryRefresh((n) => n + 1)}
            />
          )}

          <ExportHistory
            catalog={catalog}
            institutionId={tenantId}
            refreshKey={historyRefresh}
          />
        </>
      )}
    </Page>
  );
}
