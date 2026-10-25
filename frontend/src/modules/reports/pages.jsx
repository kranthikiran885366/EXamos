import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useTenant } from '../../core/db/tenant';
import { Page, Tabs, Card, Icon } from '../../core/ui/kit';
import { CATALOG } from './service';
import { ReportPreview } from './ReportsPage';
export { default as ReportsPage } from './ReportsPage';

function ReportSection({ title, desc, keys, icon }) {
  const { tenantId } = useTenant();
  const [type, setType] = useState(keys[0]);
  const reports = keys.map((k) => CATALOG.find((c) => c.key === k)).filter(Boolean);

  return (
    <Page title={title} desc={desc}
      actions={<Link className="btn" to="/reports"><Icon name="chart" size={15} /> Report hub</Link>}>
      <Card title="Choose a report">
        <Tabs value={type} onChange={setType} tabs={reports.map((r) => ({ key: r.key, label: r.label }))} />
        <p className="muted sm">{reports.find((r) => r.key === type)?.desc}</p>
      </Card>
      <ReportPreview key={type} type={type} tenantId={tenantId} />
    </Page>
  );
}

export function ExamReportsPage() {
  return <ReportSection title="Exam reports" desc="Attendance, results, lifecycle and candidate readiness."
    icon="exam" keys={['attendance', 'results', 'exam-summary', 'candidate-readiness']} />;
}

export function DeviceReportsPage() {
  return <ReportSection title="Device reports" desc="Fleet compliance, attestation, compatibility and USB custody."
    icon="device" keys={['fleet', 'attestation', 'compatibility', 'usb-custody']} />;
}

export function SecurityReportsPage() {
  return <ReportSection title="Security reports" desc="Incidents, events, vulnerabilities, release validation and audit summary."
    icon="shield" keys={['incidents', 'security-events', 'vulnerabilities', 'release-validation', 'audit-summary']} />;
}
