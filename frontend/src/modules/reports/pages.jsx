import { ReportSection } from './ReportsPage';

export { default as ReportsPage } from './ReportsPage';

export function ExamReportsPage() {
  return (
    <ReportSection
      group="exams"
      title="Exam reports"
      desc="Exam lifecycle, attendance, results and candidate readiness, aggregated by the server from authorized records."
      preferredKeys={['exam-summary', 'attendance', 'results', 'candidate-readiness']}
    />
  );
}

export function DeviceReportsPage() {
  return (
    <ReportSection
      group="devices"
      title="Device reports"
      desc="Fleet compliance, attestation, hardware compatibility and USB custody, enforced by tenant scope."
      preferredKeys={['fleet', 'attestation', 'compatibility', 'usb-custody']}
    />
  );
}

export function SecurityReportsPage() {
  return (
    <ReportSection
      group="security"
      title="Security reports"
      desc="Tenant-scoped server reports for incidents, security events, vulnerabilities, release validation and audit summaries. These report populations are distinct from the platform administrative-event list and global ledger."
      preferredKeys={['incidents', 'security-events', 'vulnerabilities', 'release-validation', 'audit-summary']}
    />
  );
}
