// Production platform bootstrap identities. All operational accounts are managed via the database.
export const DEMO = [
  { username: 'root', name: 'Platform Root', role: 'superadmin', password: 'Exam0S!Root#2026', tenant: null, email: 'root@examos.local' },
  { username: 'admin', name: 'Platform Administrator', role: 'superadmin', password: 'StrongAdminPassword#2026!', tenant: null, email: 'admin@examos.local' },
];

export const DEMO_BY_ROLE = DEMO.reduce((acc, u) => {
  if (!acc[u.role]) acc[u.role] = [];
  acc[u.role].push(u);
  return acc;
}, {});
