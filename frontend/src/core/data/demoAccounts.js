// Bootstrap identities written into the users store on first run. After that, all identity is read from the database.
// `tenant` is resolved against the seeded institutions: 'T1' = TCS ION, 'T2' = Demo Institute, null = global.
export const DEMO = [
  { username: 'root', name: 'Platform Root', role: 'superadmin', password: 'Exam0S!Root#2026', tenant: null, email: 'root@examos.example' },
  { username: 'ananya', name: 'Ananya Kumar', role: 'ops_admin', password: 'Exam0S!Ops#2026', tenant: null, email: 'ananya@examos.example' },
  { username: 'auditor', name: 'Meera Rao', role: 'auditor', password: 'Exam0S!Audit#2026', tenant: null, email: 'meera.rao@audit.example' },
  { username: 'release', name: 'Vikram Shah', role: 'release_engineer', password: 'Exam0S!Rel#2026', tenant: null, email: 'vikram.shah@examos.example' },

  { username: 'instadmin', name: 'Priya Menon', role: 'inst_admin', password: 'Exam0S!Inst#2026', tenant: 'T1', email: 'priya.menon@tcsion.example' },
  { username: 'controller', name: 'Arjun Nair', role: 'exam_controller', password: 'Exam0S!Ctrl#2026', tenant: 'T1', email: 'arjun.nair@tcsion.example' },
  { username: 'invig', name: 'Rahul Sen', role: 'invigilator', password: 'Exam0S!Invig#2026', tenant: 'T1', email: 'rahul.sen@tcsion.example' },
  { username: 'itadmin', name: 'Sneha Kulkarni', role: 'it_admin', password: 'Exam0S!It#2026', tenant: 'T1', email: 'sneha.k@tcsion.example' },
  { username: 'security', name: 'Kabir Bose', role: 'security_engineer', password: 'Exam0S!Sec#2026', tenant: 'T1', email: 'kabir.bose@tcsion.example' },
  { username: 'support', name: 'Divya Pillai', role: 'support', password: 'Exam0S!Supp#2026', tenant: 'T1', email: 'divya.pillai@tcsion.example' },
  { username: 'finance', name: 'Rohan Gupta', role: 'finance', password: 'Exam0S!Fin#2026', tenant: 'T1', email: 'rohan.gupta@tcsion.example' },
  { username: 'student', name: 'Aarav Sharma', role: 'student', password: 'Exam0S!Stud#2026', tenant: 'T1', email: 'aarav.sharma@mail.examos.example' },

  { username: 'demoinst', name: 'Nisha Verma', role: 'inst_admin', password: 'Exam0S!Demo#2026', tenant: 'T2', email: 'nisha.verma@demo.example' },
  { username: 'demostudent', name: 'Diya Nair', role: 'student', password: 'Exam0S!DemoStud#2026', tenant: 'T2', email: 'diya.nair@demo.example' },
];

export const DEMO_BY_ROLE = DEMO.reduce((acc, u) => {
  if (!acc[u.role]) acc[u.role] = [];
  acc[u.role].push(u);
  return acc;
}, {});
