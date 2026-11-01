// Demo seed identities.
//
// This file used to ship plaintext platform bootstrap passwords inside the
// JavaScript bundle. That is a credential disclosure hazard (anyone who can
// fetch the login page can read it) and it duplicated the server's account
// database. Management accounts are now provisioned by the ExamOS server and
// the console has no local credential login, so no seed identities exist.
export const DEMO = [];

export const DEMO_BY_ROLE = {};
