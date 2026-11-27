/**
 * Lightweight regional language (i18n) registry for ExamOS Console.
 * Supports English (en), Hindi (hi), and Telugu (te) with safe fallback to English.
 */

export const SUPPORTED_LOCALES = [
  { code: 'en', label: 'English' },
  { code: 'hi', label: 'हिन्दी (Hindi)' },
  { code: 'te', label: 'తెలుగు (Telugu)' },
];

const DICTIONARIES = {
  en: {
    'nav.dashboard': 'Dashboard',
    'nav.exams': 'Exams',
    'nav.candidates': 'Candidates',
    'nav.devices': 'Devices',
    'nav.audit': 'Audit trail',
    'nav.releases': 'Releases',
    'nav.monitoring': 'Monitoring',
    'action.freeze_session': 'Freeze Session',
    'action.export_signed_audit': 'Download Signed Export',
    'action.verify_ledger': 'Verify Ledger',
    'status.frozen': 'Session Frozen',
    'status.healthy': 'System Healthy',
  },
  hi: {
    'nav.dashboard': 'डैशबोर्ड',
    'nav.exams': 'परीक्षाएं',
    'nav.candidates': 'अभ्यर्थी',
    'nav.devices': 'उपकरण',
    'nav.audit': 'ऑडिट ट्रेल',
    'nav.releases': 'रिलीज़',
    'nav.monitoring': 'निगरानी',
    'action.freeze_session': 'सत्र फ्रीज़ करें',
    'action.export_signed_audit': 'हस्ताक्षरित ऑडिट डाउनलोड करें',
    'action.verify_ledger': 'लेज़र सत्यापित करें',
    'status.frozen': 'सत्र फ्रीज़ किया गया',
    'status.healthy': 'सिस्टम स्वस्थ है',
  },
  te: {
    'nav.dashboard': 'డాష్‌బోర్డ్',
    'nav.exams': 'పరీక్షలు',
    'nav.candidates': 'అభ్యర్థులు',
    'nav.devices': 'పరికరాలు',
    'nav.audit': 'ఆడిట్ ట్రయల్',
    'nav.releases': 'విడుదలలు',
    'nav.monitoring': 'పర్యవేక్షణ',
    'action.freeze_session': 'సెషన్ ఫ్రీజ్ చేయండి',
    'action.export_signed_audit': 'సంతకం చేసిన ఆడిట్ డౌన్‌లోడ్',
    'action.verify_ledger': 'లెడ్జర్ ధృవీకరించండి',
    'status.frozen': 'సెషన్ ఫ్రీజ్ చేయబడింది',
    'status.healthy': 'సిస్టమ్ ఆరోగ్యంగా ఉంది',
  },
};

const STORAGE_KEY = 'examos.locale';

export function getLocale() {
  try {
    const saved = typeof localStorage !== 'undefined' ? localStorage.getItem(STORAGE_KEY) : null;
    if (saved && DICTIONARIES[saved]) return saved;
  } catch { /* ignore storage restrictions */ }
  return 'en';
}

export function setLocale(code) {
  const next = DICTIONARIES[code] ? code : 'en';
  try {
    if (typeof localStorage !== 'undefined') localStorage.setItem(STORAGE_KEY, next);
  } catch { /* ignore */ }
  return next;
}

export function t(key, locale = getLocale()) {
  const dict = DICTIONARIES[locale] || DICTIONARIES.en;
  return dict[key] || DICTIONARIES.en[key] || key;
}
