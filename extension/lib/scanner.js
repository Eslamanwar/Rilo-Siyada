/**
 * Siyada — Keyword Hint Engine
 *
 * This is NOT a PII detector. The LLM is the only detector.
 *
 * This file exists solely to update the badge color while the user types,
 * giving a live hint that something might be sensitive before they press send.
 * It uses simple word matching — no regex patterns trying to validate PII values,
 * which always fail on edge cases. The one exception is credential *prefixes*
 * (AKIA, ghp_, -----BEGIN PRIVATE KEY): those are fixed by the issuing vendor,
 * so a prefix check is exact, and pasted code rarely contains the plain words above.
 *
 * Export (via window.SiyadaScanner):
 *   mightBeSensitive(text) → boolean
 *     Returns true if any sensitive keyword is present — used only for badge color.
 *     False negatives are fine here; the LLM catches everything on send.
 */

(() => {
  'use strict';

  // Words that suggest the message might contain something sensitive.
  // Deliberately broad — false positives here just turn the badge orange,
  // the LLM then decides the truth on send.
  const SENSITIVE_WORDS = [
    // Identity
    'emirates id', 'eid', 'identity card', 'national id', 'passport',
    'رقم الهوية', 'هوية', 'جواز',

    // Financial
    'credit card', 'debit card', 'card number', 'iban', 'account number',
    'cvv', 'expiry', 'bank account', 'routing number',
    'رقم الحساب', 'بطاقة',

    // Credentials
    'password', 'passwd', 'secret', 'api key', 'access key', 'private key',
    'token', 'credential', 'auth', 'passphrase', 'pin',
    'كلمة المرور', 'مفتاح',

    // Health
    'patient', 'diagnosis', 'prescription', 'medical record', 'ssn',
    'blood type', 'مريض', 'تشخيص', 'وصفة',

    // Generic PII signals
    'date of birth', 'dob', 'home address', 'phone number', 'mobile number',
    'social security', 'tax id', 'تاريخ الميلاد',
  ];

  // Vendor-fixed credential prefixes and code shapes that carry secrets.
  const SECRET_SHAPES = [
    /\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b/,      // AWS key IDs
    /\barn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:\d{12}:/,      // AWS ARN with account id
    /-----BEGIN [A-Z ]*PRIVATE KEY/,                        // PEM private key
    /\b(?:gh[pousr]_|github_pat_|glpat-|xox[abprs]-|AIza|GOCSPX-|sk-ant-|sk-proj-|sk_live_|rk_live_|SG\.)/, // vendor tokens
    /\beyJ[A-Za-z0-9_-]{8,}\.eyJ/,                         // JWT
    /\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:[^\s@]+@/i,        // user:pass@ in a URL
    /\bBearer\s+[A-Za-z0-9._~+/=-]{20,}/,                  // Authorization header
    /\b(?:aws_secret_access_key|aws_access_key_id|client_secret|api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]/i, // config assignment
  ];

  function mightBeSensitive(text) {
    if (!text || typeof text !== 'string') return false;
    const lower = text.toLowerCase();
    return SENSITIVE_WORDS.some(word => lower.includes(word)) ||
           SECRET_SHAPES.some(re => re.test(text));
  }

  window.SiyadaScanner = { mightBeSensitive };
})();
