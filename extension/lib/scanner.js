/**
 * Siyada — Keyword Hint Engine
 *
 * This is NOT a PII detector. The LLM is the only detector.
 *
 * This file exists solely to update the badge color while the user types,
 * giving a live hint that something might be sensitive before they press send.
 * It uses simple word matching — no regex patterns trying to validate PII values,
 * which always fail on edge cases.
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

  function mightBeSensitive(text) {
    if (!text || typeof text !== 'string') return false;
    const lower = text.toLowerCase();
    return SENSITIVE_WORDS.some(word => lower.includes(word));
  }

  window.SiyadaScanner = { mightBeSensitive };
})();
