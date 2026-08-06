/*
 * GOVP-1 browser reference verifier.
 *
 * This module is byte-compatible with govp-protocol/govp 0.1.10. Records are
 * processed locally and no field is uploaded by this code.
 */
import { verifyAsync as nobleVerify } from './noble-ed25519.js?v=0.1.10-20260805.1';

const encoder = new TextEncoder();
const RECORD_DOMAIN = 'GOVP::record.v1\0';
const TYPECODE = {
  agent: 'AGENT',
  benchmark: 'BENCH',
  dataset: 'DATA',
  document: 'DOC',
  model: 'MODEL',
  pipeline: 'PIPE',
};
const REQUIRED = [
  'version',
  'canonical',
  'publisher',
  'asset-type',
  'asset-id',
  'asset-sha256',
  'govp-id',
  'evidence',
  'public-key',
  'signature',
];
const LEGACY = {
  pubkey: 'public-key',
  sha256: 'asset-sha256',
  timestamp: 'generated-at',
  type: 'asset-type',
};
const GOVP1_TRIM_CHARS = new Set(Array.from(
  '\u0009\u000b\u000c\u001c\u001d\u001e\u001f\u0020\u0085\u00a0\u1680'
  + '\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a'
  + '\u2028\u2029\u202f\u205f\u3000',
));
const URI_ALLOWED = new Set(Array.from(
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=",
));
const URI_HEX = new Set(Array.from('0123456789ABCDEFabcdef'));
const NON_PRINTABLE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Zs}]/u;

function asciiLower(value) {
  return String(value).replace(/[A-Z]/g, (character) => (
    String.fromCharCode(character.charCodeAt(0) + 32)
  ));
}

export function trimFieldValue(value) {
  const characters = Array.from(String(value));
  let start = 0;
  let end = characters.length;
  while (start < end && GOVP1_TRIM_CHARS.has(characters[start])) start += 1;
  while (end > start && GOVP1_TRIM_CHARS.has(characters[end - 1])) end -= 1;
  return characters.slice(start, end).join('');
}

export function normalizeFieldName(value) {
  return asciiLower(trimFieldValue(value));
}

function containsSurrogate(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdfff) {
      if (code <= 0xdbff && index + 1 < value.length) {
        const next = value.charCodeAt(index + 1);
        if (next >= 0xdc00 && next <= 0xdfff) {
          index += 1;
          continue;
        }
      }
      return true;
    }
  }
  return false;
}

function validateSignableFields(fields) {
  if (!fields || typeof fields !== 'object' || Array.isArray(fields)) {
    throw new TypeError('record must be an object');
  }
  for (const [rawKey, value] of Object.entries(fields)) {
    if (typeof rawKey !== 'string' || typeof value !== 'string') {
      throw new TypeError('record field names and values must be strings');
    }
    const key = normalizeFieldName(rawKey);
    if (containsSurrogate(key) || containsSurrogate(value)) {
      throw new TypeError('record fields must contain Unicode scalar values');
    }
    if (!key || /[:\0\r\n]/.test(key)) {
      throw new TypeError("record field names cannot be empty or contain ':', NUL, CR or LF");
    }
    if (/[\0\r\n]/.test(value)) {
      throw new TypeError('record field values cannot contain NUL, CR or LF');
    }
  }
}

function normalizeFields(fields) {
  const normalized = {};
  for (const [rawKey, rawValue] of Object.entries(fields)) {
    const key = normalizeFieldName(rawKey);
    normalized[LEGACY[key] || key] = trimFieldValue(rawValue);
  }
  return normalized;
}

function validUriCharacters(value) {
  for (let index = 0; index < value.length;) {
    const character = value[index];
    if (character === '%') {
      if (index + 2 >= value.length
          || !URI_HEX.has(value[index + 1])
          || !URI_HEX.has(value[index + 2])) return false;
      index += 3;
      continue;
    }
    if (!URI_ALLOWED.has(character)) return false;
    index += 1;
  }
  return true;
}

function validAbsoluteUrl(value, httpsOnly = false) {
  if (typeof value !== 'string' || !value || !validUriCharacters(value)) return false;
  const schemeMatch = /^([A-Za-z][A-Za-z0-9+.-]*):/.exec(value);
  if (!schemeMatch) return false;
  const scheme = asciiLower(schemeMatch[1]);
  if (httpsOnly && scheme !== 'https') return false;
  if ((scheme === 'http' || scheme === 'https') && !/^https?:\/\//i.test(value)) return false;
  try {
    const url = new URL(value);
    if ((scheme === 'http' || scheme === 'https') && !url.hostname) return false;
    if (url.username || url.password) return false;
    void url.port;
    return true;
  } catch {
    return false;
  }
}

export function normalizeCanonical(value) {
  if (typeof value !== 'string') return '';
  const raw = trimFieldValue(value);
  if (!validUriCharacters(raw)) return '';
  const match = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#]*)(.*)$/.exec(raw);
  if (!match || match[2].includes('@')) return '';
  try {
    const parsed = new URL(raw);
    if (!parsed.hostname) return '';
    void parsed.port;
  } catch {
    return '';
  }

  let authority = match[2];
  if (authority.startsWith('[')) {
    const end = authority.indexOf(']');
    if (end < 0) return '';
    authority = authority.slice(0, end + 1).toLowerCase() + authority.slice(end + 1);
  } else {
    const colon = authority.lastIndexOf(':');
    authority = colon >= 0
      ? authority.slice(0, colon).toLowerCase() + authority.slice(colon)
      : authority.toLowerCase();
  }
  return `${asciiLower(match[1])}://${authority}${match[3]}`;
}

function validBase64Length(value, expectedLength) {
  if (typeof value !== 'string'
      || value.length % 4 !== 0
      || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return false;
  try {
    return decodeBase64(value).length === expectedLength;
  } catch {
    return false;
  }
}

function validRfc3339Utc(value) {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?Z$/.exec(value);
  if (!match) return false;
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
  if (year < 1 || month < 1 || month > 12 || hour > 23 || minute > 59) return false;
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const monthDays = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (day < 1 || day > monthDays[month - 1]) return false;
  if (second === 60) return hour === 23 && minute === 59;
  return second >= 0 && second <= 59;
}

function validFormat(fields) {
  try {
    validateSignableFields(fields);
  } catch {
    return false;
  }
  const normalized = normalizeFields(fields);
  if (normalized.version !== 'GOVP-1') return false;
  if (!REQUIRED.every((key) => typeof normalized[key] === 'string' && normalized[key])) return false;
  if (normalized['generated-at'] && !validRfc3339Utc(normalized['generated-at'])) return false;
  return validAbsoluteUrl(normalized.canonical, true)
    && Object.hasOwn(TYPECODE, normalized['asset-type'])
    && /^[0-9a-f]{64}$/.test(normalized['asset-sha256'])
    && /^GOVP-(DOC|DATA|MODEL|AGENT|PIPE|BENCH)-[0-9a-f]{12}$/.test(normalized['govp-id'])
    && validAbsoluteUrl(normalized.evidence)
    && validBase64Length(normalized['public-key'], 32)
    && validBase64Length(normalized.signature, 64);
}

function decodeBase64(value) {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

function hexadecimal(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

async function sha256Hex(bytes) {
  return hexadecimal(await crypto.subtle.digest('SHA-256', bytes));
}

function concatenate(first, second) {
  const output = new Uint8Array(first.length + second.length);
  output.set(first, 0);
  output.set(second, first.length);
  return output;
}

function compareBytes(first, second) {
  const limit = Math.min(first.length, second.length);
  for (let index = 0; index < limit; index += 1) {
    if (first[index] !== second[index]) return first[index] - second[index];
  }
  return first.length - second.length;
}

export function parseRecord(text) {
  const fields = {};
  String(text).replace(/\r\n/g, '\n').split('\n').forEach((rawLine) => {
    const line = trimFieldValue(rawLine);
    if (!line || line.startsWith('#') || !line.includes(':')) return;
    const separator = line.indexOf(':');
    const key = normalizeFieldName(line.slice(0, separator));
    fields[LEGACY[key] || key] = trimFieldValue(line.slice(separator + 1));
  });
  return fields;
}

export function loadJsonRecord(payload) {
  let record = payload;
  let bundle = null;
  if (record && typeof record === 'object' && !Array.isArray(record) && record.format === 'GOVP-1') {
    if (!record.record || typeof record.record !== 'object' || Array.isArray(record.record)) {
      throw new TypeError('JSON bundle record must be an object');
    }
    if (!record.asset || typeof record.asset !== 'object' || Array.isArray(record.asset)) {
      throw new TypeError('JSON bundle asset must be an object');
    }
    bundle = record;
    record = record.record;
  }
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    throw new TypeError('JSON record must be an object');
  }
  if (!Object.entries(record).every(([key, value]) => (
    typeof key === 'string' && typeof value === 'string'
  ))) {
    throw new TypeError('JSON record field names and values must be strings');
  }
  validateSignableFields(record);
  const fields = normalizeFields(record);
  validateSignableFields(fields);
  if (bundle !== null && !bundleMatches(bundle, fields)) {
    throw new TypeError('JSON bundle asset must match the signed record');
  }
  return { fields, bundle };
}

export function signingInput(fields) {
  validateSignableFields(fields);
  const normalized = normalizeFields(fields);
  const items = Object.entries(normalized)
    .filter(([key, value]) => key !== 'signature' && value)
    .map(([key, value]) => ({ key, value, bytes: encoder.encode(key) }));
  items.sort((first, second) => compareBytes(first.bytes, second.bytes));
  return encoder.encode(items.map(({ key, value }) => `${key}: ${value}\n`).join(''));
}

export async function deriveGovpId(assetType, assetId, assetSha256) {
  const normalizedType = String(assetType || '').toLowerCase();
  if (!Object.hasOwn(TYPECODE, normalizedType)
      || containsSurrogate(String(assetId || ''))
      || containsSurrogate(String(assetSha256 || ''))) return null;
  const identity = `${normalizedType}\n${assetId}\n${String(assetSha256).toLowerCase()}`;
  const digest = await sha256Hex(encoder.encode(identity));
  return `GOVP-${TYPECODE[normalizedType]}-${digest.slice(0, 12)}`;
}

let nativeEd25519 = null;

async function supportsNativeEd25519() {
  if (nativeEd25519 !== null) return nativeEd25519;
  try {
    await crypto.subtle.importKey('raw', new Uint8Array(32), { name: 'Ed25519' }, false, ['verify']);
    nativeEd25519 = true;
  } catch {
    nativeEd25519 = false;
  }
  return nativeEd25519;
}

export async function verifyRecordSignature(fields) {
  const normalized = normalizeFields(fields);
  if (normalized.version !== 'GOVP-1') return null;
  if (!normalized.signature || !normalized['public-key']) return false;
  let message;
  try {
    message = concatenate(encoder.encode(RECORD_DOMAIN), signingInput(fields));
  } catch {
    return false;
  }
  if (await supportsNativeEd25519()) {
    try {
      const publicKey = await crypto.subtle.importKey(
        'raw',
        decodeBase64(normalized['public-key']),
        { name: 'Ed25519' },
        false,
        ['verify'],
      );
      return await crypto.subtle.verify(
        { name: 'Ed25519' },
        publicKey,
        decodeBase64(normalized.signature),
        message,
      );
    } catch {
      // Fall through to the vendored, audited implementation.
    }
  }
  try {
    return await nobleVerify(
      decodeBase64(normalized.signature),
      message,
      decodeBase64(normalized['public-key']),
    );
  } catch {
    return false;
  }
}

function isPrintable(value) {
  for (const character of String(value)) {
    if (character !== ' ' && NON_PRINTABLE.test(character)) return false;
  }
  return true;
}

function presentationWarnings(fields) {
  const warnings = new Set();
  for (const [key, value] of Object.entries(fields)) {
    if (typeof value === 'string' && (!isPrintable(key) || !isPrintable(value))) {
      warnings.add('signed-non-printable-text');
    }
  }
  const normalized = normalizeFields(fields);
  if (typeof normalized.evidence === 'string'
      && validAbsoluteUrl(normalized.evidence)
      && !/^https?:/i.test(normalized.evidence)) {
    warnings.add('non-http-evidence-scheme');
  }
  return Array.from(warnings).sort();
}

function bundleMatches(bundle, fields) {
  try {
    const normalized = normalizeFields(fields);
    return bundle
      && bundle.asset
      && bundle.asset.hash
      && bundle.asset.hash.alg === 'sha256'
      && bundle.asset.type === normalized['asset-type']
      && bundle.asset.id === normalized['asset-id']
      && bundle.asset.hash.value === normalized['asset-sha256'];
  } catch {
    return false;
  }
}

export async function verifyFields(fields, { fetchedUrl = null, assetBytes = null, bundle = null } = {}) {
  const normalized = normalizeFields(fields);
  const checks = {
    format: validFormat(fields),
    signature: await verifyRecordSignature(fields),
    'govp-id': false,
    canonical: fetchedUrl
      ? normalizeCanonical(normalized.canonical || '') === normalizeCanonical(fetchedUrl)
      : null,
    asset: null,
  };

  const derivedGovpId = normalized['asset-type'] && normalized['asset-id'] && normalized['asset-sha256']
    ? await deriveGovpId(normalized['asset-type'], normalized['asset-id'], normalized['asset-sha256'])
    : null;
  checks['govp-id'] = Boolean(derivedGovpId && normalized['govp-id'] === derivedGovpId);

  let assetSha256 = null;
  if (assetBytes !== null) {
    const bytes = assetBytes instanceof Uint8Array ? assetBytes : new Uint8Array(assetBytes);
    assetSha256 = await sha256Hex(bytes);
    checks.asset = assetSha256 === String(normalized['asset-sha256'] || '').toLowerCase();
  }

  const bundleOk = bundle === null ? null : bundleMatches(bundle, fields);
  const ok = checks.format
    && checks.signature === true
    && checks['govp-id']
    && checks.canonical !== false
    && checks.asset !== false
    && bundleOk !== false;

  return {
    ok,
    fields: normalized,
    checks,
    derivedGovpId,
    assetSha256,
    warnings: presentationWarnings(fields),
    bundle: bundleOk,
    native: nativeEd25519,
  };
}

export async function verifyText(text, options = {}) {
  return verifyFields(parseRecord(text), options);
}

export const GOVP = {
  RECORD_DOMAIN,
  TYPECODE,
  deriveGovpId,
  loadJsonRecord,
  normalizeCanonical,
  normalizeFieldName,
  parseRecord,
  signingInput,
  trimFieldValue,
  verifyFields,
  verifyRecordSignature,
  verifyText,
};

export default GOVP;
