/*
 * GOVP-1 JavaScript verifier.
 *
 * This module is byte-compatible with govp-protocol/govp 0.1.11. Records are
 * processed locally and no field is uploaded by this code.
 */
import { Point, hashes, verify as nobleVerify } from './noble-ed25519.js?v=0.1.11-20260806.1';
import { sha256, sha512 } from './noble-hashes/sha2.js?v=0.1.11-20260806.1';

hashes.sha512 = sha512;

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

function normalizeJsonFields(fields) {
  const normalized = {};
  const sources = new Map();
  for (const [rawKey, rawValue] of Object.entries(fields)) {
    const normalizedKey = normalizeFieldName(rawKey);
    const canonicalKey = LEGACY[normalizedKey] || normalizedKey;
    if (sources.has(canonicalKey)) {
      throw new TypeError(
        `JSON record contains colliding normalized field names: ${JSON.stringify(sources.get(canonicalKey))} and ${JSON.stringify(rawKey)}`,
      );
    }
    sources.set(canonicalKey, rawKey);
    normalized[canonicalKey] = trimFieldValue(rawValue);
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

function rfc3339UtcMilliseconds(value) {
  if (!validRfc3339Utc(value)) return null;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?Z$/.exec(value);
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
  const milliseconds = Number((match[7] || '').padEnd(3, '0').slice(0, 3));
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, Math.min(second, 59), milliseconds);
  return date.getTime() + (second === 60 ? 1000 : 0);
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
  return hexadecimal(sha256(bytes));
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
  const fields = normalizeJsonFields(record);
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

function littleEndianInteger(bytes) {
  let result = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    result = (result << 8n) | BigInt(bytes[index]);
  }
  return result;
}

function strictPrimeSubgroupPoint(bytes) {
  try {
    const point = Point.fromBytes(bytes, false);
    return !point.isSmallOrder() && point.isTorsionFree();
  } catch {
    return false;
  }
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
  try {
    const publicKey = decodeBase64(normalized['public-key']);
    const signature = decodeBase64(normalized.signature);
    if (!strictPrimeSubgroupPoint(publicKey)
        || !strictPrimeSubgroupPoint(signature.subarray(0, 32))
        || littleEndianInteger(signature.subarray(32)) >= Point.CURVE().n) return false;
    return await nobleVerify(
      signature,
      message,
      publicKey,
      { zip215: false },
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
    native: false,
    backend: '@noble/ed25519@3.1.0-strict',
  };
}

export async function verifyText(text, options = {}) {
  return verifyFields(parseRecord(text), options);
}


const KEY_STATES = new Set(['active', 'retired', 'revoked']);
const REVOCATION_REASONS = new Set([
  'cessation', 'compromised', 'other', 'superseded', 'withdrawn',
]);
const STATUS_FIELDS = new Set([
  'authority', 'canonical', 'format', 'generated_at', 'keys', 'publisher',
  'revoked_records',
]);
const KEY_FIELDS = new Set(['changed_at', 'key_id', 'public_key', 'state']);
const REVOCATION_FIELDS = new Set(['govp_id', 'reason', 'revoked_at']);

function hasExactFields(value, expected) {
  const keys = Object.keys(value);
  return keys.length === expected.size && keys.every((key) => expected.has(key));
}

export async function deriveKeyId(publicKey) {
  if (!validBase64Length(publicKey, 32)) {
    throw new TypeError('public key must contain 32 raw Ed25519 bytes');
  }
  return `sha256:${await sha256Hex(decodeBase64(publicKey))}`;
}

export function parseStatus(text) {
  const payload = JSON.parse(text);
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new TypeError('status document must be a JSON object');
  }
  return payload;
}

function httpsOrigin(value) {
  if (!validAbsoluteUrl(value, true)) return null;
  try {
    const parsed = new URL(value);
    return `${parsed.protocol.toLowerCase()}//${parsed.hostname.toLowerCase()}:${parsed.port || '443'}`;
  } catch {
    return null;
  }
}

async function validStatusFormat(status) {
  if (!status || typeof status !== 'object' || Array.isArray(status)
      || !hasExactFields(status, STATUS_FIELDS)
      || status.format !== 'GOVP-STATUS-1'
      || status.authority !== 'https-origin'
      || typeof status.publisher !== 'string' || !status.publisher
      || typeof status.canonical !== 'string' || !validAbsoluteUrl(status.canonical, true)
      || typeof status.generated_at !== 'string' || !validRfc3339Utc(status.generated_at)
      || !Array.isArray(status.keys) || status.keys.length === 0
      || !Array.isArray(status.revoked_records)) return false;

  const keyIds = new Set();
  const publicKeys = new Set();
  for (const entry of status.keys) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)
        || !hasExactFields(entry, KEY_FIELDS)
        || typeof entry.key_id !== 'string'
        || typeof entry.public_key !== 'string'
        || !KEY_STATES.has(entry.state)
        || typeof entry.changed_at !== 'string'
        || !validRfc3339Utc(entry.changed_at)) return false;
    let expected;
    try {
      expected = await deriveKeyId(entry.public_key);
    } catch {
      return false;
    }
    if (entry.key_id !== expected
        || keyIds.has(entry.key_id)
        || publicKeys.has(entry.public_key)) return false;
    keyIds.add(entry.key_id);
    publicKeys.add(entry.public_key);
  }

  const revokedIds = new Set();
  for (const entry of status.revoked_records) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)
        || !hasExactFields(entry, REVOCATION_FIELDS)
        || typeof entry.govp_id !== 'string'
        || !/^GOVP-(DOC|DATA|MODEL|AGENT|PIPE|BENCH)-[0-9a-f]{12}$/.test(entry.govp_id)
        || revokedIds.has(entry.govp_id)
        || typeof entry.revoked_at !== 'string'
        || !validRfc3339Utc(entry.revoked_at)
        || !REVOCATION_REASONS.has(entry.reason)) return false;
    revokedIds.add(entry.govp_id);
  }
  return true;
}

export async function evaluateStatus(
  fields,
  status,
  {
    fetchedUrl = null,
    recordFetchedUrl = null,
    now = Date.now(),
    maxAgeSeconds = 300,
    maxFutureSkewSeconds = 60,
  } = {},
) {
  if (!Number.isFinite(maxAgeSeconds) || maxAgeSeconds < 0
      || !Number.isFinite(maxFutureSkewSeconds) || maxFutureSkewSeconds < 0) {
    throw new TypeError('status freshness windows must be finite and non-negative');
  }
  const evaluationTime = now instanceof Date ? now.getTime() : Number(now);
  if (!Number.isFinite(evaluationTime)) {
    throw new TypeError('status evaluation time must be a Date or millisecond timestamp');
  }
  const core = await verifyFields(fields, { fetchedUrl: recordFetchedUrl });
  const normalized = core.fields;
  const statusFormat = await validStatusFormat(status);
  const generatedAt = statusFormat ? rfc3339UtcMilliseconds(status.generated_at) : null;
  const statusFresh = generatedAt !== null
    && generatedAt >= evaluationTime - maxAgeSeconds * 1000
    && generatedAt <= evaluationTime + maxFutureSkewSeconds * 1000;
  const statusCanonical = fetchedUrl === null
    ? null
    : Boolean(
      statusFormat
      && normalizeCanonical(status.canonical) === normalizeCanonical(fetchedUrl),
    );
  const sameOrigin = Boolean(
    statusFormat && httpsOrigin(normalized.canonical) === httpsOrigin(status.canonical),
  );
  const keyActive = Boolean(
    statusFormat && status.keys.some((entry) => (
      entry.public_key === normalized['public-key'] && entry.state === 'active'
    )),
  );
  const recordNotRevoked = Boolean(
    statusFormat && Boolean(normalized['govp-id']) && !status.revoked_records.some((entry) => (
      entry.govp_id === normalized['govp-id']
    )),
  );
  const checks = {
    core: core.ok,
    'status-format': statusFormat,
    'status-fresh': statusFresh,
    'status-canonical': statusCanonical,
    'same-origin': sameOrigin,
    'key-active': keyActive,
    'record-not-revoked': recordNotRevoked,
  };
  const snapshotValid = core.ok
    && statusFormat
    && sameOrigin
    && keyActive
    && recordNotRevoked;
  const online = fetchedUrl !== null && recordFetchedUrl !== null;
  const currentlyTrusted = online
    ? snapshotValid && statusFresh && statusCanonical === true
    : null;
  return {
    currentlyTrusted,
    snapshotValid,
    snapshotTrusted: snapshotValid,
    checks,
    reasons: Object.entries(checks)
      .filter(([, value]) => value === false)
      .map(([name]) => name),
  };
}

export const GOVP = {
  RECORD_DOMAIN,
  TYPECODE,
  deriveGovpId,
  deriveKeyId,
  evaluateStatus,
  loadJsonRecord,
  normalizeCanonical,
  normalizeFieldName,
  parseRecord,
  parseStatus,
  signingInput,
  trimFieldValue,
  verifyFields,
  verifyRecordSignature,
  verifyText,
};

export default GOVP;
