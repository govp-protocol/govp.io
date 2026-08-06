import { loadJsonRecord, verifyFields, verifyText } from './govp-engine.js?v=0.1.11-20260806.1';

export async function verifySource(source, options = {}) {
  const trimmed = source.trim();
  if (!trimmed.startsWith('{')) return verifyText(source, options);
  const loaded = loadJsonRecord(JSON.parse(trimmed));
  return verifyFields(loaded.fields, { ...options, bundle: loaded.bundle });
}
