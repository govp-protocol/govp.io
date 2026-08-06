import { verifySource } from './verify-source.js?v=0.1.11-20260806.1';

const MAX_RECORD_BYTES = 1024 * 1024;
const MAX_ASSET_BYTES = 16 * 1024 * 1024;
const encoder = new TextEncoder();

const form = document.querySelector('#verify-form');
const recordInput = document.querySelector('#record');
const canonicalInput = document.querySelector('#canonical-url');
const assetInput = document.querySelector('#asset');
const result = document.querySelector('#verification-result');
const summary = document.querySelector('#result-summary');
const checks = document.querySelector('#result-checks');
const warningBox = document.querySelector('#result-warnings');

function addCheck(name, value) {
  const term = document.createElement('dt');
  term.textContent = name;
  const detail = document.createElement('dd');
  const passed = value === true;
  const omitted = value === null || value === undefined;
  detail.className = passed ? 'check-pass' : omitted ? 'muted' : 'check-fail';
  detail.textContent = passed ? 'Pass' : omitted ? 'Not requested' : 'Fail';
  checks.append(term, detail);
}

function renderError(error) {
  result.hidden = false;
  summary.className = 'lead check-fail';
  summary.textContent = error instanceof Error ? error.message : String(error);
  checks.replaceChildren();
  warningBox.replaceChildren();
}

function renderReport(report) {
  result.hidden = false;
  checks.replaceChildren();
  warningBox.replaceChildren();
  summary.className = report.ok ? 'lead check-pass' : 'lead check-fail';
  summary.textContent = report.ok ? 'The requested GOVP checks passed.' : 'One or more requested GOVP checks failed.';
  for (const key of ['format', 'signature', 'govp-id', 'canonical', 'asset']) addCheck(key, report.checks[key]);
  if (report.warnings?.length) {
    const list = document.createElement('ul');
    list.className = 'warning-list';
    for (const warning of report.warnings) {
      const item = document.createElement('li');
      item.textContent = warning;
      list.append(item);
    }
    warningBox.append(list);
  }
}

async function selectedAsset() {
  const file = assetInput.files?.[0];
  if (!file) return null;
  if (file.size > MAX_ASSET_BYTES) throw new Error('The selected asset exceeds the 16 MiB browser limit. Use the CLI for larger files.');
  return new Uint8Array(await file.arrayBuffer());
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const source = recordInput.value;
    if (encoder.encode(source).byteLength > MAX_RECORD_BYTES) throw new Error('The record exceeds the 1 MiB browser limit.');
    const assetBytes = await selectedAsset();
    const fetchedUrl = canonicalInput.value.trim() || null;
    const report = await verifySource(source, { assetBytes, fetchedUrl });
    renderReport(report);
  } catch (error) {
    renderError(error);
  }
});

form.addEventListener('reset', () => {
  result.hidden = true;
  checks.replaceChildren();
  warningBox.replaceChildren();
});

document.querySelector('#load-example').addEventListener('click', async () => {
  try {
    const response = await fetch('/govp/examples/manufacturing-record.govp.txt');
    if (!response.ok) throw new Error('The synthetic example could not be loaded.');
    recordInput.value = await response.text();
    canonicalInput.value = '';
    result.hidden = true;
  } catch (error) {
    renderError(error);
  }
});
