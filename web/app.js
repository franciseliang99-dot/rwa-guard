'use strict';

/* Constants taken from contracts/src/GuardBits.sol. The masks are named there
   for a reason: a bit range would silently widen when a gate is added or
   withdrawn, and G7 was withdrawn on 2026-09-04 with its bit left reserved. */
const MASK256 = (1n << 256n) - 1n;
const VIOLATED_MASK = 0x17Fn;
const UNREADABLE_MASK = 0x17F0000n;
const RESERVED_MASK = 0x800080n;
const U_AGGREGATE = 1n << 255n;
const KNOWN_MASK = VIOLATED_MASK | UNREADABLE_MASK | U_AGGREGATE;
const UNREADABLE_SHIFT = 16n;

/* isSafeToTrade(address,(address,address,address,address,uint64)) */
const SELECTOR = '731479a9';

const GATES = [
  { bit: 0n, id: 'G0', name: 'Token identity' },
  { bit: 1n, id: 'G1', name: 'Global pause' },
  { bit: 2n, id: 'G2', name: 'Token pause' },
  { bit: 3n, id: 'G3', name: 'Counterparty block' },
  { bit: 4n, id: 'G4', name: 'Implementation drift' },
  { bit: 5n, id: 'G5', name: 'Ratio transition' },
  { bit: 6n, id: 'G6', name: 'Feed staleness' },
  { bit: 8n, id: 'G8', name: 'Feed coherence' }
];

const CHAINS = {
  'arbitrum-sepolia': {
    label: 'Arbitrum Sepolia',
    chainId: '0x66eee',
    decimal: 421614,
    rpc: 'https://sepolia-rollup.arbitrum.io/rpc',
    reach: 'On this chain only G0, G6 and G8 have anything to read; G1 through G5 read contracts that do not exist here, so their unreadable bits are the designed answer.'
  },
  'robinhood-testnet': {
    label: 'Robinhood Chain testnet',
    chainId: '0xb626',
    decimal: 46630,
    rpc: 'https://rpc.testnet.chain.robinhood.com',
    reach: 'This is the chain where the equity tokens and the control plane live, so all eight conditions have something to read.'
  }
};

function $(id) { return document.getElementById(id); }

/* ---------- encoding ---------- */

function addrHex(raw, field) {
  const s = String(raw === undefined || raw === null ? '' : raw).trim().toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(s)) {
    throw new Error(field + ': expected a 20-byte address, got "' + String(raw) + '"');
  }
  return s;
}

function addrWord(raw, field) {
  return addrHex(raw, field).slice(2).padStart(64, '0');
}

function uintWord(raw, field) {
  const s = String(raw === undefined || raw === null ? '' : raw).trim();
  if (!/^[0-9]+$/.test(s)) {
    throw new Error(field + ': expected a non-negative integer (0 is the strictest value, not "unset")');
  }
  const v = BigInt(s);
  if (v > (1n << 64n) - 1n) throw new Error(field + ': does not fit in uint64');
  return v.toString(16).padStart(64, '0');
}

function buildCalldata(f) {
  /* Ctx is a static tuple, so this signature carries no offset word:
     selector + 6 words = 196 bytes. */
  return '0x' + SELECTOR
    + addrWord(f.token, 'token')
    + addrWord(f.priceFeed, 'priceFeed')
    + addrWord(f.actor, 'actor')
    + addrWord(f.counterparty, 'counterparty')
    + addrWord(f.expectedImpl, 'expectedImpl')
    + uintWord(f.maxFeedAge, 'maxFeedAge');
}

/* ---------- transport ---------- */

async function rpc(url, method, params) {
  let res;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: method, params: params })
    });
  } catch (e) {
    return { ok: false, reason: 'transport', detail: String(e && e.message ? e.message : e) };
  }
  if (!res.ok) {
    return { ok: false, reason: 'http', detail: 'HTTP ' + res.status + ' ' + res.statusText };
  }
  let body;
  try { body = await res.json(); }
  catch (e) { return { ok: false, reason: 'parse', detail: 'the response was not JSON' }; }
  if (body && body.error) {
    return {
      ok: false,
      reason: 'rpc',
      detail: String(body.error.message || 'no message') + ' (code ' + String(body.error.code) + ')',
      data: typeof body.error.data === 'string' ? body.error.data : null
    };
  }
  if (!body || typeof body.result !== 'string') {
    return { ok: false, reason: 'shape', detail: 'the response carried no result field' };
  }
  return { ok: true, result: body.result };
}

/* ---------- the decoding contract ---------- */

function decodeReasonBits(bits, okRaw) {
  const out = { fatal: [], notes: [], rows: [] };

  /* 1. ok is defined as reasonBits == 0, and is never re-derived from a
        subset of the bits. If the payload disagrees with itself, that is a
        failed judgement, not a verdict. */
  const okDerived = (bits === 0n);
  if (okRaw !== null && okRaw !== okDerived) {
    out.fatal.push(
      'Clause 1: the returned ok flag says ' + String(okRaw) +
      ' while reasonBits says ' + String(okDerived) +
      '. ok is defined as reasonBits == 0; a payload that contradicts itself is not a verdict.'
    );
  }

  /* 3. bits 7 and 23 are permanently reserved. */
  const reserved = bits & RESERVED_MASK;
  if (reserved !== 0n) {
    out.fatal.push(
      'Clause 3: a permanently reserved bit is set (0x' + reserved.toString(16) +
      '). Bits 7 and 23 are reserved, so this payload was not produced by this version of the guard.'
    );
  }

  /* 2. anything outside KNOWN_MASK means a newer version produced this. */
  const unknown = bits & (MASK256 ^ KNOWN_MASK);
  if (unknown !== 0n) {
    out.fatal.push(
      'Clause 2: bits outside KNOWN_MASK are set (0x' + unknown.toString(16) +
      '). This payload comes from a newer version than this page understands. An older reader must block, never silently ignore it.'
    );
  }

  /* 4. bit 255 is an aggregate of the unreadable plane, not a ninth gate. */
  const planeSet = (bits & UNREADABLE_MASK) !== 0n;
  const aggregateSet = (bits & U_AGGREGATE) !== 0n;
  if (planeSet !== aggregateSet) {
    out.fatal.push(
      'Clause 4: bit 255 aggregates the unreadable plane, and the two disagree here (plane ' +
      (planeSet ? 'set' : 'clear') + ', aggregate ' + (aggregateSet ? 'set' : 'clear') + ').'
    );
  }

  /* 5. per gate, violated and that gate's own unreadable bit are exclusive. */
  for (let i = 0; i < GATES.length; i++) {
    const g = GATES[i];
    const violated = ((bits >> g.bit) & 1n) === 1n;
    const unreadable = ((bits >> (g.bit + UNREADABLE_SHIFT)) & 1n) === 1n;
    if (violated && unreadable) {
      out.fatal.push(
        'Clause 5: gate ' + g.id + ' reports both violated and unreadable. ' +
        'Those two are mutually exclusive for a single gate.'
      );
    }
    out.rows.push({ id: g.id, name: g.name, violated: violated, unreadable: unreadable });
  }

  /* 6. G0 changes what the other bits are about. */
  if ((bits & 1n) === 1n) {
    out.notes.push(
      'G0 is set. Clause 6: the bits for G1, G3 and G4 are true statements about that ' +
      'canonical control plane, not necessarily statements about this token\'s actual controller.'
    );
  }

  if (aggregateSet) {
    out.notes.push(
      'Bit 255 is set: at least one condition could not be read. ' +
      'An unreadable condition is not a satisfied condition, so this is a block.'
    );
  }

  out.status = out.fatal.length > 0 ? 'UNDETERMINED' : (bits === 0n ? 'PASS' : 'BLOCK');
  return out;
}

/* ---------- rendering ---------- */

const VERDICT_TEXT = {
  PASS: ['pass', 'PASS', 'All eight named conditions are absent and every one of them was readable.'],
  BLOCK: ['block', 'BLOCK', 'At least one named condition is present, or could not be read.'],
  UNDETERMINED: ['undet', 'UNDETERMINED', 'This page could not reach a judgement. Undetermined is treated as a block, never as a pass.']
};

function setVerdict(el, status, extra) {
  const spec = VERDICT_TEXT[status];
  el.className = 'verdict ' + spec[0];
  el.textContent = '';
  el.appendChild(document.createTextNode(spec[1]));
  const small = document.createElement('small');
  small.textContent = extra ? extra : spec[2];
  el.appendChild(small);
}

function renderNotes(el, fatal, notes) {
  el.textContent = '';
  for (let i = 0; i < fatal.length; i++) {
    const p = document.createElement('p');
    p.className = 'flag';
    p.textContent = fatal[i];
    el.appendChild(p);
  }
  for (let i = 0; i < notes.length; i++) {
    const p = document.createElement('p');
    p.className = 'muted';
    p.textContent = notes[i];
    el.appendChild(p);
  }
}

function renderRows(rows) {
  const body = document.querySelector('#bits tbody');
  body.textContent = '';
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    const tr = document.createElement('tr');
    const cells = [
      [r.id, ''],
      [r.name, ''],
      [r.violated ? 'yes' : '-', r.violated ? 'set' : 'clear'],
      [r.unreadable ? 'yes' : '-', r.unreadable ? 'unr' : 'clear']
    ];
    for (let c = 0; c < cells.length; c++) {
      const td = document.createElement('td');
      td.textContent = cells[c][0];
      if (cells[c][1]) td.className = cells[c][1];
      tr.appendChild(td);
    }
    body.appendChild(tr);
  }
}

/* ---------- the live check ---------- */

function readForm() {
  return {
    token: $('token').value,
    priceFeed: $('priceFeed').value,
    actor: $('actor').value,
    counterparty: $('counterparty').value,
    expectedImpl: $('expectedImpl').value,
    maxFeedAge: $('maxFeedAge').value
  };
}

async function run() {
  const chain = CHAINS[$('chain').value];
  const url = $('rpc').value.trim();
  const control = $('control');
  const verdict = $('verdict');

  $('results').hidden = false;
  renderNotes($('notes'), [], []);
  renderRows([]);
  $('raw').textContent = '';

  let guard, data;
  try {
    guard = addrHex($('guard').value, 'guard view contract');
    data = buildCalldata(readForm());
  } catch (e) {
    control.className = 'arm bad';
    control.textContent = 'Input rejected before any call was made: ' + e.message;
    setVerdict(verdict, 'UNDETERMINED', 'Nothing was asked of the chain, so nothing is known about this token.');
    $('calldata').textContent = '';
    return;
  }
  $('calldata').textContent =
    'calldata, ' + ((data.length - 2) / 2) + ' bytes (selector plus six static words, no offset word): ' + data;

  /* Control arm. A rejected endpoint makes every call fail identically, which
     reads exactly like "the contract has none of these functions". Keep a call
     that is known to succeed in the same run. */
  const cid = await rpc(url, 'eth_chainId', []);
  if (!cid.ok) {
    control.className = 'arm bad';
    control.textContent =
      'Control arm failed: eth_chainId was not answered (' + cid.reason + ': ' + cid.detail +
      '). Every call to this endpoint fails the same way, so a uniform wall of failures here is a transport symptom, not a contract fact.';
    setVerdict(verdict, 'UNDETERMINED', 'The endpoint could not answer a call that is known to succeed.');
    return;
  }

  const seen = cid.result.toLowerCase();
  const want = chain.chainId.toLowerCase();
  if (BigInt(seen) !== BigInt(want)) {
    control.className = 'arm bad';
    control.textContent =
      'Control arm answered, but this endpoint reports chain id ' + seen + ' (' + BigInt(seen).toString(10) +
      ') while ' + chain.label + ' is ' + want + ' (' + chain.decimal + '). You are pointed at a different chain than the one selected.';
  } else {
    control.className = 'arm good';
    control.textContent =
      'Control arm passed: eth_chainId answered ' + seen + ' (' + chain.decimal + '), which matches ' +
      chain.label + '. Failures below are about the contract, not the transport. ' + chain.reach;
  }

  const call = await rpc(url, 'eth_call', [{ to: guard, data: data }, 'latest']);
  if (!call.ok) {
    let extra = 'The call did not return a judgement (' + call.reason + ': ' + call.detail + ').';
    if (call.data === '0x' || call.data === null) {
      extra += ' An empty revert is a failed judgement, never reasonBits == 0.';
    } else if (typeof call.data === 'string') {
      extra += ' Revert data: ' + call.data + '. This page only decodes the two-word success return; a GuardBlocked payload comes from the integration library, not from this view.';
    }
    setVerdict(verdict, 'UNDETERMINED', extra);
    return;
  }

  const hex = call.result.startsWith('0x') ? call.result.slice(2) : call.result;
  $('raw').textContent = 'raw return: 0x' + hex;

  if (hex.length < 128) {
    setVerdict(verdict, 'UNDETERMINED',
      'The call returned ' + (hex.length / 2) + ' bytes; two 32-byte words are required. ' +
      'A short or empty return is a failed judgement, never reasonBits == 0.');
    return;
  }

  const okWord = BigInt('0x' + hex.slice(0, 64));
  const bits = BigInt('0x' + hex.slice(64, 128));
  let okRaw = null;
  const preface = [];
  if (okWord === 0n) { okRaw = false; }
  else if (okWord === 1n) { okRaw = true; }
  else {
    preface.push('The first word is neither 0 nor 1 (0x' + okWord.toString(16) +
      '), so it is not a valid bool. The verdict below rests on reasonBits alone.');
  }
  if (hex.length > 128) {
    preface.push('The return carried ' + ((hex.length - 128) / 2) + ' trailing bytes beyond the encoding; they are ignored.');
  }

  const res = decodeReasonBits(bits, okRaw);
  setVerdict(verdict, res.status, res.status === 'PASS'
    ? 'reasonBits is exactly 0. All eight named conditions are absent and every one was readable.'
    : undefined);
  renderNotes($('notes'), res.fatal, preface.concat(res.notes));
  renderRows(res.rows);
}

/* ---------- the offline decoder ---------- */

function runManual() {
  const out = $('manualOut');
  out.textContent = '';
  const raw = $('manualBits').value.trim();
  let bits;
  try {
    if (raw === '') throw new Error('nothing to decode');
    bits = /^0x/i.test(raw) ? BigInt(raw) : BigInt(raw);
    if (bits < 0n || bits > MASK256) throw new Error('value does not fit in uint256');
  } catch (e) {
    const p = document.createElement('p');
    p.className = 'flag';
    p.textContent = 'Could not read that value: ' + (e && e.message ? e.message : String(e));
    out.appendChild(p);
    return;
  }

  const res = decodeReasonBits(bits, null);
  const v = document.createElement('div');
  setVerdict(v, res.status, res.status === 'PASS'
    ? 'reasonBits is exactly 0.'
    : undefined);
  out.appendChild(v);

  const notes = document.createElement('div');
  renderNotes(notes, res.fatal, res.notes);
  out.appendChild(notes);

  const table = document.createElement('table');
  const head = document.createElement('thead');
  head.innerHTML = '<tr><th>Gate</th><th>Condition</th><th>Violated</th><th>Unreadable</th></tr>';
  table.appendChild(head);
  const body = document.createElement('tbody');
  table.appendChild(body);
  out.appendChild(table);
  for (let i = 0; i < res.rows.length; i++) {
    const r = res.rows[i];
    const tr = document.createElement('tr');
    const cells = [
      [r.id, ''],
      [r.name, ''],
      [r.violated ? 'yes' : '-', r.violated ? 'set' : 'clear'],
      [r.unreadable ? 'yes' : '-', r.unreadable ? 'unr' : 'clear']
    ];
    for (let c = 0; c < cells.length; c++) {
      const td = document.createElement('td');
      td.textContent = cells[c][0];
      if (cells[c][1]) td.className = cells[c][1];
      tr.appendChild(td);
    }
    body.appendChild(tr);
  }

  const hexline = document.createElement('p');
  hexline.className = 'mono muted';
  hexline.textContent = 'reasonBits = 0x' + bits.toString(16) + ' (' + bits.toString(10) + ')';
  out.appendChild(hexline);
}

/* ---------- wiring ---------- */

function syncChain() {
  const chain = CHAINS[$('chain').value];
  $('rpc').value = chain.rpc;
}

document.addEventListener('DOMContentLoaded', function () {
  syncChain();
  $('chain').addEventListener('change', syncChain);
  $('run').addEventListener('click', function () { run(); });
  $('runManual').addEventListener('click', runManual);
});
