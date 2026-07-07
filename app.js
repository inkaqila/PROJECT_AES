// ============================================================
//  app.js — UI Controller for AES-128 Simulator
// ============================================================

let currentMode = 'enc';

function setMode(m) {
  currentMode = m;
  document.getElementById('btn-enc').classList.toggle('active', m === 'enc');
  document.getElementById('btn-dec').classList.toggle('active', m === 'dec');
  document.getElementById('inp-label').textContent = m === 'enc' ? 'Plaintext' : 'Ciphertext';
}

function validate() {
  const ptEl = document.getElementById('inp-text');
  const kEl  = document.getElementById('inp-key');
  const pte  = document.getElementById('err-text');
  const ke   = document.getElementById('err-key');
  let ok = true;

  const pt = ptEl.value.trim();
  const k  = kEl.value.trim();

  // plaintext: 32 hex chars OR up to 16 text chars
  const isHex32 = /^[0-9a-fA-F\s]{32,35}$/.test(pt) && pt.replace(/\s/g,'').length === 32;
  const isText16 = pt.length > 0 && pt.length <= 16 && !/^[0-9a-fA-F]+$/.test(pt.replace(/\s/g,''));
  const ptOk = isHex32 || (pt.length > 0 && pt.length <= 16);

  if (!ptOk) {
    ptEl.classList.add('err'); pte.style.display = 'block'; ok = false;
  } else {
    ptEl.classList.remove('err'); pte.style.display = 'none';
  }

  const keyOk = /^[0-9a-fA-F\s]+$/.test(k) && k.replace(/\s/g,'').length === 32;
  if (!keyOk) {
    kEl.classList.add('err'); ke.style.display = 'block'; ok = false;
  } else {
    kEl.classList.remove('err'); ke.style.display = 'none';
  }

  return ok;
}

function doProcess() {
  if (!validate()) return;

  let ptRaw = document.getElementById('inp-text').value.trim();
  const kRaw = document.getElementById('inp-key').value.trim();

  // Auto-convert text to hex if needed
  let ptHex;
  if (ptRaw.replace(/\s/g,'').length === 32 && /^[0-9a-fA-F\s]+$/.test(ptRaw)) {
    ptHex = ptRaw.replace(/\s/g,'');
  } else {
    ptHex = AES128.textToHex(ptRaw);
  }
  const kHex = kRaw.replace(/\s/g,'');

  const trace = AES128.process(ptHex, kHex, currentMode);
  renderResult(trace, ptHex, kHex);

  document.getElementById('result-box').style.display = 'block';
  document.getElementById('sol-panel').style.display = 'none';
  document.getElementById('tog-btn').querySelector('span').textContent = 'Tampilkan Proses Perhitungan';
  document.getElementById('t-arrow').classList.remove('open');
  document.getElementById('result-box').scrollIntoView({behavior:'smooth', block:'start'});
}

function doReset() {
  document.getElementById('inp-text').value = '';
  document.getElementById('inp-key').value  = '';
  ['inp-text','inp-key'].forEach(id => document.getElementById(id).classList.remove('err'));
  ['err-text','err-key'].forEach(id => document.getElementById(id).style.display = 'none');
  document.getElementById('result-box').style.display = 'none';
}

function toggleSol(btn) {
  const panel = document.getElementById('sol-panel');
  const arrow = document.getElementById('t-arrow');
  const open  = panel.style.display === 'block';
  panel.style.display = open ? 'none' : 'block';
  arrow.classList.toggle('open', !open);
  btn.querySelector('span').textContent = open
    ? 'Tampilkan Proses Perhitungan'
    : 'Sembunyikan Proses Perhitungan';
}

function copyResult() {
  const val = document.getElementById('res-str').textContent;
  navigator.clipboard.writeText(val).then(() => showToast('Disalin!'));
}

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2000);
}

// ── RENDER RESULT ──────────────────────────────────────────
function renderResult(trace, ptHex, kHex) {
  const isEnc = trace.mode === 'enc';
  document.getElementById('res-lbl').textContent = isEnc ? 'Ciphertext (Hasil Enkripsi)' : 'Plaintext (Hasil Dekripsi)';

  const outHex = trace.output;
  // Show output as spaced pairs
  const spaced = outHex.match(/.{2}/g).join(' ');
  document.getElementById('res-str').textContent = spaced;

  // Hex cells
  const cells = outHex.match(/.{2}/g);
  document.getElementById('res-bytes').innerHTML = cells.map(c =>
    `<div class="rbyte">${c}</div>`
  ).join('');

  buildSolution(trace, ptHex, kHex);
}

// ── BUILD SOLUTION ─────────────────────────────────────────
function buildSolution(trace, ptHex, kHex) {
  const { roundKeys, keySteps, rounds, initial, mode } = trace;
  const isEnc = mode === 'enc';
  let h = '';

  // ── KEY EXPANSION ────────────────────────────────────────
  h += collapseSec('key-exp', 'Key Expansion (RK0 – RK10)', () => {
    let s = '';
    s += pill('Rumus: W[i] = g(W[i-1]) ⊕ W[i-4]  jika i kelipatan 4 | W[i] = W[i-1] ⊕ W[i-4]  selainnya');
    s += '<div class="rk-grid">';
    for (let r = 0; r <= 10; r++) {
      const bytes = stateToHexArray(roundKeys[r]);
      s += `<div class="rk-card">
        <div class="rk-title">RK${r}</div>
        ${stateHtml(roundKeys[r], 'sm')}
      </div>`;
    }
    s += '</div>';
    return s;
  });

  // ── INITIAL ROUND ────────────────────────────────────────
  h += collapseSec('init', 'Initial Round', () => {
    let s = '';
    s += pill(`Input dimasukkan ke State Matrix (column-major): ${ptHex.match(/.{2}/g).join(' ')}`);
    s += twoState('State Awal', initial.state, 'Setelah AddRoundKey (RK0)', initial.afterARK, 'accent', 'green');
    return s;
  });

  // ── ROUNDS ───────────────────────────────────────────────
  rounds.forEach((round, idx) => {
    if (isEnc) {
      const rNum = round.r;
      const isFinal = rNum === 10;
      h += collapseSec(`round-${rNum}`, `Round ${rNum}${isFinal ? ' — Final Round (tanpa MixColumns)' : ''}`, () => {
        let s = '';
        s += pill(`Menggunakan RK${rNum}: ${stateToHexArray(roundKeys[rNum]).join(' ')}`);
        s += twoState('SubBytes', round.afterSB, 'ShiftRows', round.afterSR, 'purple', 'orange');
        if (!isFinal) {
          s += twoState('MixColumns', round.afterMC, `AddRoundKey (RK${rNum})`, round.afterARK, 'green', 'accent');
        } else {
          s += '<div style="margin-top:12px">';
          s += labeledState(`AddRoundKey (RK10) = Ciphertext`, round.afterARK, 'accent');
          s += '</div>';
        }
        return s;
      });
    } else {
      const rNum = round.r;
      const isFinal = rNum === 0;
      h += collapseSec(`round-${rNum}`, `Dekripsi Round ${9 - idx + 1} (RK${rNum})`, () => {
        let s = '';
        s += pill(`Menggunakan RK${rNum}: ${stateToHexArray(roundKeys[rNum]).join(' ')}`);
        s += twoState('InvShiftRows', round.afterISR, 'InvSubBytes', round.afterISB, 'purple', 'orange');
        if (!isFinal) {
          s += twoState(`AddRoundKey (RK${rNum})`, round.afterARK, 'InvMixColumns', round.afterIMC, 'accent', 'green');
        } else {
          s += '<div style="margin-top:12px">';
          s += labeledState(`AddRoundKey (RK0) = Plaintext`, round.afterARK, 'green');
          s += '</div>';
        }
        return s;
      });
    }
  });

  document.getElementById('sol-panel').innerHTML = h;

  // Auto-open first section
  document.querySelectorAll('.csec-body').forEach((el, i) => {
    if (i === 0) el.style.display = 'block';
  });
  document.querySelectorAll('.csec-arrow').forEach((el, i) => {
    if (i === 0) el.classList.add('open');
  });
}

// ── HTML HELPERS ────────────────────────────────────────────
const COLORS = {
  accent: { text: '#4f46e5', bg: '#eef0ff', border: '#c7d2fe' },
  green:  { text: '#065f46', bg: '#d1fae5', border: '#6ee7b7' },
  purple: { text: '#6b21a8', bg: '#f3e8ff', border: '#d8b4fe' },
  orange: { text: '#92400e', bg: '#fef3c7', border: '#fcd34d' },
};

function stateHtml(state, size='md') {
  const sz = size === 'sm' ? 'st-sm' : 'st-md';
  let h = `<div class="state-matrix ${sz}">`;
  for (let r = 0; r < 4; r++) {
    h += '<div class="sm-row">';
    for (let c = 0; c < 4; c++) {
      h += `<div class="sm-cell">${AES128.h2(state[r][c])}</div>`;
    }
    h += '</div>';
  }
  h += '</div>';
  return h;
}

function labeledState(label, state, colorKey='accent') {
  const C = COLORS[colorKey];
  return `<div class="state-block" style="border-color:${C.border}">
    <div class="state-lbl" style="color:${C.text};background:${C.bg}">${label}</div>
    <div style="padding:10px">${stateHtml(state)}</div>
  </div>`;
}

function twoState(lbl1, s1, lbl2, s2, c1, c2) {
  return `<div class="two-states">
    ${labeledState(lbl1, s1, c1)}
    <div class="arrow-right">→</div>
    ${labeledState(lbl2, s2, c2)}
  </div>`;
}

function stateToHexArray(state) {
  const b = [];
  for (let c = 0; c < 4; c++)
    for (let r = 0; r < 4; r++)
      b.push(AES128.h2(state[r][c]));
  return b;
}

function pill(text) {
  return `<div class="info-pill">${text}</div>`;
}

function collapseSec(id, title, fn) {
  return `<div class="csec">
    <div class="csec-header" onclick="toggleSec('${id}')">
      <span>${title}</span>
      <span class="csec-arrow" id="arr-${id}">▼</span>
    </div>
    <div class="csec-body" id="body-${id}" style="display:none">${fn()}</div>
  </div>`;
}

function toggleSec(id) {
  const body = document.getElementById('body-'+id);
  const arr  = document.getElementById('arr-'+id);
  const open = body.style.display === 'block';
  body.style.display = open ? 'none' : 'block';
  arr.classList.toggle('open', !open);
}

// Key & input listeners
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('inp-key').addEventListener('input', function() {
    this.value = this.value.replace(/[^0-9a-fA-F\s]/g,'');
  });
  document.addEventListener('keydown', e => { if(e.key==='Enter') doProcess(); });
});
