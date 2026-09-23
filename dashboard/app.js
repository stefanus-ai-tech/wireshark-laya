const $ = id => document.getElementById(id);
const state = { predictions: [], metrics: null };
const labels = ['normal', 'port_scan', 'dns_activity', 'connection_burst', 'unknown'];
const fmt = n => n == null || !Number.isFinite(Number(n)) ? '—' : (Number(n) * 100).toFixed(1) + '%';
const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
function selected() { const engine = $('engine-select').value; return state.predictions.filter(row => engine === 'all' || row.engine === engine); }
function render() {
  const rows = selected(), engine = $('engine-select').value;
  const unique = new Set(rows.map(row => `${row.pcap}|${row.start_epoch}`));
  $('window-count').textContent = unique.size || '—';
  $('prediction-count').textContent = rows.length || '—';
  const metric = state.metrics && engine !== 'all' ? state.metrics[engine] : null;
  $('accuracy').textContent = metric ? fmt(metric.accuracy) : '—';
  $('f1').textContent = metric ? fmt(metric.macro_f1_present_classes) : '—';
  const counts = Object.fromEntries(labels.map(label => [label, 0]));
  rows.forEach(row => { if (row.prediction?.activity in counts) counts[row.prediction.activity]++; });
  $('chart-total').textContent = `${rows.length} hasil`;
  $('distribution').classList.toggle('empty', !rows.length);
  $('distribution').innerHTML = rows.length ? labels.map(label => `<div class="bar-row"><span>${esc(label.replaceAll('_',' '))}</span><div class="bar-track"><div class="bar-fill" style="width:${counts[label]/rows.length*100}%"></div></div><b>${counts[label]}</b></div>`).join('') : 'Muat predictions.jsonl untuk melihat grafik.';
  if (!metric) $('matrix').innerHTML = 'Pilih engine dan muat metrics.json untuk melihat matrix.';
  else {
    const matrix = metric.confusion_matrix || {};
    const max = Math.max(1, ...labels.flatMap(a => labels.map(b => Number(matrix[a]?.[b] || 0))));
    $('matrix').innerHTML = `<table class="matrix"><thead><tr><th>Aktual ↓ / Prediksi →</th>${labels.map(l => `<th>${esc(l.replaceAll('_',' '))}</th>`).join('')}</tr></thead><tbody>${labels.map(a => `<tr><th>${esc(a.replaceAll('_',' '))}</th>${labels.map(b => { const n = Number(matrix[a]?.[b] || 0); return `<td style="background:rgba(125,226,196,${.08 + n/max*.72})">${n}</td>`; }).join('')}</tr>`).join('')}</tbody></table>`;
  }
  const status = $('status-select').value, search = $('search').value.trim().toLowerCase();
  const filtered = rows.filter(row => {
    const known = labels.includes(row.label);
    const correct = row.prediction?.activity === row.label;
    if (status === 'wrong' && (!known || correct)) return false;
    if (status === 'correct' && (!known || !correct)) return false;
    return !search || `${row.pcap} ${row.label} ${row.prediction?.activity}`.toLowerCase().includes(search);
  });
  $('row-count').textContent = `${filtered.length} baris`;
  $('results-body').innerHTML = filtered.length ? filtered.slice(0,500).map(row => {
    const p = row.prediction || {}, f = row.features || {};
    const date = Number.isFinite(Number(row.start_epoch)) ? new Date(Number(row.start_epoch)*1000).toLocaleString('id-ID') : '—';
    const known = labels.includes(row.label), correct = p.activity === row.label;
    const outcome = known ? `<span class="tag ${correct?'good':'bad'}">${correct?'Benar':'Salah'}</span>` : '—';
    return `<tr><td>${esc(date)}</td><td title="${esc(row.pcap)}">${esc(String(row.pcap||'').split(/[\\/]/).pop())}</td><td>${esc(row.engine)}</td><td>${esc(row.label||'—')}</td><td><span class="tag">${esc(p.activity||'—')}</span></td><td>${fmt(p.confidence)}</td><td>${fmt(p.needs_review)}</td><td>${esc(f.packet_count??'—')}</td><td>${esc(f.unique_syn_dst_ports??'—')}</td><td>${outcome}</td></tr>`;
  }).join('') : '<tr><td colspan="10" class="empty-cell">Tidak ada hasil untuk filter ini.</td></tr>';
}
async function loadPredictions(file) {
  try {
    const rows = (await file.text()).split(/\r?\n/).filter(line => line.trim()).map((line, index) => {
      try { return JSON.parse(line); } catch { throw new Error(`JSON tidak valid di baris ${index+1}`); }
    });
    if (rows.some(row => !row.prediction || !row.engine)) throw new Error('Format predictions.jsonl tidak sesuai.');
    state.predictions = rows;
    const engines = [...new Set(rows.map(row => row.engine))].sort();
    $('engine-select').innerHTML = '<option value="all">Semua engine</option>' + engines.map(e => `<option value="${esc(e)}">${esc(e)}</option>`).join('');
    if (engines.length === 1) $('engine-select').value = engines[0];
    $('status').textContent = `${file.name} · ${rows.length} prediksi dimuat`;
    render();
  } catch (error) { $('status').textContent = `Gagal: ${error.message}`; }
}
async function loadMetrics(file) {
  try { const data = JSON.parse(await file.text()); if (!data || typeof data !== 'object') throw new Error('Format metrics tidak sesuai.'); state.metrics = data; $('status').textContent = `${file.name} · metrik dimuat`; render(); }
  catch (error) { $('status').textContent = `Gagal: ${error.message}`; }
}
$('predictions-file').addEventListener('change', event => { if (event.target.files[0]) loadPredictions(event.target.files[0]); });
$('metrics-file').addEventListener('change', event => { if (event.target.files[0]) loadMetrics(event.target.files[0]); });
['engine-select','status-select','search'].forEach(id => $(id).addEventListener(id === 'search' ? 'input' : 'change', render));
if (window.NETWATCH_DATA) {
  state.predictions = window.NETWATCH_DATA.predictions || [];
  state.metrics = window.NETWATCH_DATA.metrics || null;
  const engines = [...new Set(state.predictions.map(row => row.engine))].sort();
  $('engine-select').innerHTML = '<option value="all">Semua engine</option>' + engines.map(e => `<option value="${esc(e)}">${esc(e)}</option>`).join('');
  $('status').textContent = `${state.predictions.length} prediksi dari hasil lab dimuat`;
  render();
}
