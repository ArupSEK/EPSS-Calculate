/* =========================
   EPSS Lookup - FINAL (no JSON)
   ========================= */

const EPSS_BASE = "https://api.first.org/data/v1/epss";
const MAX_BATCH_CVES = 100;
const MAX_QUERY_CHARS = 1900;

let lastSearchRows = []; // array of {cve, epss, percentile, date}
let sortState = { key: "cve", dir: "asc" };

let chart = null;
let uploadedWorkbook = null;
let uploadedSheetName = "";
let uploadedAoa = null;
let uploadedFileName = "";
let uploadedIsCsv = false;
let lastGeneratedAoa = null;
let originalUploadedAoa = null;
let previewReorderHandler = null;
let generatedReorderHandler = null;
let lastGeneratedSheetName = "";
let lastBaseAoa = null;
let lastComputedExtras = null;
let lastEpssMap = null;

const $ = (id) => document.getElementById(id);

function toast(msg, type="info"){
  const el = $("toast");
  if(!el) return;
  el.textContent = msg;
  el.classList.remove("hidden");
  el.style.borderColor = type==="error" ? "rgba(255,59,59,.8)" : "rgba(255,255,255,.9)";
  setTimeout(()=> el.classList.add("hidden"), 2800);
}

function setStatus(el, msg){ if(el) el.textContent = msg || ""; }
function setProgress(pct){
  const bar = $("progressBar");
  if(bar) bar.style.width = `${Math.max(0, Math.min(100, pct))}%`;
}

function setButtonLoading(btn, loading){
  if(!btn) return;
  btn.classList.toggle("isLoading", !!loading);
  btn.disabled = !!loading;
}

function normalizeCve(raw){
  if(!raw) return "";
  const s = String(raw).trim().toUpperCase();
  const m = s.match(/CVE[\s_\-]*([0-9]{4})[\s_\-]*([0-9]{4,7})/);
  if(!m) return "";
  return `CVE-${m[1]}-${m[2]}`;
}

function extractCVEs(text){
  if(!text) return [];
  const rawMatches = String(text).match(/CVE[\s_\-]*\d{4}[\s_\-]*\d{4,7}/gi);
  if(!rawMatches) return [];
  const normalized = rawMatches.map(normalizeCve).filter(Boolean);
  return [...new Set(normalized)];
}

function buildBatches(cves){
  const unique = [...new Set(cves.map(c => c.toUpperCase()))];
  const batches = [];
  let current = [];

  const wouldExceedChars = (arr, next) => ([...arr, next].join(",").length > MAX_QUERY_CHARS);

  for(const cve of unique){
    if(current.length >= MAX_BATCH_CVES || wouldExceedChars(current, cve)){
      if(current.length) batches.push(current);
      current = [];
    }
    current.push(cve);
  }
  if(current.length) batches.push(current);
  return batches;
}

async function fetchEpssMapForCves(cves, onProgress){
  const batches = buildBatches(cves);
  const out = new Map();

  for(let i=0; i<batches.length; i++){
    const batch = batches[i];
    const url = `${EPSS_BASE}?cve=${encodeURIComponent(batch.join(","))}`;

    const res = await fetch(url);
    if(!res.ok) throw new Error(`EPSS API error: HTTP ${res.status}`);

    const json = await res.json();
    const data = json?.data || [];
    for(const row of data){
      if(row?.cve) out.set(String(row.cve).toUpperCase(), row);
    }
    if(onProgress) onProgress(i+1, batches.length);
  }
  return out;
}

function fmtNum(x){
  const n = Number(x);
  if(!Number.isFinite(n)) return "";
  return n.toFixed(9).replace(/0+$/,"").replace(/\.$/,"");
}

function epssBadgeClass(epss){
  const n = Number(epss);
  if(!Number.isFinite(n)) return "badge--green";
  if(n >= 0.7) return "badge--red";
  if(n >= 0.3) return "badge--orange";
  if(n >= 0.1) return "badge--yellow";
  return "badge--green";
}

/* =========================
   TABLE RENDER (with toggles + sorting)
   ========================= */
function getVisibleColumns(){
  return {
    epss: $("colEpss")?.checked ?? true,
    pct: $("colPercentile")?.checked ?? true,
    date: $("colDate")?.checked ?? true
  };
}

function sortRows(rows){
  const {key, dir} = sortState;
  const mult = dir === "asc" ? 1 : -1;

  const toNum = (v) => {
    const n = Number(v);
    return Number.isFinite(n) ? n : -Infinity;
  };

  const sorted = [...rows].sort((a,b)=>{
    if(key === "cve"){
      return a.cve.localeCompare(b.cve) * mult;
    }
    if(key === "epss"){
      return (toNum(a.epss) - toNum(b.epss)) * mult;
    }
    if(key === "percentile"){
      return (toNum(a.percentile) - toNum(b.percentile)) * mult;
    }
    if(key === "date"){
      return String(a.date || "").localeCompare(String(b.date || "")) * mult;
    }
    return 0;
  });

  return sorted;
}

function setSort(key){
  if(sortState.key === key){
    sortState.dir = sortState.dir === "asc" ? "desc" : "asc";
  } else {
    sortState.key = key;
    sortState.dir = "asc";
  }
  renderResultsTable();
}

function renderResultsTable(){
  const table = $("resultsTable");
  if(!table) return;

  const thead = table.querySelector("thead");
  const tbody = table.querySelector("tbody");
  if(!thead || !tbody) return;

  const cols = getVisibleColumns();

  thead.innerHTML = "";
  tbody.innerHTML = "";

  const headers = [{k:"cve", t:"CVE"}];
  if(cols.epss) headers.push({k:"epss", t:"EPSS"});
  if(cols.pct) headers.push({k:"percentile", t:"Percentile"});
  if(cols.date) headers.push({k:"date", t:"Date"});

  const trh = document.createElement("tr");
  headers.forEach(h=>{
    const th = document.createElement("th");
    th.textContent = h.t;
    const hint = document.createElement("span");
    hint.className = "sortHint";
    hint.textContent = sortState.key === h.k ? (sortState.dir === "asc" ? "▲" : "▼") : "↕";
    th.appendChild(hint);
    th.addEventListener("click", ()=> setSort(h.k));
    trh.appendChild(th);
  });
  thead.appendChild(trh);

  const rows = sortRows(lastSearchRows);

  if(!rows.length){
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = headers.length;
    td.textContent = "No results yet.";
    td.style.opacity = "0.75";
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  for(const r of rows){
    const tr = document.createElement("tr");

    const tdC = document.createElement("td");
    tdC.textContent = r.cve;
    tr.appendChild(tdC);

    if(cols.epss){
      const td = document.createElement("td");
      const badge = document.createElement("span");
      badge.className = `badge ${epssBadgeClass(r.epss)}`;
      badge.textContent = r.epss || "";
      td.appendChild(badge);
      tr.appendChild(td);
    }

    if(cols.pct){
      const td = document.createElement("td");
      td.textContent = r.percentile || "";
      tr.appendChild(td);
    }

    if(cols.date){
      const td = document.createElement("td");
      td.textContent = r.date || "";
      tr.appendChild(td);
    }

    tbody.appendChild(tr);
  }
}

/* =========================
   Copy / Download
   ========================= */
function rowsToTSV(rows){
  const cols = getVisibleColumns();
  const headers = ["CVE"];
  if(cols.epss) headers.push("EPSS");
  if(cols.pct) headers.push("Percentile");
  if(cols.date) headers.push("Date");

  const lines = [headers.join("\t")];
  for(const r of sortRows(rows)){
    const line = [r.cve];
    if(cols.epss) line.push(r.epss || "");
    if(cols.pct) line.push(r.percentile || "");
    if(cols.date) line.push(r.date || "");
    lines.push(line.join("\t"));
  }
  return lines.join("\n");
}

function rowsToCSV(rows){
  const cols = getVisibleColumns();
  const headers = ["CVE"];
  if(cols.epss) headers.push("EPSS");
  if(cols.pct) headers.push("Percentile");
  if(cols.date) headers.push("Date");

  const esc = (s)=> `"${String(s ?? "").replaceAll('"','""')}"`;

  const lines = [headers.map(esc).join(",")];
  for(const r of sortRows(rows)){
    const line = [r.cve];
    if(cols.epss) line.push(r.epss || "");
    if(cols.pct) line.push(r.percentile || "");
    if(cols.date) line.push(r.date || "");
    lines.push(line.map(esc).join(","));
  }
  return lines.join("\n");
}

function downloadTextFile(filename, content, mime){
  const blob = new Blob([content], {type: mime});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/* =========================
   Summary chips
   ========================= */
function updateSummary(rows){
  const wrap = $("searchSummary");
  if(!wrap) return;

  if(!rows.length){
    wrap.style.display = "none";
    return;
  }
  wrap.style.display = "flex";

  const total = rows.length;
  const found = rows.filter(r => r.epss !== "").length;
  const nums = rows.map(r => Number(r.epss)).filter(n => Number.isFinite(n));
  const max = nums.length ? Math.max(...nums) : 0;
  const avg = nums.length ? (nums.reduce((a,b)=>a+b,0)/nums.length) : 0;

  $("sumFound").textContent = `Found: ${found}/${total}`;
  $("sumMax").textContent = `Max EPSS: ${max.toFixed(3)}`;
  $("sumAvg").textContent = `Avg EPSS: ${avg.toFixed(3)}`;
}

/* =========================
   Chart (Excel)
   ========================= */
function renderChart(epssValues, topList){
  const canvas = $("epssChart");
  if(!canvas || !window.Chart) return;

  const vals = epssValues.map(v => Number(v)).filter(v => Number.isFinite(v));
  const stats = {
    count: vals.length,
    min: vals.length ? Math.min(...vals) : 0,
    max: vals.length ? Math.max(...vals) : 0,
    avg: vals.length ? (vals.reduce((a,b)=>a+b,0)/vals.length) : 0,
    median: 0
  };
  if(vals.length){
    const sorted = [...vals].sort((a,b)=>a-b);
    const mid = Math.floor(sorted.length / 2);
    stats.median = sorted.length % 2 ? sorted[mid] : (sorted[mid-1] + sorted[mid]) / 2;
  }

  const buckets = [
    { label: "0–0.01", min: 0, max: 0.01 },
    { label: "0.01–0.05", min: 0.01, max: 0.05 },
    { label: "0.05–0.1", min: 0.05, max: 0.1 },
    { label: "0.1–0.3", min: 0.1, max: 0.3 },
    { label: "0.3–0.6", min: 0.3, max: 0.6 },
    { label: "0.6–1.0", min: 0.6, max: 1.0 },
  ];
  const counts = buckets.map(b => vals.filter(x => x >= b.min && x < b.max).length);

  if(chart) chart.destroy();
  const ctx = canvas.getContext("2d");
  const gradient = ctx.createLinearGradient(0, 0, 0, canvas.height || 160);
  gradient.addColorStop(0, "rgba(138,91,255,.85)");
  gradient.addColorStop(1, "rgba(45,255,179,.55)");

  chart = new Chart(canvas, {
    type: "bar",
    data: { labels: buckets.map(b => b.label), datasets: [{ label: "Count", data: counts, backgroundColor: gradient, borderRadius: 6 }] },
    options: {
      responsive: true,
      plugins: {
        legend: { display:false },
        tooltip: { enabled: true }
      },
      scales: {
        x: { grid: { display:false } },
        y: { grid: { color: "rgba(0,0,0,.08)" }, ticks: { precision: 0 } }
      }
    }
  });

  $("chartCount").textContent = String(stats.count);
  $("chartMin").textContent = stats.count ? stats.min.toFixed(3) : "0";
  $("chartMax").textContent = stats.count ? stats.max.toFixed(3) : "0";
  $("chartAvg").textContent = stats.count ? stats.avg.toFixed(3) : "0";
  $("chartMedian").textContent = stats.count ? stats.median.toFixed(3) : "0";

  const topWrap = $("chartTopList");
  if(topWrap){
    if(topList && topList.length){
      topWrap.textContent = topList.map(t => `${t.cve} (${fmtNum(t.epss)})`).join(" • ");
    } else {
      topWrap.textContent = "—";
    }
  }
}

/* =========================
   Excel processing
   ========================= */
function aoaFromSheet(sheet){
  return XLSX.utils.sheet_to_json(sheet, { header: 1, raw: false, defval: "" });
}
function sheetFromAOA(aoa){
  return XLSX.utils.aoa_to_sheet(aoa);
}

function rowCVEsFromColumn(row, columnIndex){
  const cell = row?.[columnIndex];
  return extractCVEs(cell);
}

function getFileExtension(filename){
  return String(filename || "").toLowerCase().split(".").pop();
}

function isSupportedSpreadsheet(filename){
  const ext = getFileExtension(filename);
  return ["xlsx", "xls", "xlsm", "xlsb", "csv"].includes(ext);
}

let xlsxLoadPromise = null;

function loadScript(src){
  return new Promise((resolve, reject)=>{
    const script = document.createElement("script");
    script.src = src;
    script.async = true;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error(`Failed to load ${src}`));
    document.head.appendChild(script);
  });
}

async function ensureXlsxLoaded(){
  if(window.XLSX) return true;
  if(!xlsxLoadPromise){
    const sources = [
      "./vendor/xlsx.full.min.js",
      "https://cdn.sheetjs.com/xlsx-0/frontend/xlsx.full.min.js",
      "https://cdn.jsdelivr.net/npm/xlsx@0.20.1/dist/xlsx.full.min.js",
      "https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.20.1/xlsx.full.min.js"
    ];
    xlsxLoadPromise = (async ()=>{
      for(const src of sources){
        try{
          await loadScript(src);
          if(window.XLSX) return true;
        }catch{
          // try next source
        }
      }
      return false;
    })();
  }
  return xlsxLoadPromise;
}

function parseCsvToAoa(text){
  const rows = [];
  let row = [];
  let cell = "";
  let inQuotes = false;
  let i = 0;

  const pushCell = () => {
    row.push(cell);
    cell = "";
  };

  const pushRow = () => {
    rows.push(row);
    row = [];
  };

  while(i < text.length){
    const ch = text[i];
    if(inQuotes){
      if(ch === '"'){
        const next = text[i + 1];
        if(next === '"'){
          cell += '"';
          i += 2;
          continue;
        }
        inQuotes = false;
        i += 1;
        continue;
      }
      cell += ch;
      i += 1;
      continue;
    }

    if(ch === '"'){
      inQuotes = true;
      i += 1;
      continue;
    }

    if(ch === ","){
      pushCell();
      i += 1;
      continue;
    }

    if(ch === "\r"){
      if(text[i + 1] === "\n") i += 1;
      pushCell();
      pushRow();
      i += 1;
      continue;
    }

    if(ch === "\n"){
      pushCell();
      pushRow();
      i += 1;
      continue;
    }

    cell += ch;
    i += 1;
  }

  pushCell();
  if(row.length || rows.length === 0) pushRow();
  return rows;
}

function aoaToCsv(aoa){
  const esc = (s)=> `"${String(s ?? "").replaceAll('"','""')}"`;
  return aoa.map(row => row.map(esc).join(",")).join("\n");
}

function formatTimestampForFilename(date){
  const pad = (n)=> String(n).padStart(2, "0");
  const y = date.getFullYear();
  const m = pad(date.getMonth() + 1);
  const d = pad(date.getDate());
  const hh = pad(date.getHours());
  const mm = pad(date.getMinutes());
  const ss = pad(date.getSeconds());
  return `${y}${m}${d}_${hh}${mm}${ss}`;
}

function buildGeneratedAoa(baseAoa, extras, exportCols){
  if(!baseAoa || !baseAoa.length) return [];
  const out = baseAoa.map(row => [...row]);
  const header = out[0] || [];
  if(exportCols.epss) header.push("EPSS Score");
  if(exportCols.pct) header.push("EPSS Percentile");
  if(exportCols.date) header.push("EPSS Date");
  if(exportCols.found) header.push("EPSS CVEs Found");
  out[0] = header;

  for(let r = 1; r < out.length; r++){
    const row = out[r] || [];
    const extra = extras?.[r] || { epss:"", pct:"", date:"", found:"" };
    if(exportCols.epss) row.push(extra.epss);
    if(exportCols.pct) row.push(extra.pct);
    if(exportCols.date) row.push(extra.date);
    if(exportCols.found) row.push(extra.found);
    out[r] = row;
  }
  return out;
}

function computeExtrasFromMap(baseAoa, selectedColumnIndex, epssMap, multiMode){
  const extras = [];
  const epssValuesForChart = [];

  for(let r=1; r<baseAoa.length; r++){
    const row = baseAoa[r] || [];
    const cves = rowCVEsFromColumn(row, selectedColumnIndex);

    let epssOut = "";
    let pctOut = "";
    let dateOut = "";

    if(multiMode === "comma"){
      const epssList = [];
      const pctList = [];
      const dateList = [];
      let hasHit = false;

      for(const cve of cves){
        const hit = epssMap?.get(cve.toUpperCase());
        if(!hit){
          epssList.push("");
          pctList.push("");
          dateList.push("");
          continue;
        }
        hasHit = true;
        epssList.push(fmtNum(hit.epss));
        pctList.push(fmtNum(hit.percentile));
        dateList.push(hit.date || "");
      }

      epssOut = hasHit ? epssList.join(", ") : "";
      pctOut = hasHit ? pctList.join(", ") : "";
      dateOut = hasHit ? dateList.join(", ") : "";
    } else {
      let best = { epss: -1, percentile: "", date: "" };
      for(const cve of cves){
        const hit = epssMap?.get(cve.toUpperCase());
        if(!hit) continue;
        const e = Number(hit.epss);
        if(Number.isFinite(e) && e > best.epss){
          best = {
            epss: e,
            percentile: fmtNum(hit.percentile),
            date: hit.date || ""
          };
        }
      }
      epssOut = best.epss >= 0 ? fmtNum(best.epss) : "";
      pctOut  = best.epss >= 0 ? best.percentile : "";
      dateOut = best.epss >= 0 ? best.date : "";
    }

    const foundList = cves.join(", ");
    extras[r] = { epss: epssOut, pct: pctOut, date: dateOut, found: foundList };

    if(epssOut){
      if(multiMode === "max"){
        epssValuesForChart.push(Number(epssOut));
      } else {
        epssOut.split(",").forEach(value => {
          const num = Number(value.trim());
          if(Number.isFinite(num)) epssValuesForChart.push(num);
        });
      }
    }
  }

  return { extras, epssValuesForChart };
}

function getSelectedColumnIndex(){
  const select = $("excelColumnSelect");
  if(!select) return 0;
  const val = Number(select.value);
  return Number.isFinite(val) ? val : 0;
}

function getMultiEpssMode(){
  const selected = document.querySelector("input[name='multiEpssMode']:checked");
  return selected?.value || "comma";
}

function getExcelExportColumns(){
  return {
    epss: $("excelColEpss")?.checked ?? true,
    pct: $("excelColPercentile")?.checked ?? true,
    date: $("excelColDate")?.checked ?? true,
    found: $("excelColFound")?.checked ?? true
  };
}

function detectDefaultColumn(header){
  const idx = header.findIndex(h => String(h).toLowerCase().includes("cve"));
  return idx >= 0 ? idx : 0;
}

function buildColumnOptions(header){
  const select = $("excelColumnSelect");
  if(!select) return;
  select.innerHTML = "";

  header.forEach((label, index) => {
    const option = document.createElement("option");
    option.value = String(index);
    const name = String(label || "").trim();
    option.textContent = name ? `${name} (Column ${index + 1})` : `Column ${index + 1}`;
    select.appendChild(option);
  });
}

function reorderAoaColumns(aoa, fromIdx, toIdx){
  if(!aoa || fromIdx === toIdx) return aoa;
  return aoa.map(row => {
    const next = [...row];
    const [moved] = next.splice(fromIdx, 1);
    next.splice(toIdx, 0, moved);
    return next;
  });
}

function bindScrollControl(wrap, slider){
  if(!wrap || !slider) return;
  if(slider.dataset.bound === "1") return;
  slider.dataset.bound = "1";

  slider.addEventListener("input", ()=>{
    wrap.scrollLeft = Number(slider.value) || 0;
  });

  wrap.addEventListener("scroll", ()=>{
    slider.value = String(wrap.scrollLeft || 0);
  });
}

function syncScrollControl(wrap, slider){
  if(!wrap || !slider) return;
  const max = Math.max(0, wrap.scrollWidth - wrap.clientWidth);
  slider.max = String(max);
  slider.value = String(Math.min(max, wrap.scrollLeft || 0));
  slider.disabled = max === 0;
}

const PREVIEW_MAX_ROWS = 12;
const GENERATED_MAX_ROWS = 300;
const GENERATED_MAX_COLS = 300;

function normalizeAoaToRange(aoa, ws){
  if(!ws || !ws["!ref"]) return aoa;
  const range = XLSX.utils.decode_range(ws["!ref"]);
  const rows = range.e.r + 1;
  const cols = range.e.c + 1;
  const out = [];

  for(let r = 0; r < rows; r++){
    const src = aoa[r] || [];
    const next = new Array(cols);
    for(let c = 0; c < cols; c++){
      next[c] = src[c] ?? "";
    }
    out.push(next);
  }
  return out;
}

function renderPreviewTable(tableId, statusId, aoa, selectedColumnIndex, enableDrag, onReorder){
  const table = $(tableId);
  const status = statusId ? $(statusId) : null;
  if(!table) return;
  const thead = table.querySelector("thead");
  const tbody = table.querySelector("tbody");
  if(!thead || !tbody) return;

  thead.innerHTML = "";
  tbody.innerHTML = "";

  if(!aoa || !aoa.length){
    if(status) status.textContent = "No preview available.";
    return;
  }

  const header = aoa[0] || [];
  let maxCols = Math.max(...aoa.map(r => (r ? r.length : 0)), header.length);
  if(tableId === "excelGeneratedTable"){
    maxCols = Math.min(maxCols, GENERATED_MAX_COLS);
  }
  const rowLimit = tableId === "excelGeneratedTable" ? GENERATED_MAX_ROWS : PREVIEW_MAX_ROWS;
  const maxRows = Math.min(aoa.length, rowLimit + 1);

  const headerRow = document.createElement("tr");
  for(let idx = 0; idx < maxCols; idx++){
    const cell = header[idx];
    const th = document.createElement("th");
    th.textContent = cell || `Column ${idx + 1}`;
    if(idx === selectedColumnIndex && tableId === "excelPreviewTable") th.classList.add("isSelected");
    if(enableDrag && onReorder){
      th.draggable = true;
      th.dataset.colIndex = String(idx);
      th.addEventListener("dragstart", (e)=>{
        e.dataTransfer.setData("text/plain", String(idx));
      });
      th.addEventListener("dragover", (e)=> e.preventDefault());
      th.addEventListener("drop", (e)=>{
        e.preventDefault();
        const from = Number(e.dataTransfer.getData("text/plain"));
        const to = Number(th.dataset.colIndex);
        if(!Number.isFinite(from) || !Number.isFinite(to) || from === to) return;

        onReorder(from, to);
      });
    }
    headerRow.appendChild(th);
  }
  thead.appendChild(headerRow);

  for(let r = 1; r < maxRows; r++){
    const row = aoa[r] || [];
    const tr = document.createElement("tr");
    for(let idx = 0; idx < maxCols; idx++){
      const td = document.createElement("td");
      td.textContent = row[idx] ?? "";
      if(idx === selectedColumnIndex && tableId === "excelPreviewTable") td.classList.add("isSelected");
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }

  if(status){
    if(tableId === "excelGeneratedTable"){
      status.textContent = `Previewing ${maxRows - 1} generated row(s), ${maxCols} columns (max ${GENERATED_MAX_ROWS} rows / ${GENERATED_MAX_COLS} cols).`;
    } else {
      status.textContent = `Previewing ${maxRows - 1} row(s), ${maxCols} columns from "${uploadedSheetName}".`;
    }
  }

  const wrap = table.closest(".tableWrap--preview");
  const slider = tableId === "excelPreviewTable" ? $("previewScroll") : $("generatedScroll");
  bindScrollControl(wrap, slider);
  syncScrollControl(wrap, slider);
}

async function loadWorkbookFromFile(file){
  const ext = getFileExtension(file.name);
  if(ext === "csv"){
    const text = await file.text();
    const aoa = parseCsvToAoa(text);
    if(aoa.length === 0) throw new Error("CSV file is empty.");
    return { wb: null, sheetName: "CSV", aoa, isCsv: true };
  }

  const hasXlsx = await ensureXlsxLoaded();
  if(!hasXlsx){
    throw new Error("Excel engine failed to load. Your browser blocked the SheetJS CDN. Use CSV upload or host ./vendor/xlsx.full.min.js.");
  }

  const data = await file.arrayBuffer();
  const wb = XLSX.read(data, { type: "array" });

  const sheetName = wb.SheetNames[0];
  const ws = wb.Sheets[sheetName];
  let aoa = aoaFromSheet(ws);
  aoa = normalizeAoaToRange(aoa, ws);
  if(aoa.length === 0) throw new Error("Excel sheet is empty.");

  return { wb, sheetName, aoa, isCsv: false };
}

document.addEventListener("DOMContentLoaded", ()=>{
  // Tabs
  document.querySelectorAll(".tab").forEach(btn=>{
    btn.addEventListener("click", ()=>{
      document.querySelectorAll(".tab").forEach(b=> b.classList.remove("tab--active"));
      btn.classList.add("tab--active");
      const tab = btn.dataset.tab;
      $("tab-search").classList.toggle("hidden", tab !== "search");
      $("tab-excel").classList.toggle("hidden", tab !== "excel");
    });
  });

  // Slider
  let slideIndex = 0;
  setInterval(()=>{
    const slides = document.querySelectorAll(".slider__slide");
    const dots = document.querySelectorAll(".dot");
    slides.forEach(s=> s.classList.remove("slider__slide--active"));
    dots.forEach(d=> d.classList.remove("dot--active"));
    slideIndex = (slideIndex + 1) % slides.length;
    slides[slideIndex].classList.add("slider__slide--active");
    dots[slideIndex].classList.add("dot--active");
  }, 2600);

  // Toggle listeners
  ["colEpss","colPercentile","colDate"].forEach(id=>{
    const el = $(id);
    if(el) el.addEventListener("change", ()=> renderResultsTable());
  });


  // Copy table
  $("btnCopyTable").addEventListener("click", async ()=>{
    try{
      const tsv = rowsToTSV(lastSearchRows);
      await navigator.clipboard.writeText(tsv);
      toast("Copied table (paste into Excel)");
    }catch{
      toast("Clipboard blocked by browser", "error");
    }
  });

  // Download CSV
  $("btnDownloadCsv").addEventListener("click", ()=>{
    const csv = rowsToCSV(lastSearchRows);
    downloadTextFile("epss_results.csv", csv, "text/csv;charset=utf-8");
    toast("CSV downloaded");
  });

  // Quick Search
  $("btnSearch").addEventListener("click", async ()=>{
    const btn = $("btnSearch");
    const statusEl = $("searchStatus");
    const raw = $("cveInput").value;
    const cves = extractCVEs(raw);

    if(!cves.length){
      toast("No CVE found. Example: CVE-2022-27225", "error");
      return;
    }

    setButtonLoading(btn, true);
    setStatus(statusEl, "Fetching EPSS…");
    lastSearchRows = [];
    renderResultsTable();
    updateSummary(lastSearchRows);

    try{
      const map = await fetchEpssMapForCves(cves, (i,n)=>{
        setStatus(statusEl, `Fetching… batch ${i}/${n}`);
      });

      lastSearchRows = cves.map(cve=>{
        const row = map.get(cve.toUpperCase());
        return row ? {
          cve,
          epss: fmtNum(row.epss),
          percentile: fmtNum(row.percentile),
          date: row.date || ""
        } : { cve, epss:"", percentile:"", date:"" };
      });

      renderResultsTable();
      updateSummary(lastSearchRows);

      const found = lastSearchRows.filter(r=> r.epss !== "").length;
      setStatus(statusEl, `Done. Found ${found}/${cves.length}.`);
      toast("EPSS fetched ✅");
    }catch(e){
      setStatus(statusEl, "");
      toast(e.message || String(e), "error");
    }finally{
      setButtonLoading(btn, false);
    }
  });

  // Clear search
  $("btnClearSearch").addEventListener("click", ()=>{
    $("cveInput").value = "";
    setStatus($("searchStatus"), "");
    lastSearchRows = [];
    renderResultsTable();
    updateSummary(lastSearchRows);
    toast("Cleared");
  });

  // Excel reset
  $("btnClearExcel").addEventListener("click", ()=>{
    $("fileInput").value = "";
    setProgress(0);
    setStatus($("excelStatus"), "");
    uploadedWorkbook = null;
    uploadedSheetName = "";
    uploadedAoa = null;
    uploadedFileName = "";
    uploadedIsCsv = false;
    lastGeneratedAoa = null;
    originalUploadedAoa = null;
    previewReorderHandler = null;
    generatedReorderHandler = null;
    lastGeneratedSheetName = "";
    lastBaseAoa = null;
    lastComputedExtras = null;
    lastEpssMap = null;
    const previewStatus = $("excelPreviewStatus");
    if(previewStatus) previewStatus.textContent = "Upload a file to preview the sheet and choose a column.";
      const previewTable = $("excelPreviewTable");
      if(previewTable){
        previewTable.querySelector("thead").innerHTML = "";
        previewTable.querySelector("tbody").innerHTML = "";
      }
      const generatedStatus = $("excelGeneratedStatus");
      if(generatedStatus) generatedStatus.textContent = "Processed file preview will appear here.";
      const generatedTable = $("excelGeneratedTable");
      if(generatedTable){
        generatedTable.querySelector("thead").innerHTML = "";
        generatedTable.querySelector("tbody").innerHTML = "";
      }
      const downloadBtn = $("btnDownloadGenerated");
      if(downloadBtn) downloadBtn.disabled = true;
      toast("Reset");
    });

  // Excel file preview
  $("fileInput").addEventListener("change", async (event)=>{
    const file = event.target.files?.[0];
    const statusEl = $("excelStatus");
    if(!file){
      setStatus(statusEl, "");
      return;
    }
    if(!isSupportedSpreadsheet(file.name)){
      toast("Unsupported file. Use .xlsx, .xls, .xlsm, .xlsb, or .csv", "error");
      return;
    }

    try{
      setStatus(statusEl, "Loading preview…");
      const { wb, sheetName, aoa, isCsv } = await loadWorkbookFromFile(file);
      uploadedWorkbook = wb;
      uploadedSheetName = sheetName;
      uploadedAoa = aoa;
      uploadedFileName = file.name;
      uploadedIsCsv = isCsv;
      originalUploadedAoa = aoa.map(row => [...row]);

      const header = aoa[0] || [];
      buildColumnOptions(header);
      const defaultColumn = detectDefaultColumn(header);
      const select = $("excelColumnSelect");
      if(select) select.value = String(defaultColumn);
      previewReorderHandler = (from, to)=>{
        uploadedAoa = reorderAoaColumns(uploadedAoa, from, to);
        const select = $("excelColumnSelect");
        let selected = Number(select?.value);
        if(Number.isFinite(selected)){
          if(selected === from) selected = to;
          else if(from < selected && to >= selected) selected -= 1;
          else if(from > selected && to <= selected) selected += 1;
          if(select) select.value = String(selected);
        }
        buildColumnOptions(uploadedAoa[0] || []);
        if(select && Number.isFinite(selected)) select.value = String(selected);
        renderPreviewTable("excelPreviewTable", "excelPreviewStatus", uploadedAoa, selected, true, previewReorderHandler);
      };
      renderPreviewTable("excelPreviewTable", "excelPreviewStatus", aoa, defaultColumn, false, null);
      setStatus(statusEl, "Preview ready. Choose a CVE column and process.");
    }catch(e){
      setStatus(statusEl, "");
      toast(e.message || String(e), "error");
    }
  });

  $("excelColumnSelect").addEventListener("change", ()=>{
    if(uploadedAoa){
      renderPreviewTable("excelPreviewTable", "excelPreviewStatus", uploadedAoa, getSelectedColumnIndex(), false, null);
    }
  });

  $("btnResetColumnOrder").addEventListener("click", ()=>{
    if(!originalUploadedAoa){
      toast("No uploaded sheet to reset", "error");
      return;
    }
    uploadedAoa = originalUploadedAoa.map(row => [...row]);
    const header = uploadedAoa[0] || [];
    buildColumnOptions(header);
    const defaultColumn = detectDefaultColumn(header);
    const select = $("excelColumnSelect");
    if(select) select.value = String(defaultColumn);
    renderPreviewTable("excelPreviewTable", "excelPreviewStatus", uploadedAoa, defaultColumn, false, null);
    toast("Column order reset");
  });

  // Excel process
  $("btnProcessExcel").addEventListener("click", async ()=>{
    const btn = $("btnProcessExcel");
    const fileEl = $("fileInput");
    const statusEl = $("excelStatus");

    const file = fileEl.files?.[0];
    if(!file){
      toast("Upload an Excel file first", "error");
      return;
    }
    if(!isSupportedSpreadsheet(file.name)){
      toast("Unsupported file. Use .xlsx, .xls, .xlsm, .xlsb, or .csv", "error");
      return;
    }

    setButtonLoading(btn, true);
    setProgress(0);
    setStatus(statusEl, "Reading Excel…");

    try{
      if(!uploadedAoa || uploadedFileName !== file.name){
        const { wb, sheetName, aoa, isCsv } = await loadWorkbookFromFile(file);
        uploadedWorkbook = wb;
        uploadedSheetName = sheetName;
        uploadedAoa = aoa;
        uploadedFileName = file.name;
        uploadedIsCsv = isCsv;
      }

      const baseAoa = [...uploadedAoa.map(row => [...row])];
      const sheetName = uploadedSheetName;
      const selectedColumnIndex = getSelectedColumnIndex();
      const multiMode = getMultiEpssMode();
      const exportCols = getExcelExportColumns();

      if(!exportCols.epss && !exportCols.pct && !exportCols.date && !exportCols.found){
        setStatus(statusEl, "");
        toast("Select at least one column to add", "error");
        setButtonLoading(btn, false);
        return;
      }

      // Collect CVEs from rows
      const rowCveLists = [];
      const allCVEs = new Set();

      for(let r=1; r<baseAoa.length; r++){
        const row = baseAoa[r] || [];
        const cves = rowCVEsFromColumn(row, selectedColumnIndex);
        rowCveLists[r] = cves;
        cves.forEach(c => allCVEs.add(c));
      }

      const all = [...allCVEs];
      if(all.length === 0){
        setStatus(statusEl, "No CVEs found in the sheet.");
        toast("No CVEs detected in Excel", "error");
        setButtonLoading(btn, false);
        return;
      }

      setStatus(statusEl, `Found ${all.length} unique CVEs. Fetching EPSS…`);
      const map = await fetchEpssMapForCves(all, (i,n)=>{
        setProgress(Math.round((i/n)*100));
        setStatus(statusEl, `Fetching EPSS… batch ${i}/${n}`);
      });

      // Fill new columns per row
      const { extras, epssValuesForChart } = computeExtrasFromMap(baseAoa, selectedColumnIndex, map, multiMode);

      const topList = [...map.values()]
        .filter(r => Number.isFinite(Number(r?.epss)))
        .sort((a,b)=> Number(b.epss) - Number(a.epss))
        .slice(0, 5)
        .map(r => ({ cve: String(r.cve || "").toUpperCase(), epss: r.epss }));
      renderChart(epssValuesForChart, topList);
      setProgress(100);
      setStatus(statusEl, "Done ✅ Exporting file…");

      lastBaseAoa = baseAoa;
      lastComputedExtras = extras;
      lastEpssMap = map;
      lastGeneratedAoa = buildGeneratedAoa(baseAoa, extras, exportCols);
      lastGeneratedSheetName = sheetName || "Sheet1";
      generatedReorderHandler = (from, to)=>{
        lastGeneratedAoa = reorderAoaColumns(lastGeneratedAoa, from, to);
        renderPreviewTable("excelGeneratedTable", "excelGeneratedStatus", lastGeneratedAoa, -1, true, generatedReorderHandler);
        toast("Generated preview reordered");
      };
      renderPreviewTable("excelGeneratedTable", "excelGeneratedStatus", lastGeneratedAoa, -1, true, generatedReorderHandler);
      const downloadBtn = $("btnDownloadGenerated");
      if(downloadBtn) downloadBtn.disabled = false;
      setStatus(statusEl, "Done ✅ Preview ready. Click download to save Excel.");
      toast("Generated preview ready ✅");
    }catch(e){
      setStatus(statusEl, "");
      setProgress(0);
      toast(e.message || String(e), "error");
    }finally{
      setButtonLoading(btn, false);
    }
  });

  $("btnDownloadGenerated").addEventListener("click", ()=>{
    if(!lastGeneratedAoa || !lastGeneratedAoa.length){
      toast("No generated file to download", "error");
      return;
    }
    if(!window.XLSX){
      toast("Excel export requires SheetJS. Host ./vendor/xlsx.full.min.js.", "error");
      return;
    }
    const outWb = XLSX.utils.book_new();
    const outWs = sheetFromAOA(lastGeneratedAoa);
    const sheetName = lastGeneratedSheetName || "Sheet1";
    XLSX.utils.book_append_sheet(outWb, outWs, sheetName);

    const base = (uploadedFileName || "epss_output").replace(/\.(xlsx|xls|xlsm|xlsb|csv)$/i, "");
    const stamp = formatTimestampForFilename(new Date());
    const outName = `${base}_final_EPSS_${stamp}.xlsx`;
    XLSX.writeFile(outWb, outName);
    toast(`Downloaded ${outName}`);
  });

  ["excelColEpss","excelColPercentile","excelColDate","excelColFound"].forEach(id=>{
    const el = $(id);
    if(!el) return;
    el.addEventListener("change", ()=>{
      if(!lastBaseAoa || !lastComputedExtras) return;
      const exportCols = getExcelExportColumns();
      lastGeneratedAoa = buildGeneratedAoa(lastBaseAoa, lastComputedExtras, exportCols);
      renderPreviewTable("excelGeneratedTable", "excelGeneratedStatus", lastGeneratedAoa, -1, true, generatedReorderHandler);
      toast("Generated preview updated");
    });
  });

  document.querySelectorAll("input[name='multiEpssMode']").forEach(el=>{
    el.addEventListener("change", ()=>{
      if(!lastBaseAoa || !lastEpssMap) return;
      const exportCols = getExcelExportColumns();
      const selectedColumnIndex = getSelectedColumnIndex();
      const mode = getMultiEpssMode();
      const { extras, epssValuesForChart } = computeExtrasFromMap(lastBaseAoa, selectedColumnIndex, lastEpssMap, mode);
      lastComputedExtras = extras;
      lastGeneratedAoa = buildGeneratedAoa(lastBaseAoa, lastComputedExtras, exportCols);
      renderPreviewTable("excelGeneratedTable", "excelGeneratedStatus", lastGeneratedAoa, -1, true, generatedReorderHandler);

      const topList = [...lastEpssMap.values()]
        .filter(r => Number.isFinite(Number(r?.epss)))
        .sort((a,b)=> Number(b.epss) - Number(a.epss))
        .slice(0, 5)
        .map(r => ({ cve: String(r.cve || "").toUpperCase(), epss: r.epss }));
      renderChart(epssValuesForChart, topList);
      toast("Mode updated");
    });
  });

  // Initial render
  renderResultsTable();
  updateSummary(lastSearchRows);
});
