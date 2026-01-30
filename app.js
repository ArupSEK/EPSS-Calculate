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

function extractCVEs(text){
  if(!text) return [];
  const matches = String(text).match(/CVE-\d{4}-\d{4,7}/gi);
  if(!matches) return [];
  return [...new Set(matches.map(m => m.toUpperCase()))];
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
function renderChart(epssValues){
  const canvas = $("epssChart");
  if(!canvas || !window.Chart) return;

  const vals = epssValues.map(v => Number(v)).filter(v => Number.isFinite(v));

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
  chart = new Chart(canvas, {
    type: "bar",
    data: { labels: buckets.map(b => b.label), datasets: [{ label: "Count", data: counts }] },
    options: { responsive: true, plugins: { legend: { display:false } } }
  });
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

function renderExcelPreview(aoa, selectedColumnIndex){
  const table = $("excelPreviewTable");
  const status = $("excelPreviewStatus");
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
  const maxRows = Math.min(aoa.length, 8);

  const headerRow = document.createElement("tr");
  header.forEach((cell, idx) => {
    const th = document.createElement("th");
    th.textContent = cell || `Column ${idx + 1}`;
    if(idx === selectedColumnIndex) th.classList.add("isSelected");
    headerRow.appendChild(th);
  });
  thead.appendChild(headerRow);

  for(let r = 1; r < maxRows; r++){
    const row = aoa[r] || [];
    const tr = document.createElement("tr");
    header.forEach((_, idx) => {
      const td = document.createElement("td");
      td.textContent = row[idx] ?? "";
      if(idx === selectedColumnIndex) td.classList.add("isSelected");
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  }

  if(status){
    status.textContent = `Previewing ${maxRows - 1} row(s) from "${uploadedSheetName}".`;
  }
}

async function loadWorkbookFromFile(file){
  const hasXlsx = await ensureXlsxLoaded();
  if(!hasXlsx) throw new Error("Excel engine failed to load.");

  const data = await file.arrayBuffer();
  const wb = XLSX.read(data, { type: "array" });

  const sheetName = wb.SheetNames[0];
  const ws = wb.Sheets[sheetName];
  const aoa = aoaFromSheet(ws);
  if(aoa.length === 0) throw new Error("Excel sheet is empty.");

  return { wb, sheetName, aoa };
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
    const previewStatus = $("excelPreviewStatus");
    if(previewStatus) previewStatus.textContent = "Upload a file to preview the sheet and choose a column.";
    const previewTable = $("excelPreviewTable");
    if(previewTable){
      previewTable.querySelector("thead").innerHTML = "";
      previewTable.querySelector("tbody").innerHTML = "";
    }
    toast("Reset");
  });

  // Download template
  $("btnDownloadTemplate").addEventListener("click", ()=>{
    const template = [
      ["Asset ID", "CVE", "Owner", "Notes"],
      ["SRV-001", "CVE-2023-1234", "IT", "Single CVE example"],
      ["SRV-002", "CVE-2022-27225, CVE-2022-27223", "Security", "Multiple CVEs example"],
      ["SRV-003", "", "Ops", "Leave blank if no CVE"]
    ];
    const csv = template.map(row => row.map(cell => `"${String(cell).replaceAll('"','""')}"`).join(",")).join("\n");
    downloadTextFile("epss_template.csv", csv, "text/csv;charset=utf-8");
    toast("Template downloaded");
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
      const { wb, sheetName, aoa } = await loadWorkbookFromFile(file);
      uploadedWorkbook = wb;
      uploadedSheetName = sheetName;
      uploadedAoa = aoa;
      uploadedFileName = file.name;

      const header = aoa[0] || [];
      buildColumnOptions(header);
      const defaultColumn = detectDefaultColumn(header);
      const select = $("excelColumnSelect");
      if(select) select.value = String(defaultColumn);
      renderExcelPreview(aoa, defaultColumn);
      setStatus(statusEl, "Preview ready. Choose a CVE column and process.");
    }catch(e){
      setStatus(statusEl, "");
      toast(e.message || String(e), "error");
    }
  });

  $("excelColumnSelect").addEventListener("change", ()=>{
    if(uploadedAoa){
      renderExcelPreview(uploadedAoa, getSelectedColumnIndex());
    }
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
        const { wb, sheetName, aoa } = await loadWorkbookFromFile(file);
        uploadedWorkbook = wb;
        uploadedSheetName = sheetName;
        uploadedAoa = aoa;
        uploadedFileName = file.name;
      }

      const aoa = [...uploadedAoa.map(row => [...row])];
      const sheetName = uploadedSheetName;
      const selectedColumnIndex = getSelectedColumnIndex();
      const multiMode = getMultiEpssMode();

      // Ensure header row exists
      const header = aoa[0] || [];
      const addCols = ["EPSS Score", "EPSS Percentile", "EPSS Date", "EPSS CVEs Found"];
      addCols.forEach(c => header.push(c));
      aoa[0] = header;

      // Collect CVEs from rows
      const rowCveLists = [];
      const allCVEs = new Set();

      for(let r=1; r<aoa.length; r++){
        const row = aoa[r] || [];
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
      const epssValuesForChart = [];

      for(let r=1; r<aoa.length; r++){
        const row = aoa[r] || [];
        const cves = rowCveLists[r] || [];

        let epssOut = "";
        let pctOut = "";
        let dateOut = "";

        if(multiMode === "comma"){
          const epssList = [];
          const pctList = [];
          const dateList = [];
          let hasHit = false;

          for(const cve of cves){
            const hit = map.get(cve.toUpperCase());
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
          // pick MAX EPSS among row CVEs
          let best = { epss: -1, percentile: "", date: "" };

          for(const cve of cves){
            const hit = map.get(cve.toUpperCase());
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

        row.push(epssOut, pctOut, dateOut, foundList);
        aoa[r] = row;

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

      renderChart(epssValuesForChart);
      setProgress(100);
      setStatus(statusEl, "Done ✅ Exporting new Excel…");

      // Write new workbook
      const outWb = XLSX.utils.book_new();
      const outWs = sheetFromAOA(aoa);
      XLSX.utils.book_append_sheet(outWb, outWs, sheetName);

      const outName = file.name.replace(/\.xlsx$/i,"").replace(/\.xls$/i,"") + "_epss.xlsx";
      XLSX.writeFile(outWb, outName);

      setStatus(statusEl, `Exported: ${outName}`);
      toast("Excel exported ✅");
    }catch(e){
      setStatus(statusEl, "");
      setProgress(0);
      toast(e.message || String(e), "error");
    }finally{
      setButtonLoading(btn, false);
    }
  });

  // Initial render
  renderResultsTable();
  updateSummary(lastSearchRows);
});
