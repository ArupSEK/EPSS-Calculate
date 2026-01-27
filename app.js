/* =========================
   EPSS Lookup - GitHub Pages
   ========================= */

const EPSS_BASE = "https://api.first.org/data/v1/epss"; // :contentReference[oaicite:6]{index=6}
const MAX_BATCH_CVES = 100;
const MAX_QUERY_CHARS = 1900; // API mentions 2000 char limit for cve param, keep buffer :contentReference[oaicite:7]{index=7}

let chart = null;
let lastSearchJson = {};

// ---------- Helpers ----------
const $ = (id) => document.getElementById(id);

function toast(msg, type = "info") {
  const el = $("toast");
  el.textContent = msg;
  el.classList.remove("hidden");
  el.style.borderColor = type === "error" ? "rgba(255,80,80,.5)" : "var(--border)";
  setTimeout(() => el.classList.add("hidden"), 2800);
}

function setStatus(el, msg) {
  el.textContent = msg || "";
}

function setProgress(pct) {
  $("progressBar").style.width = `${Math.max(0, Math.min(100, pct))}%`;
}

function extractCVEs(text) {
  if (!text) return [];
  const s = String(text);
  // tolerate brackets, commas, text, etc.
  const matches = s.match(/CVE-\d{4}-\d{4,7}/gi);
  if (!matches) return [];
  // normalize uppercase + unique
  return [...new Set(matches.map(m => m.toUpperCase()))];
}

function normalizeHeader(h) {
  return String(h || "")
    .trim()
    .toLowerCase()
    .replace(/[\s/_-]+/g, " ");
}

function looksLikeCveHeader(h) {
  const nh = normalizeHeader(h);
  // tolerate common typos / variants
  return (
    nh.includes("cve") ||
    nh.includes("cwe") ||
    nh.includes("identified") && nh.includes("cve") ||
    nh.includes("vulnerability") && nh.includes("id")
  );
}

// Build batches of CVEs respecting both:
// - up to 100 CVEs per batch
// - URL query length limit (buffer under 2000 chars) :contentReference[oaicite:8]{index=8}
function buildBatches(cves) {
  const unique = [...new Set(cves.map(x => x.toUpperCase()))];
  const batches = [];
  let current = [];

  const wouldExceedChars = (arr, next) => {
    const joined = [...arr, next].join(",");
    return joined.length > MAX_QUERY_CHARS;
  };

  for (const cve of unique) {
    if (
      current.length >= MAX_BATCH_CVES ||
      wouldExceedChars(current, cve)
    ) {
      if (current.length) batches.push(current);
      current = [];
    }
    current.push(cve);
  }
  if (current.length) batches.push(current);
  return batches;
}

async function fetchEpssMapForCves(cves, onProgress) {
  const batches = buildBatches(cves);
  const out = new Map();

  let done = 0;
  for (let i = 0; i < batches.length; i++) {
    const batch = batches[i];
    const url = `${EPSS_BASE}?cve=${encodeURIComponent(batch.join(","))}`;

    let res;
    try {
      res = await fetch(url, { method: "GET" });
    } catch (e) {
      throw new Error(`Network error while calling EPSS API: ${e?.message || e}`);
    }

    if (!res.ok) {
      throw new Error(`EPSS API returned HTTP ${res.status}`);
    }

    const json = await res.json();
    const data = json?.data || [];
    for (const row of data) {
      // row: { cve, epss, percentile, date }
      if (row?.cve) out.set(String(row.cve).toUpperCase(), row);
    }

    done += batch.length;
    if (onProgress) onProgress({ batchIndex: i + 1, batchCount: batches.length, done, total: cves.length });
  }

  return out;
}

function aggregateEpss(rows, mode) {
  // rows: array of api objects {epss, percentile, date}
  const numeric = rows
    .map(r => Number(r?.epss))
    .filter(v => Number.isFinite(v));

  if (!numeric.length) return { value: "", note: "No EPSS found" };

  if (mode === "avg") {
    const avg = numeric.reduce((a, b) => a + b, 0) / numeric.length;
    return { value: avg, note: `avg of ${numeric.length}` };
  }

  if (mode === "list") {
    return { value: numeric.join(", "), note: `list of ${numeric.length}` };
  }

  // default max
  const max = Math.max(...numeric);
  return { value: max, note: `max of ${numeric.length}` };
}

function formatMaybeNum(x) {
  const n = Number(x);
  if (!Number.isFinite(n)) return "";
  // EPSS often shown with 6-9 decimals
  return n.toFixed(9).replace(/0+$/,"").replace(/\.$/,"");
}

function safeSheetName(name) {
  return String(name || "Sheet1").slice(0, 28);
}

// ---------- UI: theme ----------
$("themeBtn").addEventListener("click", () => {
  const root = document.documentElement;
  const now = root.getAttribute("data-theme");
  root.setAttribute("data-theme", now === "light" ? "dark" : "light");
});

// ---------- UI: tabs ----------
document.querySelectorAll(".tab").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(b => b.classList.remove("tab--active"));
    btn.classList.add("tab--active");

    const tab = btn.dataset.tab;
    $("tab-search").classList.toggle("hidden", tab !== "search");
    $("tab-excel").classList.toggle("hidden", tab !== "excel");
  });
});

// ---------- UI: slider ----------
let slideIndex = 0;
setInterval(() => {
  const slides = document.querySelectorAll(".slider__slide");
  const dots = document.querySelectorAll(".dot");
  slides.forEach(s => s.classList.remove("slider__slide--active"));
  dots.forEach(d => d.classList.remove("dot--active"));
  slideIndex = (slideIndex + 1) % slides.length;
  slides[slideIndex].classList.add("slider__slide--active");
  dots[slideIndex].classList.add("dot--active");
}, 2600);

// ---------- Quick search ----------
$("btnClearSearch").addEventListener("click", () => {
  $("cveInput").value = "";
  $("searchResult").textContent = "{}";
  setStatus($("searchStatus"), "");
  lastSearchJson = {};
});

$("btnCopyJson").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(JSON.stringify(lastSearchJson, null, 2));
    toast("Copied JSON to clipboard");
  } catch {
    toast("Clipboard blocked by browser", "error");
  }
});

$("btnSearch").addEventListener("click", async () => {
  const statusEl = $("searchStatus");
  const raw = $("cveInput").value;
  const cves = extractCVEs(raw);

  if (!cves.length) {
    toast("No CVE found. Example: CVE-2022-27225", "error");
    return;
  }

  setStatus(statusEl, "Fetching EPSS…");
  $("searchResult").textContent = "{}";

  try {
    const epssMap = await fetchEpssMapForCves(cves, (p) => {
      setStatus(statusEl, `Fetching… batch ${p.batchIndex}/${p.batchCount}`);
    });

    const result = {};
    for (const cve of cves) {
      const row = epssMap.get(cve.toUpperCase());
      result[cve] = row
        ? {
            epss: formatMaybeNum(row.epss),
            percentile: formatMaybeNum(row.percentile),
            date: row.date || ""
          }
        : { epss: "", percentile: "", date: "", error: "Not found" };
    }

    lastSearchJson = result;
    $("searchResult").textContent = JSON.stringify(result, null, 2);
    setStatus(statusEl, `Done. Found ${Object.values(result).filter(r => r.epss).length}/${cves.length}.`);
    toast("EPSS fetched");
  } catch (e) {
    setStatus(statusEl, "");
    toast(e.message || String(e), "error");
  }
});

// ---------- Excel flow ----------
let loadedWorkbook = null;
let loadedSheetNames = [];

$("btnResetExcel").addEventListener("click", () => {
  $("fileInput").value = "";
  loadedWorkbook = null;
  loadedSheetNames = [];
  setStatus($("excelStatus"), "");
  setProgress(0);
  renderPreview([]);
  renderChart([]);
  toast("Reset");
});

$("fileInput").addEventListener("change", async (ev) => {
  const file = ev.target.files?.[0];
  if (!file) return;

  if (!window.XLSX) {
    toast("XLSX library not loaded. Check your script tag.", "error");
    return;
  }

  setStatus($("excelStatus"), "Reading workbook…");
  setProgress(0);

  try {
    const data = await file.arrayBuffer();
    loadedWorkbook = XLSX.read(data, { type: "array" });
    loadedSheetNames = loadedWorkbook.SheetNames || [];

    if (!loadedSheetNames.length) throw new Error("No sheets found in workbook.");

    // Preview first sheet
    const ws = loadedWorkbook.Sheets[loadedSheetNames[0]];
    const json = XLSX.utils.sheet_to_json(ws, { defval: "" });
    renderPreview(json.slice(0, 10));
    setStatus($("excelStatus"), `Loaded: ${file.name} (sheets: ${loadedSheetNames.length}).`);
    toast("Workbook loaded");
  } catch (e) {
    setStatus($("excelStatus"), "");
    toast(`Failed to read Excel: ${e.message || e}`, "error");
  }
});

function renderPreview(rows) {
  const thead = $("previewTable").querySelector("thead");
  const tbody = $("previewTable").querySelector("tbody");
  thead.innerHTML = "";
  tbody.innerHTML = "";

  if (!rows || !rows.length) return;

  const headers = Object.keys(rows[0] || {});
  const trh = document.createElement("tr");
  headers.forEach(h => {
    const th = document.createElement("th");
    th.textContent = h;
    trh.appendChild(th);
  });
  thead.appendChild(trh);

  rows.forEach(r => {
    const tr = document.createElement("tr");
    headers.forEach(h => {
      const td = document.createElement("td");
      td.textContent = String(r[h] ?? "");
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
}

function renderChart(epssValues) {
  const ctx = $("epssChart");
  if (!ctx) return;

  const vals = epssValues
    .map(v => Number(v))
    .filter(v => Number.isFinite(v));

  // simple histogram buckets
  const buckets = [
    { label: "0–0.01", min: 0, max: 0.01 },
    { label: "0.01–0.05", min: 0.01, max: 0.05 },
    { label: "0.05–0.1", min: 0.05, max: 0.1 },
    { label: "0.1–0.3", min: 0.1, max: 0.3 },
    { label: "0.3–0.6", min: 0.3, max: 0.6 },
    { label: "0.6–1.0", min: 0.6, max: 1.0 },
  ];

  const counts = buckets.map(b =>
    vals.filter(x => x >= b.min && x < b.max).length
  );

  if (chart) chart.destroy();
  chart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: buckets.map(b => b.label),
      datasets: [{ label: "Count", data: counts }]
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: getComputedStyle(document.body).color } },
        y: { ticks: { color: getComputedStyle(document.body).color } },
      }
    }
  });
}

$("btnProcess").addEventListener("click", async () => {
  const statusEl = $("excelStatus");

  if (!loadedWorkbook) {
    toast("Upload an Excel file first.", "error");
    return;
  }

  const processOnlyFirst = $("onlyFirstSheet").checked;
  const includePercentile = $("includePercentile").checked;
  const aggMode = $("aggMode").value;

  const sheetNames = processOnlyFirst ? [loadedSheetNames[0]] : loadedSheetNames.slice();
  setStatus(statusEl, "Scanning workbook for CVEs…");
  setProgress(2);

  try {
    // 1) Convert sheets to JSON rows
    const sheetsRows = [];
    let allCVEs = [];

    for (const name of sheetNames) {
      const ws = loadedWorkbook.Sheets[name];
      const rows = XLSX.utils.sheet_to_json(ws, { defval: "" });
      sheetsRows.push({ name, rows });

      // Pull CVEs from all cells (robust against header typos)
      for (const row of rows) {
        for (const key of Object.keys(row)) {
          const val = row[key];
          const cves = extractCVEs(val);
          if (cves.length) allCVEs.push(...cves);
        }
      }
    }

    allCVEs = [...new Set(allCVEs.map(x => x.toUpperCase()))];

    if (!allCVEs.length) {
      setProgress(0);
      setStatus(statusEl, "No CVEs found in the selected sheets.");
      toast("No CVEs detected in Excel.", "error");
      return;
    }

    setStatus(statusEl, `Found ${allCVEs.length} unique CVEs. Fetching EPSS in batches…`);
    setProgress(6);

    // 2) Fetch EPSS map
    const epssMap = await fetchEpssMapForCves(allCVEs, (p) => {
      const pct = 6 + Math.round((p.batchIndex / p.batchCount) * 60);
      setProgress(pct);
      setStatus(statusEl, `Fetching EPSS… batch ${p.batchIndex}/${p.batchCount}`);
    });

    // 3) Add columns row-wise and build output workbook
    const outWb = XLSX.utils.book_new();
    const epssCollected = [];

    for (const sheet of sheetsRows) {
      const rows = sheet.rows;

      // decide which columns to append
      const EPS_COL = "EPSS Score";
      const EPS_PCT_COL = "EPSS Percentile";
      const EPS_DATE_COL = "EPSS Date";
      const EPS_CVES_COL = "EPSS CVEs Found";

      for (const row of rows) {
        // Extract CVEs from entire row (not relying on any one header)
        let rowCves = [];
        for (const k of Object.keys(row)) {
          const found = extractCVEs(row[k]);
          if (found.length) rowCves.push(...found);
        }
        rowCves = [...new Set(rowCves.map(x => x.toUpperCase()))];

        row[EPS_CVES_COL] = rowCves.join(", ");

        if (!rowCves.length) {
          row[EPS_COL] = "";
          if (includePercentile) {
            row[EPS_PCT_COL] = "";
            row[EPS_DATE_COL] = "";
          }
          continue;
        }

        const apiRows = rowCves
          .map(c => epssMap.get(c))
          .filter(Boolean);

        const agg = aggregateEpss(apiRows, aggMode);
        row[EPS_COL] = (aggMode === "list")
          ? agg.value
          : formatMaybeNum(agg.value);

        if (includePercentile) {
          // use percentile/date of the CVE with max epss (or first available)
          let best = apiRows[0] || null;
          for (const r of apiRows) {
            if (Number(r.epss) > Number(best?.epss || -1)) best = r;
          }
          row[EPS_PCT_COL] = best ? formatMaybeNum(best.percentile) : "";
          row[EPS_DATE_COL] = best ? (best.date || "") : "";
        }

        if (aggMode !== "list" && row[EPS_COL] !== "") epssCollected.push(Number(agg.value));
      }

      const outWs = XLSX.utils.json_to_sheet(rows);
      XLSX.utils.book_append_sheet(outWb, outWs, safeSheetName(sheet.name));
    }

    setProgress(92);
    renderPreview(sheetsRows[0].rows.slice(0, 10));
    renderChart(epssCollected);

    // 4) Export
    const outNameBase = "epss_output";
    const outFile = `${outNameBase}_${new Date().toISOString().slice(0,10)}.xlsx`;
    XLSX.writeFile(outWb, outFile);

    setProgress(100);
    setStatus(statusEl, `Done. Exported: ${outFile}`);
    toast("Export completed");
  } catch (e) {
    setProgress(0);
    setStatus(statusEl, "");
    toast(e.message || String(e), "error");
  }
});
