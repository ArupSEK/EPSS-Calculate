/* =========================
   EPSS Lookup - FIXED toggles
   ========================= */

const EPSS_BASE = "https://api.first.org/data/v1/epss";
const MAX_BATCH_CVES = 100;
const MAX_QUERY_CHARS = 1900;

let chart = null;
let lastSearchResult = {}; // { CVE: {epss, percentile, date} }

// ---------- Helpers ----------
const $ = (id) => document.getElementById(id);

function toast(msg, type = "info") {
  const el = $("toast");
  if (!el) return;
  el.textContent = msg;
  el.classList.remove("hidden");
  el.style.borderColor = type === "error" ? "rgba(255,80,80,.7)" : "rgba(255,255,255,.8)";
  setTimeout(() => el.classList.add("hidden"), 2800);
}

function setStatus(el, msg) {
  if (el) el.textContent = msg || "";
}

function setProgress(pct) {
  const bar = $("progressBar");
  if (bar) bar.style.width = `${Math.max(0, Math.min(100, pct))}%`;
}

function extractCVEs(text) {
  if (!text) return [];
  const s = String(text);
  const matches = s.match(/CVE-\d{4}-\d{4,7}/gi);
  if (!matches) return [];
  return [...new Set(matches.map(m => m.toUpperCase()))];
}

function buildBatches(cves) {
  const unique = [...new Set(cves.map(x => x.toUpperCase()))];
  const batches = [];
  let current = [];

  const wouldExceedChars = (arr, next) => ([...arr, next].join(",").length > MAX_QUERY_CHARS);

  for (const cve of unique) {
    if (current.length >= MAX_BATCH_CVES || wouldExceedChars(current, cve)) {
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

  for (let i = 0; i < batches.length; i++) {
    const batch = batches[i];
    const url = `${EPSS_BASE}?cve=${encodeURIComponent(batch.join(","))}`;

    const res = await fetch(url);
    if (!res.ok) throw new Error(`EPSS API error: HTTP ${res.status}`);

    const json = await res.json();
    const data = json?.data || [];
    for (const row of data) {
      if (row?.cve) out.set(String(row.cve).toUpperCase(), row);
    }

    if (onProgress) onProgress(i + 1, batches.length);
  }

  return out;
}

function formatMaybeNum(x) {
  const n = Number(x);
  if (!Number.isFinite(n)) return "";
  return n.toFixed(9).replace(/0+$/,"").replace(/\.$/,"");
}

/* ---------- TABLE RENDER (TOGGLES WORK HERE) ---------- */
function renderResultsTable(resultObj) {
  const table = $("resultsTable");
  if (!table) return;

  const thead = table.querySelector("thead");
  const tbody = table.querySelector("tbody");
  if (!thead || !tbody) return;

  const showEpss = $("colEpss")?.checked ?? true;
  const showPct = $("colPercentile")?.checked ?? true;
  const showDate = $("colDate")?.checked ?? true;

  thead.innerHTML = "";
  tbody.innerHTML = "";

  const headers = ["CVE"];
  if (showEpss) headers.push("EPSS");
  if (showPct) headers.push("Percentile");
  if (showDate) headers.push("Date");

  const trh = document.createElement("tr");
  headers.forEach(h => {
    const th = document.createElement("th");
    th.textContent = h;
    trh.appendChild(th);
  });
  thead.appendChild(trh);

  const entries = Object.entries(resultObj || {});
  if (!entries.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = headers.length;
    td.textContent = "No results yet.";
    td.style.opacity = "0.75";
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  for (const [cve, row] of entries) {
    const tr = document.createElement("tr");

    const tdCve = document.createElement("td");
    tdCve.textContent = cve;
    tr.appendChild(tdCve);

    if (showEpss) {
      const td = document.createElement("td");
      td.textContent = row?.epss ?? "";
      tr.appendChild(td);
    }
    if (showPct) {
      const td = document.createElement("td");
      td.textContent = row?.percentile ?? "";
      tr.appendChild(td);
    }
    if (showDate) {
      const td = document.createElement("td");
      td.textContent = row?.date ?? "";
      tr.appendChild(td);
    }

    tbody.appendChild(tr);
  }
}

async function copyVisibleTableTSV() {
  const showEpss = $("colEpss")?.checked ?? true;
  const showPct = $("colPercentile")?.checked ?? true;
  const showDate = $("colDate")?.checked ?? true;

  const headers = ["CVE"];
  if (showEpss) headers.push("EPSS");
  if (showPct) headers.push("Percentile");
  if (showDate) headers.push("Date");

  const lines = [headers.join("\t")];

  for (const [cve, row] of Object.entries(lastSearchResult || {})) {
    const cols = [cve];
    if (showEpss) cols.push(row?.epss ?? "");
    if (showPct) cols.push(row?.percentile ?? "");
    if (showDate) cols.push(row?.date ?? "");
    lines.push(cols.join("\t"));
  }

  await navigator.clipboard.writeText(lines.join("\n"));
}

/* ---------- Excel chart helpers (unchanged, safe) ---------- */
function renderChart(epssValues) {
  const ctx = $("epssChart");
  if (!ctx || !window.Chart) return;

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

  if (chart) chart.destroy();
  chart = new Chart(ctx, {
    type: "bar",
    data: { labels: buckets.map(b => b.label), datasets: [{ label: "Count", data: counts }] },
    options: { responsive: true, plugins: { legend: { display: false } } }
  });
}

/* =========================
   DOM READY - bind everything
   ========================= */
document.addEventListener("DOMContentLoaded", () => {
  // Tabs
  document.querySelectorAll(".tab").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach(b => b.classList.remove("tab--active"));
      btn.classList.add("tab--active");
      const tab = btn.dataset.tab;
      $("tab-search").classList.toggle("hidden", tab !== "search");
      $("tab-excel").classList.toggle("hidden", tab !== "excel");
    });
  });

  // Slider
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

  // ✅ TOGGLE FIX: bind checkbox change events
  ["colEpss", "colPercentile", "colDate"].forEach(id => {
    const el = $(id);
    if (el) el.addEventListener("change", () => renderResultsTable(lastSearchResult));
  });

  // Copy table
  const copyBtn = $("btnCopyTable");
  if (copyBtn) {
    copyBtn.addEventListener("click", async () => {
      try {
        await copyVisibleTableTSV();
        toast("Copied table (paste into Excel)");
      } catch {
        toast("Clipboard blocked by browser", "error");
      }
    });
  }

  // Search
  $("btnSearch").addEventListener("click", async () => {
    const statusEl = $("searchStatus");
    const raw = $("cveInput").value;
    const cves = extractCVEs(raw);

    if (!cves.length) return toast("No CVE found. Example: CVE-2022-27225", "error");

    setStatus(statusEl, "Fetching EPSS…");
    lastSearchResult = {};
    renderResultsTable(lastSearchResult);

    try {
      const epssMap = await fetchEpssMapForCves(cves, (i, n) => {
        setStatus(statusEl, `Fetching… batch ${i}/${n}`);
      });

      const result = {};
      for (const cve of cves) {
        const row = epssMap.get(cve.toUpperCase());
        result[cve] = row ? {
          epss: formatMaybeNum(row.epss),
          percentile: formatMaybeNum(row.percentile),
          date: row.date || ""
        } : { epss: "", percentile: "", date: "" };
      }

      lastSearchResult = result;
      renderResultsTable(lastSearchResult);
      setStatus(statusEl, `Done. Found ${Object.values(result).filter(r => r.epss).length}/${cves.length}.`);
      toast("EPSS fetched");
    } catch (e) {
      setStatus(statusEl, "");
      toast(e.message || String(e), "error");
    }
  });

  // Clear search
  $("btnClearSearch").addEventListener("click", () => {
    $("cveInput").value = "";
    setStatus($("searchStatus"), "");
    lastSearchResult = {};
    renderResultsTable(lastSearchResult);
    toast("Cleared");
  });

  // Initial render
  renderResultsTable({});
});
