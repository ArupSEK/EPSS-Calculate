<div align="center">

<img src="https://readme-typing-svg.herokuapp.com?font=Inter&size=28&duration=2500&pause=700&color=6AA6FF&center=true&vCenter=true&width=760&lines=EPSS+Lookup+%E2%80%94+CVE+%E2%86%92+EPSS;Search+CVEs+or+Upload+Excel;Batch+Fetch+100+CVEs+per+Request;Export+New+Excel+with+EPSS+Columns" />

<br/>

<img src="https://img.shields.io/badge/GitHub%20Pages-Ready-6aa6ff?style=for-the-badge&logo=github" />
<img src="https://img.shields.io/badge/Excel-Upload-7cf0c7?style=for-the-badge&logo=microsoft-excel" />
<img src="https://img.shields.io/badge/FIRST%20EPSS-API-0b1020?style=for-the-badge" />

</div>

---

## ✨ About

**EPSS Lookup** is a **simple, modern, animated** GitHub Pages web app to fetch **FIRST EPSS** scores from **CVE IDs**.  
Users can search single/multiple CVEs or upload an Excel file. The app detects CVEs row-wise (even with typos), fetches EPSS in **100-CVE batches**, and exports a new Excel with an **EPSS Score** column (plus optional percentile/date). It includes smooth UI visuals and handles errors like invalid CVEs, missing results, and API/network failures.

---

## 🎬 Demo (GIF)

> Add your own demo GIF here (recommended).
> Record screen → export as `demo.gif` → upload to repo → replace path below.

<div align="center">
  <img src="./demo.gif" width="900" alt="EPSS Lookup Demo" />
</div>

---

## ✅ Features

- 🔎 **Quick Search**: paste CVEs and fetch EPSS instantly  
- 📄 **Excel Upload (.xlsx)**: auto-detect CVEs row-wise and add:
  - `EPSS Score`
  - `EPSS Percentile` (optional)
  - `EPSS Date` (optional)
  - `EPSS CVEs Found`
- ⚡ **Batch Mode**: sends **100 CVEs per request** (and stays under URL limits)
- 🧠 **Typo Handling**: detects CVEs even if headers are messy
- 📤 **Export**: downloads updated Excel file
- 🛡️ **Error Handling**: invalid CVE formats, missing data, network/API errors

---

## 🌐 Live Site

After enabling GitHub Pages:

- `https://arupsek.github.io/<repo-name>/`

---

## 🚀 Host on GitHub Pages (Quick Steps)

1. Create a repo (example: `epss-lookup`)
2. Upload these files in repo root:
   - `index.html`
   - `styles.css`
   - `app.js`
3. Go to **Settings → Pages**
4. Set:
   - **Source**: Deploy from a branch  
   - **Branch**: `main`
   - **Folder**: `/ (root)`
5. Save → open the URL GitHub shows

---

## 📌 API

Uses FIRST EPSS API:
- https://www.first.org/epss/api

---

## 📜 License

fast.org
