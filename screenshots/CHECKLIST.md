# FLOWGUARD Demonstration Screenshot & Media Capture Checklist

This document provides a comprehensive checklist, capture specifications, and security verification guidelines for recording and capturing demonstration media (screenshots, GIFs, and video recordings) of the FLOWGUARD platform for GitHub and technical portfolios.

> [!NOTE]
> **Verified Genuine Application Visual Assets:**  
> All screenshots in `screenshots/` and `docs/images/` are verified, genuine runtime captures recorded directly from the running Streamlit dashboard (`http://localhost:8501`) and ReportLab PDF engine. All sensitive tokens, authorization headers, passwords, and administrative keys are automatically sanitized by the platform's defensive redaction engine.

---

## 1. Asset Inventory & Capture Priority

| Asset ID | File Target | Screen Description | Key Visual Elements |
| :---: | :--- | :--- | :--- |
| **IMG-01** | `docs/images/dashboard_overview.png` | **Dashboard: Vulnerable Assessment** | PNRI radial gauge at 100.0% (or 88.0%), "Critical Risk" badge, 7 Scenarios Evaluated, Scenario Matrix with FAIL statuses. |
| **IMG-02** | `docs/images/evidence_viewer.png` | **Sanitized Evidence Inspector** | Expanded card for TC-04 (IDOR) or TC-01 (Payment Bypass) showing sanitized HTTP headers, redacted tokens, and admin verification response. |
| **IMG-03** | `docs/images/dashboard_secure.png` | **Dashboard: Secure Assessment** | PNRI radial gauge at 0.00%, "Low Risk" badge (Green), 100.0% Completeness, 7/7 Scenarios with PASS badges. |
| **IMG-04** | `docs/images/assessment_history.png` | **Comparative Assessment History** | Chronological history table showing back-to-back runs (vulnerable vs. secure) with complete metadata. |
| **IMG-05** | `docs/images/pdf_report_sample.png` | **Executive PDF Report (Pages 1 & 2)** | Professional slate-navy cover page and executive summary narrative with PNRI breakdown. |

---

## 2. Detailed Capture Specifications

### Screen 1: Dashboard Overview (Vulnerable Mode — High Visual Impact)
- **Resolution**: 1920x1080 (Browser zoomed to 100% or 110% for optimal readability).
- **Target URL**: `http://localhost:8501`
- **Steps to Reproduce**:
  1. Start ShopZone: `python run_shopzone.py`
  2. Launch Dashboard: `python run_dashboard.py`
  3. In the sidebar, select **Target Mode**: `vulnerable`.
  4. Click **Run Assessment**.
  5. Once execution finishes, capture the full viewport containing:
     - The top metrics row (PNRI Score Gauge, Risk Band, Completeness, Scenarios Count).
     - The Scenario Results Matrix showing TC-01 through TC-07 with red `FAIL` badges (or yellow `INCONCLUSIVE` badge for TC-06 if race window is not corroborated by ground truth).

### Screen 2: Sanitized Evidence Inspector (Security Architecture Proof)
- **Resolution**: 1920x1080 (Focus on Findings section).
- **Steps to Reproduce**:
  1. Scroll down to Section 2: **Confirmed Findings & Evidence**.
  2. Expand Finding **`FG-TC04-001` (Insecure Direct Object Reference)** or **`FG-TC01-001`**.
  3. Expand the **Request Headers** and **Request Payload** dropdowns.
  4. Ensure the frame clearly showcases:
     - `Authorization: Bearer ***REDACTED***`
     - `password: ***REDACTED***`
     - Authoritative ground-truth verification HTTP response showing cross-tenant leakage.

### Screen 3: Dashboard Overview (Secure Mode — Verification of Defense)
- **Resolution**: 1920x1080.
- **Steps to Reproduce**:
  1. In the sidebar, toggle **Target Mode** to `secure`.
  2. Click **Run Assessment**.
  3. Capture the viewport showing:
     - PNRI Gauge at `0.00%` (Emerald Green).
     - Risk Band: `LOW`.
     - Completeness: `100.0%`.
     - All 7 scenarios displaying green `PASS` badges.
     - The callout banner: *"ZERO VULNERABILITIES DETECTED — All transactional invariants verified."*

### Screen 4: Assessment History Browser
- **Resolution**: 1920x1080.
- **Steps to Reproduce**:
  1. In the sidebar or bottom panel, open the **Assessment History** tab.
  2. Showcase at least 2–4 historical entries.
  3. Highlights: Demonstrates persistence, deterministic ID formatting (`fg-asm-[a-f0-9]{12}`), and comparative risk scoring over time.

### Screen 5: Executive PDF Report
- **Source**: `screenshots/FLOWGUARD_Executive_Report_Sample.pdf`
- **Viewer**: Adobe Acrobat, Edge PDF Viewer, or Chrome (Fit-to-Width mode).
- **Steps to Reproduce**:
  1. Open `screenshots/FLOWGUARD_Executive_Report_Sample.pdf`.
  2. Capture Page 1 (Cover Page): Clean typography, slate navy styling, metadata block.
  3. Capture Page 2: Executive summary, risk score meter, completeness warning, and methodology section.

---

## 3. Strict Pre-Capture Redaction & Privacy Checklist

Before publishing any screenshot, GIF, or video to GitHub or public repositories, verify every item below:

- [ ] **No Raw Credentials**: No plaintext passwords (e.g. `Password123!`) visible in evidence blocks or test usernames.
- [ ] **No Admin Key Exposure**: The sidebar input for `X-Admin-Key` must display as masked dots (`••••••••••••`).
- [ ] **No Session Tokens**: All JWTs, bearer tokens, or cookie hashes must be displayed as `***REDACTED***`.
- [ ] **Localhost Only**: The browser address bar must show `http://localhost:8501` or `http://127.0.0.1:8501`. No external domain names or private internal network IP addresses (e.g. `192.168.x.x` or `10.x.x.x`).
- [ ] **No Local Path Leaks**: Browser tabs, terminal headers, or file paths must not reveal sensitive Windows usernames (e.g. `C:\Users\username\...`). Crop terminal title bars if necessary.
- [ ] **Clean Browser View**: Disable personal browser bookmarks, extension icons, or extraneous open tabs.

---

## 4. Destination Directory Setup

Save captured PNG images into both:
1. `docs/images/` (Referenced by `README.md` and documentation guides)
2. `screenshots/` (Dedicated showcase gallery for GitHub viewers)

### Recommended Image Formatting
- **Format**: PNG (24-bit with standard compression).
- **DPI**: Standard 72 or 96 DPI for web.
- **Naming Convention**:
  - `docs/images/dashboard_overview.png`
  - `docs/images/evidence_viewer.png`
  - `docs/images/dashboard_secure.png`
  - `docs/images/assessment_history.png`
  - `docs/images/pdf_report_sample.png`
