# FLOWGUARD Professional Live Demonstration Script

This document provides a minute-by-minute demonstration script for showcasing the FLOWGUARD Business-Logic Security Assessment Platform in technical presentations, portfolio walk-throughs, or video demonstrations.

---

## Demonstration Overview

- **Audience**: Security Engineers, DevSecOps Leads, Application Architects, Technical Recruiters.
- **Estimated Duration**: 7 – 10 minutes.
- **Key Takeaway**: FLOWGUARD automates multi-session adversarial testing to detect critical business-logic vulnerabilities (unpaid checkout, coupon reuse, IDOR, race conditions, price tampering) that bypass conventional DAST and SAST scanners.
- **Safety Boundary**: 100% localhost-contained laboratory environment; zero external network traffic.

---

## Demonstration Setup & Layout

Arrange three terminal windows side-by-side or use VS Code's split-terminal view:

```text
+-----------------------------+-----------------------------+
| Terminal 1: ShopZone Target | Terminal 2: Streamlit UI    |
| (python run_shopzone.py)    | (python run_dashboard.py)   |
+-----------------------------+-----------------------------+
| Terminal 3: Interactive CLI & Assessment Controller       |
| (python run_assessment.py --mode vulnerable / secure)     |
+-----------------------------------------------------------+
```

---

## Minute-by-Minute Demonstration Walkthrough

### Phase 1: Architecture Introduction & Target Launch (0:00 – 1:30)

**Speaker Talking Points:**
> *"Traditional application security scanners are great at finding technical bugs like SQL injection or cross-site scripting. But when it comes to business logic—such as buying a \$4,500 laptop for \$1, or confirming an order without paying—traditional tools are blind. FLOWGUARD was built to solve this challenge through automated, multi-session adversarial testing with out-of-band ground-truth verification."*

**Step 1: Start ShopZone Target API (Terminal 1)**
```powershell
python run_shopzone.py
```
**Highlight to Audience:**
- Point out that ShopZone mounts two parallel API namespaces: `/vuln/api` and `/sec/api`.
- Emphasize the physical isolation: separate SQLite databases (`shopzone_vuln.db` and `shopzone_sec.db`).
- Mention the protected admin route requiring `X-Admin-Key` for independent ground-truth verification.

---

### Phase 2: Launch the Visual Assessment Dashboard (1:30 – 3:00)

**Speaker Talking Points:**
> *"Now we'll launch the FLOWGUARD visual analytics dashboard built with Streamlit. The dashboard connects to the local target over HTTP without direct database access."*

**Step 2: Launch Streamlit Dashboard (Terminal 2)**
```powershell
python run_dashboard.py
```
- Open browser to `http://localhost:8501`.
- Walk through the sidebar controls:
  - Target URL is constrained to localhost.
  - Mode selector (`vulnerable` vs. `secure`).
  - `X-Admin-Key` input is automatically masked (`••••••••••••`) to prevent credential leakage.

---

### Phase 3: Vulnerable-Mode Attack & Findings Analysis (3:00 – 5:00)

**Speaker Talking Points:**
> *"Let's simulate an adversarial attack against the vulnerable profile. We can run this via the CLI or directly in the dashboard. Let's run the CLI to inspect real-time progress."*

**Step 3: Run Vulnerable Assessment (Terminal 3)**
```powershell
python run_assessment.py --mode vulnerable
```

**Highlight to Audience as Results Stream In:**
1. **TC-01 (Payment Bypass)**: Attacker transitions an unpaid order from `PENDING_PAYMENT` to `CONFIRMED`. FLOWGUARD confirms via admin API that no payment record was ever created.
2. **TC-02 (Coupon Reuse)**: A single-use coupon (`max_uses=1`) is redeemed across two distinct synthetic users.
3. **TC-03 (Duplicate Order Creation)**: Resubmitting identical checkout payloads with the same idempotency key creates duplicate orders and decrements duplicate inventory.
4. **TC-04 (Order IDOR)**: User B accesses User A's order metadata; admin verification proves User A was the legitimate owner.
5. **TC-05 (Invalid Workflow Transitions)**: Attacker confirms an already-cancelled order.
6. **TC-06 (Concurrent Checkout Race)**: High-concurrency checkout threads attempt duplicate order commits from a single cart.
7. **TC-07: Client-Side Price Tampering**: Attacker submits `total_amount: 100` for a $4,500 catalog item; the server stores the tampered price.

**Review Metrics in Terminal or Dashboard:**
- **Outcome A (Race Window Corroborated)**:
  - TC-01 through TC-07: All 7 `[FAIL]`
  - Raw Risk Score: `125 / 125` | PNRI Score: `100.00 / 100.00 (Critical Risk)` | Completeness: `100.0%`
- **Outcome B (Race Window Not Corroborated)**:
  - TC-01..TC-05, TC-07: `[FAIL]`; TC-06: `[INCONCLUSIVE]`
  - Raw Risk Score: `110 / 125` | PNRI Score: `88.00 / 100.00 (Critical Risk)` | Completeness: `85.71%`
  - *Fail-Closed Policy*: An incomplete assessment (< 100.0% completeness) cannot be certified as fully verified. The dashboard prominently renders incomplete-assessment warning banners.

---

### Phase 4: Reviewing Findings & Sanitized Evidence (5:00 – 6:30)

**Speaker Talking Points:**
> *"In the dashboard, each vulnerability is mapped to a canonical CWE. More importantly, notice our defensive redaction: FLOWGUARD never logs or exposes raw tokens or passwords."*

1. Switch to the Streamlit browser window (`http://localhost:8501`).
2. Refresh or observe the latest run.
3. Expand **Finding #4 (Insecure Direct Object Reference — CWE-639)**.
4. Show the **Sanitized Evidence Viewer**:
   - `Authorization: Bearer ***REDACTED***`
   - `password: ***REDACTED***`
   - Show how the ground-truth verification HTTP response provides undeniable proof of cross-tenant leakage.

---

### Phase 5: Verifying Defense with Secure Mode (6:30 – 8:00)

**Speaker Talking Points:**
> *"Now let's assess the hardened secure profile (`/sec/api`). Here, the application enforces atomic transactions, server-authoritative pricing, FSM transitions, and database-level unique constraints."*

**Step 4: Run Secure Assessment (Terminal 3)**
```powershell
python run_assessment.py --mode secure
```

**Highlight to Audience:**
- All 7 scenarios return `[PASS]`.
- **TC-01**: Unpaid confirmation rejected with `HTTP 400 Bad Request`.
- **TC-02**: Second user coupon redemption rejected with `HTTP 409 Conflict`.
- **TC-03**: Replayed checkout returns cached original order with `idempotent_replay: true`.
- **TC-04**: Tenant access attempt denied with `HTTP 404 Not Found`.
- **TC-07**: Server recalculates the total from canonical catalog data, overriding the tampered client value.

**Review Comparative Metrics:**
- **Raw Risk Score**: `0 / 125`
- **PNRI Score**: `0.00 / 100.00 (Low Risk)`
- **Completeness**: `100.0%`
- **Confirmed Flaws**: `0`

---

### Phase 6: Executive PDF Report Generation (8:00 – 9:30)

**Speaker Talking Points:**
> *"Finally, security assessments need to be communicated to executive stakeholders. FLOWGUARD features an integrated ReportLab reporting engine that generates publication-quality PDF reports with zero direct database coupling."*

1. In the Streamlit dashboard, click the **"📥 Download PDF Report"** button located at the top of the assessment report view (or navigate to the **Assessment History** tab and click the **"📥 PDF"** button next to any historical run).
2. Open the downloaded PDF report:
   - **Page 1**: Professional cover page with target metadata and timestamp.
   - **Page 2**: Executive Summary with Project-Specific Normalized Risk Index breakdown.
   - **Page 3**: Tabular matrix of all seven scenarios with unwrapped diagnostic observations.
   - **Page 4**: Technical findings, CWE mappings, business impact analysis, code-level remediation snippets, and sanitized evidence.

---

## Demonstration Checklist Summary

Before starting your demonstration, ensure:
- [ ] Virtual environment is active: `.\venv\Scripts\Activate.ps1`.
- [ ] `.env` is configured with valid `ADMIN_KEY`.
- [ ] Port 5000 and Port 8501 are free.
- [ ] Pytest test suite passes: `python -m pytest tests -q` (383 passed).
- [ ] Browser window is zoomed to 100% or 110% at `http://localhost:8501`.
- [ ] Terminal font size is enlarged (e.g. 14pt – 16pt) for audience visibility.
