# FLOWGUARD Installation & Setup Guide (Windows)

This document provides step-by-step instructions for installing, configuring, and verifying the FLOWGUARD platform and ShopZone laboratory on Windows environments.

---

## 1. System Requirements

- **Operating System**: Windows 10 or Windows 11 (64-bit).
- **Shell**: PowerShell 5.1+ or Windows Terminal with PowerShell Core.
- **Python**: Version **3.12.x** (Verify with `python --version`).
- **RAM**: Minimum 4 GB (8 GB recommended for concurrent scenario testing).
- **Disk Space**: ~500 MB free space for virtual environment, databases, and dependencies.
- **Editor**: Visual Studio Code (Recommended).

---

## 2. Step-by-Step Installation

### Step 1: Open Terminal in Project Directory
Launch PowerShell as an Administrator or standard user and navigate to the project directory:

```powershell
cd FLOWGUARD
```

### Step 2: Configure PowerShell Execution Policy (If Needed)
If you encounter script execution restrictions when activating virtual environments, permit local signed scripts:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
```

### Step 3: Create and Activate Python Virtual Environment
Isolate project dependencies by creating a dedicated virtual environment:

```powershell
# Create the virtual environment
python -m venv venv

# Activate the virtual environment
.\venv\Scripts\Activate.ps1
```

Confirm that your prompt is prefixed with `(venv)`:
```powershell
(venv) PS C:\...\FLOWGUARD>
```

### Step 4: Install Dependencies
Upgrade `pip` and install all required packages specified in `requirements.txt`:

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Verify installed packages:
```powershell
pip list
```
Key packages include:
- `Flask` (3.1.0)
- `SQLAlchemy` (2.0.40)
- `requests` (2.34.2)
- `streamlit` (1.60.0)
- `plotly` (6.9.0)
- `reportlab` (5.0.1)
- `pytest` (9.2.0)
- `python-dotenv` (1.2.4)

---

## 3. Environment Configuration

### Step 1: Create `.env` from Example
Copy `.env.example` to generate your local `.env`:

```powershell
Copy-Item .env.example .env
```

### Step 2: Review Configuration Settings
Open `.env` in VS Code or Notepad:

```env
# Secret key for protected admin operations (reset, health, ground-truth verification)
ADMIN_KEY=flowguard_admin_secret_key_change_me_local_lab

# ShopZone Service Configuration
SHOPZONE_HOST=127.0.0.1
SHOPZONE_PORT=5000
SHOPZONE_DEBUG=False

# Physical SQLite database paths
VULN_DB_PATH=instance/shopzone_vuln.db
SEC_DB_PATH=instance/shopzone_sec.db
```

> [!IMPORTANT]
> The `ADMIN_KEY` configured in `.env` is automatically used by both ShopZone (to authenticate admin requests) and FLOWGUARD (to execute ground-truth verifications).

---

## 4. Visual Studio Code Integration

The project includes pre-configured settings in the `.vscode/` directory:

1. [`.vscode/launch.json`](../.vscode/launch.json):
   - **`1. Run ShopZone Server`**: Launches the Flask target at `http://127.0.0.1:5000`.
   - **`2. Run FlowGuard Dashboard (Streamlit)`**: Launches the visual dashboard at `http://localhost:8501`.
   - **`3. FlowGuard Assessment (Secure Mode)`**: Runs the CLI assessment against secure routes.
   - **`4. FlowGuard Assessment (Vulnerable Mode)`**: Runs the CLI assessment against vulnerable routes.
   - **`5. Run All Pytests`**: Runs the complete test suite.
2. [`.vscode/tasks.json`](../.vscode/tasks.json): One-click task execution for background servers and test runners.
3. [`.vscode/settings.json`](../.vscode/settings.json): Integrates Pytest with the VS Code Test Explorer panel.

---

## 5. Verification Checklist

To confirm the installation is operational, execute the following verification steps:

### Check 1: Execute the Automated Test Suite
Run the test suite via Pytest:
```powershell
python -m pytest tests -q
```
**Expected Result**: All 383 tests pass (`383 passed, 1 warning`).

### Check 2: Start ShopZone Target
In Terminal 1, launch the ShopZone API:
```powershell
python run_shopzone.py
```
**Expected Output**:
```text
[*] Starting ShopZone on http://127.0.0.1:5000
[*] Vulnerable mode prefix: http://127.0.0.1:5000/vuln/api
[*] Secure mode prefix:     http://127.0.0.1:5000/sec/api
[*] Admin key configured:   YES
```

### Check 3: Probe Admin Health
In Terminal 2, probe the admin health check endpoint:
```powershell
python -c "import urllib.request; req = urllib.request.Request('http://127.0.0.1:5000/api/admin/health', headers={'X-Admin-Key': 'flowguard_admin_secret_key_change_me_local_lab'}); resp = urllib.request.urlopen(req); print(resp.read().decode())"
```
**Expected Output**:
```json
{"databases":{"secure":"online","vulnerable":"online"},"mode_isolation":"physically_separate_sqlite_files","status":"healthy"}
```

### Check 4: Run a Test CLI Assessment
In Terminal 2, execute a secure assessment:
```powershell
python run_assessment.py --mode secure
```
**Expected Result**: All 7 scenarios return `[PASS]`, Completeness = 100.0%, PNRI = 0.00 / 100.00.

---

## 6. Windows Troubleshooting Guide

### Issue: `Port 5000 Already in Use`
- **Cause**: A previous ShopZone instance or another local service (such as Windows AirPlay Receiver) is bound to port 5000.
- **Resolution**:
  Identify the process ID and terminate it:
  ```powershell
  Get-Process -Id (Get-NetTCPConnection -LocalPort 5000).OwningProcess | Stop-Process -Force
  ```

### Issue: `UnicodeEncodeError: 'charmap' codec can't encode character`
- **Cause**: Standard Windows console running in `cp1252` encoding encountering UTF-8 terminal symbols.
- **Resolution**:
  FLOWGUARD has been sanitized to use ASCII indicators (`[+]`, `[!]`). If external scripts exhibit issues, set the console encoding to UTF-8:
  ```powershell
  [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
  $env:PYTHONIOENCODING = "utf-8"
  ```

### Issue: `Missing ADMIN_KEY Environment Variable`
- **Cause**: Script executed from a directory where `.env` was not discovered.
- **Resolution**:
  FLOWGUARD automatically resolves `.env` relative to the project root. Ensure `.env` exists in the top-level repository root directory (`FLOWGUARD/.env`).
