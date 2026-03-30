[README.md](https://github.com/user-attachments/files/26340615/README.md)
# NDIS Fraud Intelligence Dashboard
### v0.2 — GitHub Pages + Cloudflare Worker

A fraud pattern analysis tool for NDIS provider data. Integrates the NDIS Provider Register (data.gov.au), ABR Web Services API, and ABS population data.

---

## Architecture

```
GitHub Pages (index.html)
    │
    │  fetch()
    ▼
Cloudflare Worker (worker.js)
    ├── /api/providers  ──► data.gov.au  (NDIS Provider Register CSV)
    ├── /api/density    ──► Computed from providers + ABS population table
    ├── /api/kpis       ──► Computed KPI summary
    └── /api/abn/:abn   ──► abr.business.gov.au (ABR XML API)
```

The Worker handles:
- CORS (so GitHub Pages can call it)
- Caching (Cloudflare KV — 6-hour TTL)
- Hiding API credentials from the browser
- Risk score computation (duplicate contacts, density, ABN changes)

---

## Prerequisites

- GitHub account
- Cloudflare account (free tier is sufficient)
- ABR Web Services GUID (free — takes ~5 minutes to get)

---

## Step 1 — Get your ABR GUID (free)

1. Go to: https://abr.business.gov.au/Tools/WebServices
2. Click **Register for a GUID**
3. Fill in the registration form (business/individual details)
4. You'll receive your GUID by email — keep it safe, treat it like a password

---

## Step 2 — Deploy the Cloudflare Worker

### 2a. Install Wrangler (Cloudflare CLI)

```bash
npm install -g wrangler
wrangler login
```

### 2b. Create a new Worker project

```bash
mkdir ndis-fraud-worker
cd ndis-fraud-worker
wrangler init --yes
```

Copy `worker.js` from this repo into the project, replacing the generated `src/index.js`:

```bash
cp /path/to/worker.js src/index.js
```

### 2c. Create a wrangler.toml

Create `wrangler.toml` in your worker project:

```toml
name = "ndis-fraud-intelligence"
main = "src/index.js"
compatibility_date = "2024-01-01"

[[kv_namespaces]]
binding = "NDIS_KV"
id = "YOUR_KV_NAMESPACE_ID"   # Create this in the next step
```

### 2d. Create a KV namespace for caching

```bash
wrangler kv:namespace create "NDIS_CACHE"
```

Copy the `id` from the output and paste it into `wrangler.toml`.

### 2e. Set environment variables (secrets)

```bash
# Your ABR GUID from Step 1
wrangler secret put ABR_GUID

# Your GitHub Pages URL (e.g. https://yourusername.github.io)
wrangler secret put ALLOWED_ORIGIN
```

### 2f. Deploy

```bash
wrangler deploy
```

Note the Worker URL — it will look like:
`https://ndis-fraud-intelligence.yourusername.workers.dev`

---

## Step 3 — Configure GitHub Pages

### 3a. Fork or create a GitHub repo

Create a new GitHub repository named `ndis-fraud-intelligence` (or similar).

### 3b. Update WORKER_URL in index.html

Open `index.html` and find the CONFIG block near the top of the `<script>` tag:

```javascript
const CONFIG = {
  WORKER_URL: '',   // ← Paste your Worker URL here
  USE_MOCK: true,
  VERSION: '0.2.0'
};
```

Replace the empty string with your Worker URL:

```javascript
WORKER_URL: 'https://ndis-fraud-intelligence.yourusername.workers.dev',
```

### 3c. Push to GitHub

```bash
git init
git add index.html
git commit -m "Initial NDIS Fraud Intelligence Dashboard"
git remote add origin https://github.com/yourusername/ndis-fraud-intelligence.git
git push -u origin main
```

### 3d. Enable GitHub Pages

1. Go to your repo → **Settings** → **Pages**
2. Source: **Deploy from a branch**
3. Branch: `main` / `/ (root)`
4. Click **Save**

Your dashboard will be live at:
`https://yourusername.github.io/ndis-fraud-intelligence/`

---

## Step 4 — Verify live data is loading

1. Open your GitHub Pages URL
2. The data source badge in the top-right should show **Live Data** (green)
3. If it shows **Mock Data** (amber), check:
   - WORKER_URL is set correctly in index.html
   - The Worker deployed without errors (`wrangler tail` to debug)
   - ALLOWED_ORIGIN matches your GitHub Pages URL exactly

---

## Data Sources

| Source | URL | Update Frequency | Notes |
|--------|-----|-----------------|-------|
| NDIS Provider Register | data.gov.au | Weekly (govt publishes) | Cached 6h in Worker KV |
| ABR Web Services | abr.business.gov.au | Real-time | Free GUID required |
| ABS Population | Hardcoded (v0.2) | Manual update | Full ABS API integration in v0.3 |

---

## Fraud Detection Logic (Worker)

The Worker computes a **risk score (0–100)** for each provider:

| Signal | Score Added | Flag |
|--------|------------|------|
| Duplicate phone across multiple ABNs | +30 | `dup-contact` |
| Duplicate email across multiple ABNs | +25 | `dup-contact` |
| Provider postcode has >50 registered providers | +25 | `density` |
| Provider postcode has >30 registered providers | +15 | `density` |
| Registration < 6 months old | +10 | — |
| Multiple ABNs with same prefix (same entity) | +20 | `abn-change` |

**Risk Levels:**
- Critical: 80–100
- High: 60–79
- Medium: 40–59
- Low: 0–39

---

## Roadmap

### v0.3 — Planned
- [ ] Full ABS API integration for population data (replace hardcoded table)
- [ ] NDIS Commission deregistered providers list cross-reference
- [ ] News/media mention scraping for provider names
- [ ] Scheduled Worker cron to refresh and diff daily
- [ ] Email alert when new critical-risk providers are detected

### v0.4 — Planned
- [ ] Suburb GeoJSON overlays on map (SA2 boundaries)
- [ ] PDF export for referral reports
- [ ] ABN batch lookup (upload CSV of ABNs to check)
- [ ] Participant complaint data integration

---

## Reporting Fraud

If this tool identifies suspicious providers, report to:

- **NDIS Fraud Reporting Hotline:** 1800 650 717
- **Email:** fraudreporting@ndis.gov.au
- **Online:** https://www.ndis.gov.au/fraud-reporting
- **AFP:** www.afp.gov.au (for large-scale organised fraud)

---

## Disclaimer

This tool is for research and analysis purposes. All provider data is publicly available via government open data sources. This tool does not make legal determinations — all referrals should be reviewed by appropriate authorities before action is taken.

---

*Built to help protect NDIS participants and the integrity of the Scheme.*
