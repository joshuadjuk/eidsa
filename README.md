# EIDSA - Entra ID Signin Analyzer

EIDSA (Entra ID Signin Analyzer) is a multi-workspace Azure AD / Entra ID sign-in log analyzer. It detects cyber threats, anomalies and attack patterns in Entra ID sign-in and audit logs, either uploaded as JSON exports from the Azure portal or pulled automatically through Microsoft Graph.

## 🌟 Key Features

* **Multi-Workspace Support:** Manage multiple tenants or clients separately, with a cross-tenant overview dashboard on the home screen.
* **Threat Detection Engine:** 25 rules, including Password Spray, Brute Force, Impossible Travel (city-level coordinates), Token Replay, MFA Exhaustion, MFA method downgrade (single-factor or SMS after an Authenticator baseline) and Microsoft Identity Protection risky sign-ins.
* **Audit Log Correlation:** MFA registration after a compromise, risky OAuth consent grants, privileged role assignments and new app credentials, correlated with the sign-in detections.
* **Microsoft Graph Sync:** Pull interactive, non-interactive, service-principal and audit logs per tenant, on demand or on a schedule.
* **Alerting:** Teams, Slack or generic JSON webhook for new high-severity detections, deduplicated across runs.
* **Target User List:** Upload a `.txt` file of UPNs to analyze only those users or to highlight them.
* **IP Enrichment:** ISP, ASN and proxy/VPS/mobile data from ip-api.com, plus an optional AbuseIPDB score and Tor flag.
* **Cross-Workspace IP Correlation:** Finds attacker IPs that hit several of your tenants.
* **Large and Truncated Exports:** Files are read as a stream, so large and truncated portal exports work. Duplicate events across overlapping exports are removed.
* **Visualization & Reporting:** Executive summary, PDF reports, geo map, heatmaps, kill chain, attack graph, a KQL generator for Sentinel, and IOC export as CSV, Sentinel watchlist or STIX 2.1.
* **Triage & Collaboration:** TP/FP labels, notes, comments, a watch list and a shared drift baseline, with login and role-based access.
* **The full list of features is available in** [ROADMAP.md](ROADMAP.md)

## 🚀 Usage

1. **Preparation:** Install Node.js 20 or newer.
2. **Clone the Project:**
   ```bash
   git clone https://github.com/joshuadjuk/eidsa.git
   cd eidsa
   ```
3. **Install Dependencies & Run**
   ```bash
   npm install
   npm start        # production
   npm run dev      # development (auto-reload with nodemon)
   npm test         # unit + API tests
   ```
4. Open http://localhost:3000. On first run you are asked to create the **admin** account.

The server creates `workspaces/`, `uploads/` and `data/` automatically. `data/` holds the user accounts, the encryption key for stored secrets and the IP cache. Keep it private and back it up. If `data/secret.key` is lost, the Graph secrets and webhook URLs must be entered again.

## 👥 Roles

| Role | Can do |
|---|---|
| viewer | Read everything, run analysis, export reports |
| analyst | Everything a viewer can do, plus upload or delete logs, user lists, triage, notes, Graph sync |
| admin | Everything, plus create or delete workspaces, integrations and user management |

## ⚙️ Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | HTTP port |
| `EIDSA_AUTH` | `on` | `off` disables login. Use only for single-user local use. |
| `EIDSA_SECRET_KEY` | *(generated `data/secret.key`)* | Passphrase used to encrypt Graph secrets and webhook URLs at rest |
| `EIDSA_PUBLIC_URL` | — | Link placed in alert messages |
| `EIDSA_HOME` | project folder | Where `workspaces/`, `uploads/` and `data/` live |
| `EIDSA_CACHE_WORKSPACES` | `3` | How many analyzed workspaces stay in server memory |
| `IPAPI_KEY` | — | ip-api.com Pro key. Enrichment then uses HTTPS. Without it the free endpoint uses plain HTTP. |
| `ABUSEIPDB_KEY` | — | Adds the AbuseIPDB confidence score and Tor flag to IP enrichment |
| `ENRICH_PROVIDER` | — | `none` turns off all outbound IP lookups |
| `GRAPH_MAX_EVENTS` | `200000` | Maximum events pulled per stream in each Graph sync |

Run EIDSA behind HTTPS (reverse proxy) whenever it is reachable by anyone other than you. The session cookie is marked `Secure` automatically when the proxy sends `X-Forwarded-Proto: https`.

## ☁️ Microsoft Graph setup (per tenant)

1. In the customer tenant, go to Entra ID → App registrations → New registration.
2. Under API permissions, add the **Application** permissions `AuditLog.Read.All` and `Directory.Read.All`, then grant admin consent.
3. Under Certificates & secrets, create a new client secret.
4. In EIDSA, open the workspace → **Integrations**. Enter the tenant ID, client ID and secret, then click **Save & test connection**.
5. Choose the log streams and an optional auto-sync interval. **Sync** pulls new logs and analyzes them. The first sync covers the configured number of days. Later syncs are incremental.

Sign-in logs via Graph require Entra ID P1 or P2 in the customer tenant.

## 📄 Supported files

* Sign-in logs exported from the portal as JSON (interactive, non-interactive, service principal). Managed-identity sign-ins are skipped.
* Directory audit logs exported as JSON, detected automatically.
* Graph API responses (`{ "value": [...] }`) and plain arrays.
* Target user list: `.txt` with one userPrincipalName per line. Commas, semicolons and `#` comments are allowed.
