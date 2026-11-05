# EIDSA — Feature Roadmap

---

## Sudah Diimplementasi

- [x] Detection: Password Spray, Brute Force, Impossible Travel, Foreign Login
- [x] Detection: Admin Tool Abuse, Legacy Auth (IMAP/POP3/SMTP/EAS), MFA Exhaustion
- [x] Detection: Conditional Access Gap (CA_GAP)
- [x] Detection: Token Replay / Session Hijack
- [x] Detection: Account Enumeration (error 50034)
- [x] Detection: Service Principal Anomaly
- [x] Detection: Time-of-Day Anomaly (P10–P90 window)
- [x] Detection: First-Seen Country (sukses dari negara baru)
- [x] Detection: Concurrent Sessions (2+ negara dalam 5 menit)
- [x] Detection: Rare App Access (akses app asing dari luar home country)
- [x] Detection: Credential Stuffing (IP sama target 8+ user berbeda dalam 24h window)
- [x] Detection: Device Fingerprint Anomaly (User-Agent baru + sukses dari luar negeri)
- [x] Detection: OAuth Consent Phishing (first-ever app access dari foreign IP, T1528)
- [x] Detection: Distributed Brute Force (10+ IP berbeda terhadap 1 user dalam 1 jam)
- [x] Detection: MFA Method Downgrade (sign-in single-factor setelah baseline ≥10 sign-in dengan ≥70% MFA)
- [x] Target User List — upload .txt (1 UPN per baris), switch "Filtered users / All logs" untuk membatasi analisis ke user tersebut
- [x] Leaked Credential Cross-Match — upload breach list, flag user yang cocok, lokal
- [x] Kill Chain Coverage Matrix — MITRE tactic grid per user, klik cell → highlight detection cards
- [x] Attack Velocity Timeline — events-per-15min chart untuk top 5 foreign attacking IPs
- [x] KQL Query Generator — per detection card, generate Sentinel/Log Analytics KQL + copy clipboard
- [x] Incident Summary Export — focused per-user PDF: detections + MITRE + IOCs + recommendations
- [x] Executive Summary Dashboard — PDF 1 halaman A4 landscape untuk manajemen: risk, top threats, trend 7 hari
- [x] Session Replay Export — export chronological log-style events per user, dark terminal theme
- [x] Watch List — pin user sebagai high-priority (⭐), selalu muncul di atas risk cards
- [x] Quick Copy IOC Buttons — klik chip IP/user di detection card & IP pivot → copy ke clipboard
- [x] Bulk Triage — checkbox di detection cards, batch mark TP/FP/INV
- [x] Detection Comment / Evidence — komentar investigasi per detection card, disimpan di workspace
- [x] MITRE ATT&CK badge per detection card (klik → attack.mitre.org)
- [x] Detection Triage — label TP / FP / Investigating, FP otomatis di-suppress
- [x] User Investigation Notes — textarea per user, disimpan di workspace meta
- [x] Detection Rule Tuning per Workspace — threshold custom (spray window, brute attempts, dll)
- [x] IP Pivot Panel — klik IP → panel: enrichment, users targeted, detections, event log
- [x] NonInteractive sign-in log support
- [x] Multi-workspace support
- [x] Cross-workspace IP correlation
- [x] IP Reputation enrichment (ip-api.com — ISP / PROXY / VPS / MOBILE)
- [x] Geo map (Leaflet, dark/light tiles)
- [x] Charts: events over time, top countries, error breakdown, app types
- [x] Login Heatmap (7 hari × 24 jam SVG grid — all events + failed only)
- [x] ASN / ISP Clustering (bar chart by ISP dari ip-api.com)
- [x] Tenant Health Score (4-metric gauge: CA coverage, legacy auth, foreign success, MFA)
- [x] Attack Graph (SVG flow: Attacker IPs → Targeted Users → Detections)
- [x] User Timeline panel + drill-down (detections di atas, pagination)
- [x] IOC Search (global — IP, user, country)
- [x] Date range filter (events table)
- [x] Trusted IP whitelist (exact, prefix, CIDR)
- [x] Trusted Countries whitelist per workspace
- [x] Cache hasil analisis (localStorage)
- [x] Export PDF report
- [x] Dark/light theme toggle
- [x] Keyboard shortcut panel (`?` key)
- [x] Duplicate file detection
- [x] Timeline Swimlane
- [x] Sankey Flow Diagram — Visualisasi alur Country
- [x] **Country × App Heat Matrix** — Grid 2D: baris=negara, kolom=app, warna=success ratio & volume. Sticky row label, hover tooltip.
- [x] **Detection Sparklines** — Mini SVG 7-hari per detection card, keliatan tren serangan naik/turun tanpa buka tab lain.
- [x] **User Risk Radar Chart** — Spider chart 6 sumbu (Geo, Auth Fail, Spray/Brute, Legacy/MFA, Device/Travel, Persistence)


## Batch November 2026

**Akurasi deteksi**
- [x] Interrupt (50074/50076/KMSI/password-change) tidak lagi dihitung sebagai failed attempt
- [x] Impossible Travel pakai `geoCoordinates` (level kota) + fallback centroid ~130 negara, min. jarak 300 km, speed tunable
- [x] Time-of-Day pakai timezone workspace (default dari home country)
- [x] Token Replay: grouping per ASN / prefix /16 / /48, pengecualian dual-stack IPv4+IPv6
- [x] Rule berbasis window melaporkan setiap kampanye (bukan hanya yang pertama) + cakupan penuh kampanye
- [x] MFA Downgrade berbasis `authenticationDetails` (single-factor atau SMS/voice setelah baseline Authenticator/FIDO)
- [x] Detection: Entra Risky Sign-in (Identity Protection riskLevel / riskState)

**Audit logs**
- [x] Detection: MFA registration after compromise, OAuth consent grant (scope berisiko), privileged role assignment, app credential added — dikorelasikan dengan deteksi sign-in

**Data & performa**
- [x] Streaming JSON parser (normalisasi on-the-fly, recovery file terpotong, filter managedIdentity per event)
- [x] Deduplikasi event by id lintas file
- [x] Sliding window O(n), sort sekali per analisis
- [x] Cache server LRU + TTL, cache key ikut setting workspace (edit trusted IP langsung berlaku)
- [x] Cache hasil analisis di browser pindah ke IndexedDB
- [x] Atomic write metadata workspace

**Platform**
- [x] Login + RBAC (viewer / analyst / admin), user management, rate-limit login
- [x] Microsoft Graph pull (interactive, non-interactive, service principal, audit) + auto-sync terjadwal + retention
- [x] Alert webhook (Teams / Slack / generic) dengan dedup
- [x] Secret (Graph client secret, webhook URL) terenkripsi AES-256-GCM di disk
- [x] Cross-tenant overview dashboard
- [x] Target user list: mode All / Highlight / Filtered
- [x] Drift baseline disimpan di server (shared tim)
- [x] IOC export: Sentinel watchlist CSV + STIX 2.1
- [x] IP enrichment via HTTPS (IPAPI_KEY) + AbuseIPDB opsional + opsi matikan enrichment
- [x] Frontend dipecah jadi modul (`public/js/`), unit + API test (`npm test`)

## Berikutnya

- [ ] Beberapa user list bernama per workspace (VIP, Admin, Vendor)
- [ ] Integrasi ticketing (ServiceNow / Jira)
- [ ] Unified Audit Log (inbox rule / BEC)
- [ ] GeoIP/ASN database lokal (MaxMind) agar enrichment tanpa layanan eksternal
