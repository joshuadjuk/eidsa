# EIDSA — Panduan Konversi ke PPTX + Speaker Notes
> Gunakan file ini sebagai prompt untuk Claude AI agar menghasilkan file PPTX siap presentasi.

---

## CARA PAKAI

1. Buka [claude.ai](https://claude.ai) atau Claude API
2. Paste **seluruh isi file ini** sebagai pesan pertama
3. Claude akan menghasilkan **script Python (python-pptx)** yang menghasilkan file `.pptx`
4. Jalankan script → buka `EIDSA_Presentation.pptx` di PowerPoint / Google Slides

---

## PROMPT UTAMA — KONVERSI KE PPTX

```
Kamu adalah expert Python developer dan presentation designer.

Saya punya presentasi HTML (15 slide) yang perlu dikonversi menjadi file PPTX menggunakan library python-pptx. 

Tugas kamu:
1. Buat script Python lengkap menggunakan `python-pptx` yang menghasilkan file `EIDSA_Presentation.pptx`
2. Setiap slide harus mengandung konten dan layout yang sesuai dengan deskripsi di bawah
3. Setiap slide HARUS menyertakan **speaker notes** (notes pane di PowerPoint) sesuai teks yang saya berikan
4. Gunakan skema warna dark (background #080d14, teks putih, aksen biru #0078d4) agar konsisten dengan desain aslinya
5. Untuk tabel dan list, gunakan formatting yang rapi dan mudah dibaca
6. Tambahkan slide numbering (misal "01 / 15") di pojok kanan atas setiap slide kecuali cover

Spesifikasi teknis:
- Ukuran slide: Widescreen 16:9 (13.33 × 7.5 inch)
- Font utama: Segoe UI (fallback: Calibri)
- Background: warna gelap #0D1117 atau gunakan solid fill dark navy
- Heading: bold, warna putih atau biru muda
- Body text: abu-abu terang (#C9D1D9)
- Aksen/highlight: biru (#0078D4), merah (#EF4444), kuning (#F59E0B), hijau (#10B981)
- Untuk tabel: header row dark dengan teks putih, alternating row color
- Semua speaker notes harus masuk ke notes pane (tidak ditampilkan di slide)

Konten slide dan speaker notes ada di bawah ini. Generate script Python yang lengkap dan bisa langsung dijalankan.
```

---

## KONTEN SLIDE + SPEAKER NOTES

---

### SLIDE 01 — COVER

**Layout:** Center-aligned cover slide

**Konten:**
- Badge kecil (atas): `Sigma Graduate Program · Microsoft Consultant · TelkomSigma`
- Judul utama besar: `EIDSA`
- Subjudul: `Entra ID Signin Analyzer`
- Deskripsi: `Solusi Monitoring Keamanan Multi-Tenant Berbasis Microsoft Entra ID untuk Managed Service Provider`
- Meta row (4 kolom):
  - Presented by: Joshua Djuk
  - Program: Sigma Graduate Program
  - Role: Microsoft Consultant
  - Periode OJT: Nov 2025 – Mei 2026

**Speaker Notes:**
```
Selamat pagi / siang Bapak/Ibu. Perkenalkan saya Joshua Djuk, peserta Sigma Graduate Program track Microsoft Consultant di TelkomSigma.

Hari ini saya akan mempresentasikan EIDSA — Entra ID Signin Analyzer, sebuah tool monitoring keamanan identitas yang saya bangun selama masa OJT dari November 2025 hingga Mei 2026.

EIDSA dirancang khusus untuk menjawab tantangan nyata yang dihadapi TelkomSigma sebagai Managed Service Provider yang mengelola keamanan identitas dari banyak tenant klien sekaligus.

Mari kita mulai.
```

---

### SLIDE 02 — AGENDA

**Layout:** 2 kolom, 5 item per kolom

**Konten:**
Agenda (10 item):
1. Problem Statement — Tantangan monitoring multi-tenant di TelkomSigma
2. Gap Analysis — Keterbatasan native Entra ID untuk MSP
3. Solusi: EIDSA — Overview fitur & detection engine
4. Arsitektur Teknis — Stack, komponen, deployment
5. Head-to-Head Comparison — EIDSA vs Entra ID Native vs Sentinel
6. Business Value & ROI — Cost savings & value proposition
7. Demo PoC — Screenshot key features & live demo
8. Roadmap Implementasi — 4-phase plan menuju production
9. Risk & Mitigasi — Risiko teknis, bisnis, dan mitigasinya
10. Kesimpulan & Next Steps — Rekomendasi & call to action

**Speaker Notes:**
```
Presentasi ini akan saya bagi menjadi 10 bagian utama yang mengikuti alur berpikir: dari masalah, ke solusi, ke bukti, ke rencana ke depan.

Kita mulai dengan problem statement — memahami dulu mengapa tool seperti EIDSA dibutuhkan. Kemudian saya akan tunjukkan gap di native Entra ID, lalu memperkenalkan EIDSA sebagai solusinya.

Di bagian tengah, kita akan melihat arsitektur teknis dan perbandingan head-to-head dengan solusi Microsoft yang ada. Lalu saya akan tunjukkan business case dan demo langsung.

Di bagian akhir, saya paparkan roadmap 4 fase dan analisis risiko sebelum menutup dengan rekomendasi konkret.

Total durasi sekitar 20 menit, dan saya buka sesi tanya jawab di akhir.
```

---

### SLIDE 03 — PROBLEM STATEMENT

**Layout:** 2 kolom — pain points (kiri) + dampak bisnis (kanan)

**Konten:**
Judul: `TelkomSigma Mengelola Ratusan Tenant — Tapi Visibilitasnya Nol`

Pain Points (kiri, 3 card):
- 🏢 **Multi-Tenant Blind Spot** — Monitoring sign-in harus dilakukan satu-per-satu di portal Azure yang berbeda. Ancaman lintas tenant tidak terdeteksi.
- 💸 **Biaya Lisensi Tidak Terjangkau** — Fitur deteksi lanjutan hanya tersedia di Entra ID P2 ($6/user/bulan) + Sentinel. 10 tenant × 500 user = $30.000+/bulan.
- 🐌 **Investigasi Manual & Lambat** — SOC analyst harus export log JSON manual, buka Excel/KQL, buat laporan sendiri. MTTR rata-rata 4–8 jam per insiden.

Dampak Bisnis (kanan, 4 stat):
- 4–8 jam — rata-rata MTTR identity attack
- $30K+ — biaya lisensi/bulan (10 tenant × 500 user)
- 0% — visibilitas lintas tenant
- Manual — reporting & investigasi

Pertanyaan Inti (bottom):
> "Bagaimana TelkomSigma dapat memonitor keamanan sign-in Entra ID dari seluruh tenant klien secara terpusat, dengan biaya minimal, tanpa bergantung pada lisensi premium?"

**Speaker Notes:**
```
TelkomSigma saat ini menghadapi tiga masalah besar dalam monitoring keamanan identitas klien.

Pertama, blind spot multi-tenant. Sebagai MSP, kita mengelola puluhan tenant, tapi setiap tenant punya portal Azure sendiri. Tidak ada single view yang menampilkan semua tenant sekaligus. Kalau ada serangan yang sama menyerang dua tenant berbeda, kita tidak akan tahu sampai sudah terlambat.

Kedua, biaya lisensi yang tidak realistis. Fitur deteksi yang benar-benar berguna — seperti risk-based conditional access dan identity protection — hanya tersedia di Entra ID P2. Kalau kita kalkulasikan untuk 10 tenant klien dengan 500 user masing-masing, biayanya bisa mencapai $30.000 per bulan. Ini tidak sustainable untuk semua segmen klien kita.

Ketiga, investigasi yang masih manual. Saat ada insiden, analyst harus download log JSON dari portal, buka di Excel atau KQL, analisis manual, lalu buat laporan. Proses ini bisa memakan waktu 4 sampai 8 jam per insiden.

Pertanyaan yang menjadi landasan proyek ini: bagaimana kita bisa memonitor semua tenant secara terpusat dengan biaya minimal?
```

---

### SLIDE 04 — GAP ANALYSIS

**Layout:** 2 kolom — tidak tersedia (kiri) + perlu premium (kanan)

**Konten:**
Judul: `Apa yang Tidak Bisa Dilakukan Native Entra ID?`

Kolom kiri — Tidak tersedia sama sekali:
- ❌ Multi-Tenant Unified Dashboard — harus switch antar portal per tenant
- ❌ Custom Detection Rules — password spray, brute force, MFA fatigue hanya di P2
- ❌ Kill Chain & Attack Graph — visualisasi MITRE ATT&CK tidak ada di portal standar
- ❌ Tunable Thresholds — tidak ada konfigurasi per-tenant untuk sensitivitas deteksi
- ❌ Offline / Air-gapped Analysis — log tidak bisa dianalisis tanpa koneksi cloud

Kolom kanan — Perlu lisensi premium:
- ⚠️ Identity Risk Detection — perlu Entra ID P2 ($6/user/bln)
- ⚠️ SIEM & Log Correlation — perlu Microsoft Sentinel ($200–$2.000/bln/tenant)
- ⚠️ Geolocation Alerting — Named Locations di P1, tapi tidak ada interactive map

Kesimpulan (bottom): Fitur deteksi advanced tersedia tapi memerlukan biaya yang tidak realistis untuk SMB.

**Speaker Notes:**
```
Sebelum memperkenalkan solusi, saya ingin jujur tentang apa yang sudah bisa dilakukan Entra ID secara native — dan apa yang tidak.

Ada lima kapabilitas yang sama sekali tidak tersedia tanpa lisensi premium: multi-tenant dashboard, custom detection rules, kill chain visualization, tunable thresholds, dan offline analysis. Ini bukan fitur minor — ini adalah kebutuhan inti untuk monitoring yang efektif di environment MSP.

Di sisi lain, ada fitur yang tersedia tapi memerlukan lisensi tambahan yang mahal. Identity Protection ada di P2, SIEM correlation butuh Sentinel yang bisa sangat mahal tergantung volume data.

Kesimpulannya: Microsoft sebenarnya punya ekosistem yang lengkap — tapi harganya tidak realistis untuk semua klien. Inilah gap yang diisi EIDSA.
```

---

### SLIDE 05 — SOLUSI: EIDSA

**Layout:** 2 kolom — definisi + stats (kiri), feature grid (kanan)

**Konten:**
Judul: `EIDSA — Security Analytics Platform untuk MSP`

Definisi:
> EIDSA adalah web-based security analytics tool yang menganalisis log sign-in Entra ID dari multiple tenant secara terpusat, mendeteksi pola serangan identity, dan menghasilkan actionable insights — tanpa memerlukan lisensi Entra ID P2 atau Microsoft Sentinel.

Stats (4 kotak):
- 8+ | Detection Rules
- ∞ | Tenant Workspaces
- 10+ | Visualisasi Views
- 100% | Data On-Premise

Fitur Grid (8 item, 2 kolom):
- 🏢 Multi-Tenant Workspace — satu dashboard untuk semua tenant klien
- 🔍 Smart Detection Engine — 8 custom rules dengan threshold yang bisa diatur
- ⛓️ Kill Chain Mapping — visualisasi MITRE ATT&CK per user
- 🗺️ Geolocation Attack Map — interactive map login dari seluruh dunia
- 👤 User Risk Profiling — scoring CRITICAL / HIGH / MEDIUM / LOW
- 📊 Advanced Analytics — attack graph, velocity, swimlane, sankey
- 📓 Playbook Integration — konteks investigasi per workspace
- 📄 PDF Report Export — laporan profesional untuk klien

**Speaker Notes:**
```
EIDSA adalah jawaban langsung dari gap yang baru saja saya identifikasi.

Secara definisi, EIDSA adalah tool analitik berbasis web yang menganalisis log sign-in Entra ID dari banyak tenant sekaligus, mendeteksi pola serangan, dan menghasilkan insight yang actionable — tanpa memerlukan lisensi P2 atau Sentinel.

Kunci differentiatornya ada di empat angka ini: 8 lebih detection rules yang semuanya tunable, workspace yang tidak terbatas jumlahnya, 10 lebih jenis visualisasi, dan 100% data on-premise — tidak ada data klien yang keluar dari environment mereka sendiri.

Delapan fitur utamanya mencakup semua yang tadi saya tunjukkan tidak ada di native Entra ID: multi-tenant workspace, custom detection, kill chain, geolocation map, risk profiling, advanced analytics, playbook, dan PDF report.

Ini bukan mockup — semua fitur ini sudah berjalan dan bisa di-demo langsung hari ini.
```

---

### SLIDE 06 — DETECTION ENGINE

**Layout:** 2 kolom, 4 rule per kolom + catatan bawah

**Konten:**
Judul: `8 Custom Detection Rules — Tunable Per Tenant`

Tabel rules:
| Rule | Severity | Deskripsi |
|------|----------|-----------|
| Password Spray | HIGH | Satu IP mencoba banyak akun dalam window singkat. Threshold: ≥5 user / 10 menit |
| Brute Force | HIGH | Banyak percobaan login gagal ke satu akun. Threshold: ≥10 percobaan |
| MFA Fatigue / Exhaustion | CRITICAL | Banyak MFA prompt berturut-turut — teknik bypass modern. Threshold: ≥5 prompt |
| Impossible Travel | CRITICAL | Login dari dua negara berbeda dalam waktu yang fisik tidak mungkin |
| Foreign Login | HIGH | Login sukses dari negara di luar trusted countries list per workspace |
| Credential Stuffing | HIGH | Pola login sukses setelah banyak gagal — indikasi credential breach |
| Off-Hours Access | MEDIUM | Login di jam tidak wajar dari IP tidak dikenal |
| User Enumeration | MEDIUM | Satu IP mencoba banyak username berbeda — indikasi reconnaissance |

Catatan: ⚙️ Semua threshold bisa dikonfigurasi per workspace

**Speaker Notes:**
```
Inti dari EIDSA adalah detection engine dengan 8 rule yang saya tulis sendiri, masing-masing tunable per workspace.

Dua rule dengan severity CRITICAL yang paling kritis: MFA Fatigue — di mana attacker sudah punya password dan terus mengirim push notification MFA berharap user tidak sengaja approve — dan Impossible Travel, yang mendeteksi login dari dua negara dalam waktu yang secara fisik tidak mungkin ditempuh.

Rule HIGH mencakup Password Spray yang merupakan metode paling umum digunakan botnet global saat ini, Brute Force, Foreign Login, dan Credential Stuffing.

Yang menjadi keunggulan utama: semua threshold ini bisa diatur per workspace. Klien besar dengan banyak remote worker mungkin butuh threshold lebih tinggi untuk foreign login, sementara klien kecil yang highly regulated mungkin butuh sensitivitas maksimum.

Ini yang tidak bisa dilakukan Entra ID native tanpa P2 — konfigurasi sensitivitas per tenant.
```

---

### SLIDE 07 — ARSITEKTUR TEKNIS

**Layout:** 2 kolom — stack diagram (kiri), reasoning + tech logos (kanan)

**Konten:**
Judul: `Stack & Deployment Architecture`

Stack (kiri, 5 layer):
1. Data Source → Microsoft Entra ID Sign-in Logs (JSON)
2. Backend / Analysis Engine → Node.js + Express.js (REST API)
3. Storage → File-based JSON Workspace Store
4. Frontend → Vanilla JS + Chart.js + Leaflet.js
5. Deployment → Docker / Azure App Service / On-Premise

Kenapa Stack Ini? (kanan):
- ✅ Zero External Dependencies — tidak butuh cloud service atau lisensi tambahan
- ✅ Azure-Ready — deploy ke Azure App Service dalam hitungan menit
- ✅ Data Sovereignty — log klien tidak pernah keluar dari environment
- ✅ Lightweight & Fast — analisis 100K+ events dalam hitungan detik

Tech logos (3 kotak): Node.js · Chart.js · Leaflet.js

**Speaker Notes:**
```
Dari sisi arsitektur, saya memilih stack yang sederhana tapi powerful.

Alur datanya straightforward: log JSON dari Entra ID diupload ke EIDSA, diproses oleh Node.js backend, disimpan sebagai file JSON, ditampilkan di frontend menggunakan Vanilla JS dengan Chart.js untuk chart dan Leaflet untuk peta.

Ada empat alasan mengapa saya memilih stack ini. Pertama, zero external dependencies — tidak ada database eksternal, tidak ada cloud service berbayar. Kedua, Azure-ready — bisa di-deploy ke Azure App Service dalam hitungan menit dengan satu command Docker. Ketiga, data sovereignty — log sign-in adalah data sensitif klien, dan dengan stack ini, data tidak pernah meninggalkan environment mereka sendiri. Ini critical untuk klien di sektor pemerintahan dan keuangan. Keempat, ringan dan cepat — di pengujian saya, 100.000 events bisa dianalisis dalam kurang dari 3 detik.

Dengan deployment ke Azure App Service B1, biaya operasionalnya hanya sekitar $50 per bulan untuk semua tenant.
```

---

### SLIDE 08 — HEAD-TO-HEAD COMPARISON

**Layout:** Full-width comparison table

**Konten:**
Judul: `EIDSA vs Entra ID Native vs Microsoft Sentinel`

Tabel perbandingan (13 baris + baris biaya):

| Kapabilitas | Entra ID Free/P1 | EIDSA | Entra P2 + Sentinel |
|-------------|:---:|:---:|:---:|
| Multi-Tenant Unified Dashboard | ✗ | ✓ | Manual setup |
| Tanpa Lisensi Premium | ✓ | ✓ | ✗ |
| Password Spray Detection | ✗ | ✓ | ✓ |
| MFA Fatigue Detection | ✗ | ✓ | ✓ |
| Impossible Travel Detection | ✗ | ✓ | ✓ |
| Kill Chain / MITRE Mapping | ✗ | ✓ | ✓ |
| Interactive Geolocation Map | ✗ | ✓ | Basic only |
| Tunable Detection Thresholds | ✗ | ✓ | KQL only |
| User Risk Scoring | ✗ | ✓ | ✓ |
| Offline / Air-gapped Analysis | ✗ | ✓ | ✗ |
| Custom Playbook per Tenant | ✗ | ✓ | Complex |
| PDF Report Export | ✗ | ✓ | Manual |
| **Biaya (10 tenant × 500 users)** | ~$0 tapi terbatas | **~$50/bln** | **$30.000+/bln** |

**Speaker Notes:**
```
Ini adalah slide yang mungkin paling penting untuk keputusan bisnis.

Saya bandingkan tiga opsi: Entra ID Free/P1 yang sudah dimiliki semua klien, EIDSA yang kita bangun ini, dan Entra ID P2 plus Sentinel yang merupakan solusi premium Microsoft.

Hasilnya cukup jelas. Entra ID Free/P1 tidak memiliki hampir semua kapabilitas yang dibutuhkan untuk deteksi ancaman yang serius. P2 plus Sentinel memiliki segalanya, tapi dengan biaya $30.000 per bulan untuk skenario 10 tenant 500 user.

EIDSA memberikan paritas kapabilitas dengan P2 plus Sentinel untuk mayoritas use case MSP, dengan biaya hosting $50 per bulan. Bedanya ada di beberapa area: Sentinel unggul di AI-native detection dan real-time streaming, sementara EIDSA unggul di tunable thresholds dan offline analysis.

Satu hal yang perlu saya tegaskan: EIDSA bukan pengganti Sentinel untuk klien enterprise besar. EIDSA adalah solusi untuk gap di segmen SMB dan MSP yang tidak mampu atau tidak perlu Sentinel.
```

---

### SLIDE 09 — BUSINESS VALUE & ROI

**Layout:** 2 kolom — cost comparison (kiri), operational value (kanan) + value prop banner (bawah)

**Konten:**
Judul: `Dampak Nyata untuk TelkomSigma & Klien`

Perbandingan Biaya (kiri):
- 🔴 Entra ID P2 (5.000 user): $30.000/bln
- 🔴 Microsoft Sentinel (10 tenant): $2.000–$20.000/bln
- 🟢 EIDSA (Azure App Service B1): ~$50/bln
- Highlight: **$49.950+ penghematan/bulan (99.9% cost reduction)**

Operational Value (kanan):
- ⚡ MTTR Turun ≥60% — dari 4–8 jam ke 1–2 jam
- 🎯 SOC Efficiency — 1 analyst monitoring 10+ tenant vs sebelumnya 2–3
- 💼 New Revenue Stream — "Identity Security Monitoring as a Service"
- 🏆 Competitive Advantage — diferensiasi dari kompetitor MSP manual

Value Proposition (bawah):
> EIDSA memposisikan TelkomSigma sebagai MSP yang mampu memberikan enterprise-grade identity security monitoring kepada semua segmen klien — termasuk SMB yang tidak mampu membeli lisensi Entra ID P2.

**Speaker Notes:**
```
Sekarang kita bicara angka bisnis yang konkret.

Dari sisi biaya, perbandingannya sangat signifikan. Untuk skenario 10 tenant dengan 500 user masing-masing, biaya P2 saja sudah $30.000 per bulan. Kalau tambah Sentinel, bisa sampai $50.000. EIDSA hanya butuh $50 per bulan untuk hosting.

Penghematan potensinya di atas $49.000 per bulan, atau lebih dari 99% cost reduction. Tentu ini asumsi semua tenant dalam skenario yang sama — tapi bahkan 10-20% dari angka ini sudah sangat material.

Tapi lebih dari sekedar penghematan, ada tiga nilai operasional yang saya highlight. Pertama, MTTR turun dari 4-8 jam menjadi 1-2 jam karena semua informasi tersentralisasi dan scoring dilakukan otomatis. Kedua, satu analyst sekarang bisa handle 10 tenant, bukan hanya 2-3. Ketiga, TelkomSigma bisa menawarkan layanan monitoring keamanan identitas sebagai produk premium baru.

Ini bukan hanya penghematan cost — ini adalah pembuka revenue stream baru.
```

---

### SLIDE 10 — POC DEMO

**Layout:** Grid 3×2 feature cards + status bar bawah

**Konten:**
Judul: `PoC Sudah Berjalan — Demo Live`

6 Feature Cards:
- 🏢 Multi-Tenant Workspace — setiap klien punya workspace isolasi dengan konfigurasi & playbook sendiri
- 🔍 Detection Dashboard — risk scoring otomatis, deteksi terkelompok berdasarkan severity & tipe serangan
- ⛓️ Kill Chain Matrix — mapping per user ke MITRE ATT&CK framework, klik cell untuk drill-down
- 🗺️ Geolocation Map — heatmap & markers untuk setiap login event, filter by success/failure
- 👤 User Risk Profile — timeline per-user, triage management, notes, watchlist, dan bulk actions
- 📊 Advanced Charts — attack velocity, sankey flow, country×app matrix, swimlane timeline

Status bar:
✅ PoC Status: Fully Functional — 9 Fitur Baru Ditambahkan Selama OJT

**Speaker Notes:**
```
Ini adalah slide yang paling saya banggakan — karena semua yang saya presentasikan bukan slide teoritis. Ini semua sudah berjalan.

[Tunjukkan demo langsung jika memungkinkan]

Mari saya walk through enam fitur utama yang bisa Anda lihat langsung:

Multi-tenant workspace — cukup klik "New Workspace", masukkan nama tenant, home country, dan trusted countries list. Masing-masing workspace punya konfigurasi dan playbook sendiri.

Detection dashboard — setelah upload log JSON Entra ID, klik "Run Analysis". Dalam hitungan detik, sistem mendeteksi ancaman, memberi risk score per user, dan mengelompokkan deteksi berdasarkan severity.

Kill chain matrix — menampilkan mana stage MITRE ATT&CK yang aktif untuk setiap user. Sangat berguna untuk memahami seberapa jauh attack sudah berkembang.

Dan geolocation map menampilkan secara visual dari mana saja login terjadi di seluruh dunia.

Selain 6 fitur inti ini, selama OJT saya berhasil menambahkan 9 fitur tambahan yang akan saya jelaskan di slide berikutnya.
```

---

### SLIDE 11 — FITUR BARU BATCH 1

**Layout:** Grid 3+2 feature cards dengan color accent

**Konten:**
Judul: `5 Peningkatan Signifikan — Diimplementasikan Selama OJT`

5 Feature Cards:
- 🛡️ **CA Remediation Tab** *(Policy Automation)* — Auto-mapping setiap deteksi ke rekomendasi Conditional Access Policy spesifik. 20 rekomendasi terprioritasi dengan langkah aksi dan tips implementasi.
- ⬇ **IOC Export CSV** *(SIEM Integration)* — Ekspor satu klik semua Indicators of Compromise (IP, user, negara) ke CSV. Langsung import ke firewall, SIEM, atau blocklist.
- 87 **Numeric Risk Score** *(0–100 per User)* — Skor risiko kuantitatif: base score per tier (CRITICAL=72+) + bonus foreign login, tipe deteksi, breadth, geo-spread.
- ⚡ **Attack Campaign Grouping** *(Correlation Engine)* — Algoritma Union-Find mengkorelasi deteksi berbeda menjadi satu campaign berdasarkan shared IP dan shared user.
- 🔥 **Login Activity Heatmap** *(Temporal Analysis)* — Visualisasi 24 jam × 7 hari intensitas login per slot waktu.

**Speaker Notes:**
```
Selama OJT, saya tidak hanya membangun fitur core — saya juga terus mengembangkan EIDSA dengan fitur-fitur yang meningkatkan nilai praktisnya.

Batch pertama terdiri dari 5 fitur yang berfokus pada detection dan response.

CA Remediation adalah fitur yang paling langsung actionable. Ketika detection muncul — misalnya Password Spray — sistem otomatis merekomendasikan Conditional Access policy mana yang harus diaktifkan, lengkap dengan langkah-langkah implementasinya. Analyst tidak perlu tahu detail teknis Azure AD untuk bisa ambil tindakan.

IOC Export adalah jembatan antara EIDSA dan infrastruktur keamanan yang sudah ada. Semua IP attacker, akun yang dikompromisi, dan negara asal serangan bisa diexport ke CSV dalam satu klik, siap diimport ke firewall atau SIEM.

Numeric Risk Score mengubah label CRITICAL/HIGH/MEDIUM menjadi angka 0-100 yang bisa digunakan untuk prioritisasi yang lebih presisi. Skor 95 lebih mendesak dari skor 73, meskipun keduanya CRITICAL.

Attack Campaign Grouping menggunakan algoritma Union-Find untuk menghubungkan deteksi yang secara surface terlihat terpisah tapi sebenarnya berasal dari satu kampanye serangan yang sama.

Dan Login Heatmap membantu kita melihat pattern temporal — serangan botnet biasanya terlihat jelas sebagai spike di jam-jam tertentu.
```

---

### SLIDE 12 — FITUR LANJUTAN BATCH 2

**Layout:** Grid 2×2 feature cards

**Konten:**
Judul: `4 Peningkatan Tambahan — Investigasi & Operasional`

4 Feature Cards:
- ⚡ **Detection Explainer** *(Why Did This Fire?)* — Setiap detection card menampilkan penjelasan terstruktur: trigger logic, evidence chips (IP, waktu, jumlah attempt), konteks MITRE ATT&CK. Tidak perlu baca raw JSON.
- 🕵️ **Threat Intel IP Lookup** *(Local Static Enrichment)* — IP attacking di-tag otomatis: Tor exit nodes, named VPN providers (Mullvad, NordVPN, ProtonVPN), bulletproof hosting (M247, FranTech, Sharktech).
- 📨 **Weekly Digest Export** *(Shareable HTML Brief)* — Generate laporan HTML lengkap: KPI summary, user risk cards, top attacking countries, top threats, CA hits, campaign summary. Satu klik, siap kirim email.
- 📊 **Baseline Drift Alert** *(Trend Comparison)* — Dashboard menampilkan delta vs baseline: "↑ +340% Foreign Failed", "↑ +2 Critical Accounts". Lihat langsung apakah situasi memburuk atau membaik.

**Speaker Notes:**
```
Batch kedua berfokus pada dua hal: membantu analyst memahami alert lebih cepat, dan memudahkan komunikasi dengan klien.

Detection Explainer menjawab pertanyaan yang paling sering ditanyakan analyst junior: "mengapa alert ini muncul?" Sekarang setiap detection menampilkan penjelasan plain-text yang menjelaskan kondisi apa yang terpenuhi, evidence apa yang ditemukan, dan relevansinya ke MITRE ATT&CK. Tidak perlu decode raw JSON lagi.

Threat Intel IP Lookup adalah enrichment berbasis database lokal. Kalau IP attacker ternyata berasal dari Mullvad VPN atau jaringan M247 yang dikenal sebagai bulletproof hoster, informasi ini langsung muncul sebagai badge merah di setiap tempat IP itu ditampilkan. Tidak butuh API eksternal, zero latency.

Weekly Digest Export adalah fitur untuk komunikasi klien. Analyst bisa generate satu file HTML per workspace yang bisa langsung dikirim via email ke klien — berisi semua informasi yang relevan dalam format yang bersih dan mudah dibaca manajemen non-teknis.

Dan Baseline Drift Alert membandingkan run analisis sekarang dengan baseline sebelumnya. Kalau tiba-tiba ada lonjakan 300% foreign attempts, itu langsung terlihat di dashboard tanpa harus compare angka secara manual.
```

---

### SLIDE 13 — ROADMAP

**Layout:** 2 kolom phase diagram + progress bar bawah

**Konten:**
Judul: `4-Phase Implementation Roadmap`

Phase 1 — PoC ✅ (Nov 2025 – Mei 2026):
Core detection engine, multi-tenant workspace, 10+ visualisasi, kill chain, geolocation map, PDF export, user risk profiling, tunable rules, CA Remediation, IOC Export, numeric risk score, attack campaign grouping, login heatmap, detection explainer, threat intel IP lookup, weekly digest export, baseline drift alert.

Phase 2 — Production Ready (Q3 2026, Jul–Sep):
Integrasi langsung ke Microsoft Graph API (real-time streaming), Azure AD multi-tenant app registration, autentikasi SSO, role-based access untuk tim SOC.

Phase 3 — AI Enhancement (Q4 2026, Okt–Des):
Integrasi Azure OpenAI untuk AI-assisted investigation, natural language query atas log, automated incident summary, dan anomaly detection berbasis ML.

Phase 4 — Platform Scale (2027):
Integrasi Microsoft Sentinel bidirectional, Microsoft Teams alerting, REST API untuk SOAR, Azure Marketplace solution.

Progress indicators:
✅ Core PoC — Selesai | 🔄 Graph API — Q3 2026 | 🤖 Azure OpenAI — Q4 2026 | 🚀 Marketplace — 2027

**Speaker Notes:**
```
EIDSA saat ini ada di akhir Phase 1. Semua yang saya demonstrasikan tadi adalah deliverable Phase 1 yang sudah selesai.

Roadmap ke depan dirancang incremental — setiap phase membangun di atas yang sebelumnya.

Phase 2 di Q3 2026 adalah tentang production-readiness. Dari upload manual ke real-time streaming via Microsoft Graph API, dari single user ke multi-user dengan SSO dan role-based access. Ini yang mengubah EIDSA dari proof-of-concept menjadi produk yang bisa digunakan tim SOC secara rutin.

Phase 3 di Q4 2026 mengintegrasikan Azure OpenAI. Bayangkan analyst bisa bertanya dalam bahasa natural: "tampilkan semua login mencurigakan dari user HR bulan lalu" — dan sistem langsung merespons. Ini yang mengubah EIDSA dari tool analitik menjadi AI-powered investigation assistant.

Phase 4 di 2027 adalah tentang scale dan ekosistem: integrasi Sentinel bidirectional, Teams alerting, dan packaging sebagai Azure Marketplace solution. Pada tahap ini EIDSA bisa menjadi produk yang dijual ke MSP lain di luar TelkomSigma.

Timeline ini realistis dan sudah saya desain berdasarkan dependensi teknis yang ada.
```

---

### SLIDE 14 — RISK & MITIGASI

**Layout:** Full-width table

**Konten:**
Judul: `Identifikasi Risiko & Strategi Mitigasi`

Tabel risiko (5 baris):

| Risiko | Level | Dampak | Mitigasi |
|--------|-------|--------|----------|
| Data Privacy Klien | HIGH | Log sign-in mengandung data sensitif user klien | ✅ Deployment on-premise / private Azure. Data tidak pernah keluar dari environment klien. |
| False Positive Rate | MEDIUM | Alert tidak akurat membuang waktu SOC | ✅ Tunable thresholds per workspace, whitelist trusted IPs/countries, triage workflow. |
| Skalabilitas Storage | MEDIUM | File-based storage tidak optimal untuk volume sangat besar | ✅ Phase 2: migrasi ke Azure Cosmos DB atau Azure SQL. |
| Kompetisi dengan Sentinel | LOW | Klien enterprise mungkin lebih memilih Sentinel | ✅ EIDSA bukan pengganti Sentinel — melengkapi gap untuk SMB & MSP tanpa P2. |
| Log Format Changes | LOW | Microsoft mengubah schema log Entra ID | ✅ Parser modular — update schema di satu file. Phase 2 gunakan Graph API yang lebih stabil. |

**Speaker Notes:**
```
Saya selalu percaya bahwa proposal yang baik harus jujur tentang risikonya.

Risiko terbesar adalah data privacy. Log sign-in mengandung data sensitif — IP address, username, lokasi. Mitigasinya adalah deployment model: EIDSA dirancang untuk di-deploy on-premise atau di private Azure subscription klien. Data tidak pernah meninggalkan environment mereka. Ini bukan sekadar fitur — ini adalah design principle.

False positive adalah risiko operasional yang nyata. Kalau setiap login dari remote worker di-flag sebagai serangan, analyst akan alert fatigue. Mitigasinya adalah tunable thresholds — setiap workspace bisa dikonfigurasi sesuai profil klien — ditambah whitelist dan triage workflow.

Skalabilitas storage memang akan menjadi bottleneck untuk klien dengan volume sangat tinggi. Tapi ini sudah saya antisipasi di Phase 2 dengan rencana migrasi ke Azure SQL atau Cosmos DB.

Untuk kompetisi dengan Sentinel — saya tidak melihat ini sebagai ancaman, tapi sebagai positioning. EIDSA adalah solusi untuk segmen yang Sentinel terlalu mahal. Bukan head-to-head competition.

Dan log format changes adalah risiko jangka panjang yang sudah diantisipasi dengan arsitektur parser yang modular.
```

---

### SLIDE 15 — KESIMPULAN

**Layout:** 2 kolom — 4 pilar (kiri), next steps + closing (kanan)

**Konten:**
Judul: `EIDSA — Dari Inovasi OJT ke Produk TelkomSigma`

4 Pilar (kiri):
- 🟢 **Inovasi & Relevansi** — Solusi orisinal untuk pain point nyata MSP TelkomSigma — monitoring multi-tenant tanpa biaya lisensi premium.
- 🔵 **Kelayakan Teknis** — Stack teknologi proven (Node.js, Azure-ready), arsitektur modular, dan PoC fully functional yang dapat di-demo hari ini.
- 🟡 **Business Case** — Penghematan $49.950+/bulan, MTTR turun 60%, membuka revenue stream baru sebagai premium SOC service.
- 🟣 **Kematangan PoC** — Bukan sekadar mockup. EIDSA fully functional: 8+ detection rules, 10+ views, 9 fitur baru.

Next Steps (kanan):
1. Pilot Internal — Deploy untuk monitoring tenant internal TelkomSigma
2. Client Pilot — 2–3 klien MSP sebagai beta tester
3. Graph API Integration — Phase 2 development
4. Paketkan sebagai Produk — "Identity Security Monitoring as a Service"

Closing statement:
> EIDSA bukan hanya tugas OJT — ini adalah produk yang siap pakai untuk ekosistem Microsoft MSP TelkomSigma.

**Speaker Notes:**
```
Izinkan saya menutup dengan empat poin yang merangkum mengapa EIDSA layak untuk dilanjutkan.

Inovasi dan relevansi: EIDSA bukan adaptasi tool yang sudah ada — ini adalah solusi yang dirancang spesifik untuk pain point nyata yang dihadapi TelkomSigma hari ini. Multi-tenant monitoring tanpa premium license.

Kelayakan teknis: Ini bukan slide deck dengan mockup. EIDSA adalah aplikasi yang berjalan penuh, dibangun dengan stack yang proven dan Azure-ready, bisa di-deploy dalam hitungan jam.

Business case: Penghematan lebih dari $49.000 per bulan dalam skenario baseline. MTTR turun 60%. Dan pembuka revenue stream baru yang sebelumnya tidak ada.

Kematangan PoC: Selama 6 bulan OJT, saya tidak hanya membangun core product — saya menambahkan 9 fitur tambahan yang semuanya sudah berjalan dan bisa di-demo sekarang.

Rekomendasi saya adalah empat langkah konkret: deploy pilot internal dulu di tenant TelkomSigma sendiri, lalu pilih 2-3 klien untuk beta, mulai Phase 2 development, dan paketkan sebagai produk layanan.

EIDSA dimulai sebagai proyek OJT, tapi saya percaya ini memiliki potensi untuk menjadi produk unggulan TelkomSigma di segmen MSP Microsoft.

Terima kasih. Saya buka sesi tanya jawab.
```

---

## CATATAN TEKNIS UNTUK SCRIPT PYTHON

Saat generate script python-pptx, pastikan:

```python
# Dependencies yang dibutuhkan:
# pip install python-pptx

# Struktur dasar yang harus ada di setiap slide:
# 1. Background fill (dark color)
# 2. Slide tag (kecil, di atas judul)  
# 3. Judul slide
# 4. Slide number (pojok kanan atas, kecuali cover)
# 5. Konten utama (sesuai layout per slide)
# 6. Speaker notes (notes.text = "...")

# Warna yang digunakan:
COLORS = {
    "bg": "0D1117",        # background gelap
    "text": "E6EDF3",      # teks utama putih
    "text2": "8B949E",     # teks sekunder abu
    "accent": "0078D4",    # biru Microsoft
    "danger": "EF4444",    # merah
    "warn": "F59E0B",      # kuning
    "ok": "10B981",        # hijau
    "purple": "A855F7",    # ungu
    "border": "21262D",    # border subtle
}

# Ukuran slide: 13.33 x 7.5 inch (widescreen 16:9)
# Font: Segoe UI (atau Calibri sebagai fallback)
```
