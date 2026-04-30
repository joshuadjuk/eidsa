# EIDSA - Entra ID Signin Analyzer

EIDSA (Entra ID Signin Analyzer) is a multi-workspace Azure AD / Entra ID sign-in log analyzer application. This application is specifically designed to detect various cyber threats, anomalies, and attack patterns by analyzing JSON-formatted log export files from the Azure portal.

## 🌟 Key Features

EIDSA is equipped with various detection and visualization capabilities to assist security investigations:

* **Multi-Workspace Support:** Allows managing multiple tenants or clients separately within a single application.
* **Comprehensive Threat Detection Engine:** Detects over 20 attack vectors such as Password Spray, Brute Force, Impossible Travel, Token Replay, MFA Exhaustion, and foreign application access.
* **Automatic IP Enrichment:** Integrates with `ip-api.com` to obtain ISP information, connection types (Proxy/VPS/Mobile), and attacker geolocation.
* **Cross-Workspace IP Correlation:** Discovers attacker IP addresses conducting cross-tenant attacks across your various workspaces.
* **Truncated JSON Recovery:** A rescue feature to read and process large, truncated (incomplete) JSON log data downloaded from the Azure Portal.
* **Visualization & Reporting:** Equipped with an executive summary dashboard, user profile risk metrics, geographic maps (Geo Map), Login Heatmap, and a KQL Query Generator to be copied into Microsoft Sentinel.
* **Triage & Notes:** Features to mark True Positives (TP), False Positives (FP), or save investigation notes per user.
* **The full list of features is available in ** ROADMAP.md

## ⚠️ Important Reminder (Folder Prerequisites)

Before running the application, ensure you have created the following two folders in the root directory of this project:
1. `workspaces/` : Used by the system to store metadata configurations, rules, and thresholds for each workspace.
2. `uploads/` : Used to store the JSON sign-in log files that you upload to each workspace.

*(Note: The system will attempt to automatically create these directories if they do not exist when the server starts).*

## 🚀 Usage

1. **Preparation:** Ensure you have Node.js installed on your computer.
2. **Clone the Project:**
   ```bash
   git clone https://github.com/joshuadjuk/eidsa.git
   cd eidsa
3. **Install Dependencies & Run**
   ```bash
   npm install
   npm run build / dev