# 🛡️ Azure SOC & Honeynet Fortification Project 🛡️

[![Azure](https://img.shields.io/badge/Azure-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)](https://azure.microsoft.com)
[![Microsoft Sentinel](https://img.shields.io/badge/Microsoft_Sentinel-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)](https://azure.microsoft.com/en-us/services/microsoft-sentinel/)
[![KQL](https://img.shields.io/badge/KQL-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/)
[![Cybersecurity](https://img.shields.io/badge/Cybersecurity-Project-blue?style=for-the-badge)](https://en.wikipedia.org/wiki/Computer_security)
[![NIST](https://img.shields.io/badge/NIST%20Framework-Applied-lightgrey?style=for-the-badge)](https://www.nist.gov/cyberframework)

## 🚀 Introduction: Simulating Reality, Building Resilience

This project documents the creation and hardening of a scalable **honeynet** within the Microsoft Azure cloud ecosystem. The primary objective was to establish a controlled, observable environment to attract and analyze malicious activity, then implement robust security controls and measure their effectiveness.

By ingesting logs from diverse Azure resources into a central **Azure Log Analytics Workspace (LAW)**, and leveraging **Microsoft Sentinel** as our Security Information and Event Management (SIEM) solution, we could:
1.  Detect and visualize attack patterns.
2.  Generate automated alerts and incidents for suspicious activities.
3.  Quantify security posture improvements using **Kusto Query Language (KQL)**.

This hands-on endeavor mirrors real-world Security Operations Center (SOC) practices, offering invaluable insights into threat detection, incident response, and the tangible impact of security hardening. The project spanned two distinct 24-hour phases: an initial "exposed" phase for baseline metrics, followed by a "hardened" phase to compare and contrast.

![Project Overview Diagram](https://github.com/user-attachments/assets/c2eca427-e1a4-450d-adb9-8b64c72223c9)
*(High-level overview of the project components)*

---

## 🛠️ Core Technologies & Tools Utilized

| Technology / Service          | Purpose                                                                 |
| :---------------------------- | :---------------------------------------------------------------------- |
| **Microsoft Azure**           | Cloud platform for hosting all resources.                               |
| **Azure Virtual Machines**    | Windows (with SQL Server) & Linux OS for honeypot targets.              |
| **Azure Log Analytics (LAW)** | Centralized repository for log ingestion and analysis.                  |
| **Microsoft Sentinel**        | SIEM/SOAR for threat detection, incident management, and visualization. |
| **Azure Network Security Groups (NSGs)** | Network traffic filtering at the VM/subnet level.                       |
| **Microsoft Entra ID**        | Identity and access management for user creation and permissions.       |
| **Azure Blob Storage**        | Storing threat intelligence data (e.g., 'IP-watchlist').                |
| **Microsoft Defender for Cloud** | Security posture management and threat protection.                      |
| **Azure Key Vault**           | Securely storing and managing secrets.                                  |
| **Kusto Query Language (KQL)**| Language for querying logs and generating security metrics.             |

---

## Phase 1: Constructing the Honeynet - The "Open Gates" Approach

The initial phase focused on building the honeynet infrastructure with intentionally weakened security postures to maximize the observable attack surface. This approach, while risky in a production environment, is crucial for a honeynet's purpose: to attract and study attacks.

### 🔑 Key Setup Steps:
1.  **Virtual Machine Deployment:**
    *   Provisioned a **Windows Server VM** and installed **SQL Server**. The native Windows Firewall was **disabled**.
    *   Provisioned a **Linux VM**. Its firewall (e.g., `ufw`, `firewalld`) was also **disabled**.
    *   A dedicated **"Attack-VM"** was created within Azure to simulate controlled attacks from a known source, complementing organic internet traffic.
2.  **Network Configuration:**
    *   **Network Security Groups (NSGs)** were configured with "Allow Any/Any" inbound rules for protocols like RDP (3389), SSH (22), HTTP/S (80/443), and SQL (1433). This made the VMs globally accessible.
3.  **Identity & Access:**
    *   Multiple users were created in **Microsoft Entra ID** with varying permission levels, simulating potential internal account compromise scenarios.
4.  **Logging Infrastructure:**
    *   An **Azure Log Analytics Workspace (LAW)** was established as the central log sink.
    *   All relevant Azure resources (VMs, NSGs, Entra ID, Key Vault, etc.) were configured to forward their diagnostic logs and security events to this LAW.
5.  **Threat Intelligence & Monitoring Setup:**
    *   An **Azure Blob Storage** account was created to host an `IP-watchlist.csv` file, containing known malicious IP addresses. This was later integrated with Sentinel for threat correlation.
    *   **Microsoft Defender for Cloud** was enabled to provide baseline security recommendations and threat detection capabilities.
    *   An **Azure Key Vault** was provisioned, and sample "secrets" were created to monitor for unauthorized access attempts.
6.  **SIEM Configuration (Microsoft Sentinel):**
    *   Microsoft Sentinel was connected to the LAW.
    *   Several **custom analytic rules** were crafted in Sentinel to trigger alerts and create incidents for specific events, such as:
        *   Multiple failed login attempts (brute-force).
        *   Successful login after multiple failures.
        *   Access to Key Vault secrets from an unauthorized IP.
        *   Execution of suspicious commands or processes (if advanced VM logging was enabled).
        *   Matches against the `IP-watchlist`.

### 🏗️ Architecture Before Hardening:
This diagram illustrates the initial, highly exposed state of the honeynet.

![Architecture BEFORE Hardening](https://github.com/user-attachments/assets/f8fdc64f-38e0-4a70-bbe3-99f5b81a1583)
*(All resources deployed with public endpoints and minimal network restrictions.)*

### 🎯 Simulated Attacks During Open Exposure:
While the environment was open to organic internet traffic, the following specific attacks were simulated using the 'Attack-VM':
*   **Brute-Force Attack:** Multiple RDP/SSH login attempts with incorrect credentials against both Windows and Linux VMs, eventually culminating in a successful login with known credentials.
    *   *Real-world parallel: Attackers constantly scan for open RDP/SSH ports and attempt to brute-force weak credentials.*
*   **Simulated Malware Upload:** A benign file named to mimic malware (e.g., `mimikatz.exe`, `evil_script.sh`) was uploaded to a VM to test file integrity monitoring or endpoint detection rules (if configured).
    *   *Real-world parallel: Initial compromise often involves dropping malware or tools onto a victim machine.*
*   **Key Vault Access Violation:** An attempt was made to access secrets in Azure Key Vault using credentials or from an IP address that lacked sufficient permissions.
    *   *Real-world parallel: Attackers often seek out secrets (API keys, connection strings) to escalate privileges or pivot within a network.*

These simulated events were designed to ensure Sentinel's analytic rules were functioning correctly and generating the expected alerts and incidents.

---

## 🛡️ Phase 2: Incident Response, Remediation, and Fortification

After 24 hours of data collection in the "open" state, the focus shifted to hardening the environment. This phase mirrors the remediation steps a SOC analyst would take after identifying vulnerabilities and active threats.

### 🔍 Analysis and Triage:
Logs in LAW were queried using KQL, and incidents in Sentinel were reviewed. As anticipated:
*   Brute-force attempts and the subsequent successful login triggered high-severity alerts.
*   The simulated malware upload and Key Vault access violations also generated corresponding alerts.
*   A significant amount of unsolicited traffic from various global IPs was observed, attempting to probe common ports.

### 🔒 Hardening Measures Implemented:
The following security controls were applied, guided by **Microsoft Defender for Cloud recommendations** and principles from the **NIST Cybersecurity Framework (CSF)** and **NIST SP 800-53**:

1.  **Firewall Re-activation & Configuration:**
    *   The built-in firewalls on both Windows (Windows Defender Firewall) and Linux (e.g., `ufw`) VMs were **re-enabled**.
    *   Rules were configured to **deny all inbound traffic by default**, only allowing specific necessary ports from trusted sources.
2.  **Network Security Group (NSG) Overhaul:**
    *   NSG rules were drastically tightened. Instead of "Allow Any/Any," rules were changed to **allow traffic only from my specific public IP address** for management (RDP/SSH).
    *   For inter-service communication within Azure, rules were restricted to specific Azure IP ranges or service tags.
3.  **Private Endpoints Implementation:**
    *   Public endpoints for Azure services like SQL Server (on the VM, conceptually), Blob Storage, and Key Vault were **disabled**.
    *   **Private Endpoints** were implemented, exposing these services only within the project's Virtual Network (VNet). This effectively removes them from the public internet.
    *   *This is a critical defense-in-depth measure, ensuring that even if an NSG rule was misconfigured, the service itself wouldn't be publicly accessible.*
4.  **Just-In-Time (JIT) VM Access (Recommended by Defender for Cloud):**
    *   While not explicitly stated as implemented in the original, enabling JIT access for RDP/SSH ports is a common and highly effective hardening step. It keeps ports closed until access is explicitly requested and approved for a limited time.
5.  **Identity and Access Management (IAM) Review:**
    *   User permissions in Entra ID were reviewed, adhering to the **principle of least privilege**. Unnecessary administrative roles were removed or scoped down.
6.  **Microsoft Defender for Cloud Recommendations:**
    *   Actively addressed alerts and recommendations provided by Defender for Cloud, such as enabling specific security features, patching vulnerabilities, or configuring adaptive application controls.

### 🏗️ Architecture After Hardening:
This diagram showcases the significantly improved security posture after implementing the controls.

![Architecture AFTER Hardening](https://github.com/user-attachments/assets/52173322-dae6-419c-b0d7-46237da9f193)
*(Resources are now shielded by restrictive NSGs, host firewalls, and utilize private endpoints, drastically reducing the attack surface.)*

---

## 📊 Phase 3: Measuring the Impact - Metrics Before vs. After

Once the security controls were in place, the environment was monitored for another 24-hour period. The collected data was then compared against the baseline from the "open" phase.

### 📈 Security Metrics Comparison (24hr periods):

| Metric Category                 | Before Hardening | After Hardening | Change (%) | Significance                                                                                                |
| :------------------------------ | :--------------: | :-------------: | :--------: | :---------------------------------------------------------------------------------------------------------- |
| **Failed RDP/SSH Logins**       |      ~3500       |        0        |  -100%     | Drastic reduction due to NSG restrictions & firewall rules. Attackers can no longer reach the login ports. |
| **Security Alerts (Sentinel)**  |       ~50        |      ~2-5       |   ~-90%    | Significant drop; remaining alerts likely from internal "Attack-VM" tests or highly persistent (but blocked) probes. |
| **Malicious IPs Detected (NSG)**|      ~200        |      ~5-10      |   ~-95%    | NSGs block most unsolicited traffic before it can be analyzed deeper.                                     |
| **Successful Brute-Force**      |        1         |        0        |  -100%     | Hardened credentials and port restrictions prevent unauthorized access.                                     |
| **Key Vault Anomalous Access**  |        1         |        0        |  -100%     | Private endpoints and IAM controls prevent unauthorized access attempts.                                    |

*(Note: The above table is an interpretation of the provided chart. Actual values from your project should be used if different.)*

**Visual Representation of Metrics:**
![Metrics Chart: Before vs After Hardening](https://github.com/user-attachments/assets/ed5c88f6-1aaf-4160-ac7d-1384ca53c450)
*(This chart visually underscores the dramatic reduction in security incidents post-hardening.)*

---

## 🗺️ Attack Maps: Visualizing the Threat Landscape

Microsoft Sentinel's geolocation capabilities allowed for the visualization of attack origins, cross-referenced with the `IP-watchlist` uploaded to Blob Storage.

### 🌍 Attack Maps BEFORE Hardening:

These maps vividly illustrate the global nature of automated attacks targeting exposed services.

1.  **Failed RDP Attempts into Windows VM (Before):**
    ![Windows RDP Auth Fail BEFORE](https://github.com/user-attachments/assets/118ddb60-2f6a-4b3e-8979-5fd47905cc0e)
    *(Shows a concentration of RDP brute-force attempts from various international locations.)*

2.  **Failed SSH Attempts into Linux VM (Before):**
    ![Linux SSH Auth Fail BEFORE](https://github.com/user-attachments/assets/c6eef7da-813c-4e9b-a7f5-7a1e9d5d92d6)
    *(Similar to RDP, demonstrates widespread SSH scanning and brute-force activity.)*

3.  **All Malicious Traffic Flowing Through NSGs (Before):**
    ![NSG Malicious Flow BEFORE](https://github.com/user-attachments/assets/aa335341-05ca-42b9-8812-42a0b7fea0d2)
    *(A broader view of all suspicious traffic hitting the network perimeter.)*

### 🌐 Attack Maps AFTER Hardening:

```txt
(Sentinel did NOT generate ANY maps for any of the KQL map queries for the metrics measured during the 24hr period after hardening, thus confirming the effectiveness of the Security Controls implemented.)
