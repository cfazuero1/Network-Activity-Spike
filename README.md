# Incident Report: Network Activity Spike — Malicious IP Correlation (SOCRadar Analysis)

## Overview
SOCRadar Threat Hunting identified multiple inbound and outbound connections from internal assets to **confirmed malicious IPs** between **20–21 Oct 2025**, correlating with the network activity spike observed in **Microsoft Sentinel** telemetry.  
Cross-verification through **AbuseIPDB**, **AlienVault**, and **Kaspersky Threat Intelligence Portal** confirms that the contacted IPs exhibit **scanning, phishing, and abuse-related behaviors**, suggesting active malicious probing or beaconing within the monitored network.

---

### Confidence Level
**High**

### Severity
**High**

### Environment
Corporate Production Network

### Detection Source
SOCRadar CTI Platform + Microsoft Sentinel

---

## Findings

### 1. Threat Intelligence Correlation (SOCRadar)

| IP Address | Source | Category | Risk Score | Country | Associated Tags | Description |
|-------------|----------|-----------|-------------|----------|------------------|--------------|
| **194.180.49.103** | AbuseIPDB / Kaspersky | Bad Reputation | 43/100 (Medium) | Germany | phishing, abuse, credential | Confirmed malicious; associated with scanning activity from a hosting provider in Bergwau, Germany. |
| **162.243.203.54** | AbuseIPDB | Potential Attacker | 53/100 (Medium) | USA (Secaucus) | credential, ddos, VPS | DigitalOcean VPS address involved in repetitive scanning; marked in AbuseIPDB since 2024. |
| **103.189.80.205** | AbuseIPDB / AlienVault | Malicious Activity | 59/100 (Medium) | India (New Delhi) | ddos, ftp, ssh, malware | Listed on AlienVault OTX “IPQS Abusive IP List”; repeated abusive behavior detected. |

---

### 2. Network Behavior
- **Telemetry:** `AzureNetworkAnalytics_CL` shows inbound connections from these IPs to multiple internal hosts, averaging **286–288 connection attempts per IP**, indicating automated scanning rather than user-driven traffic.  
- **Ports:** Targeted ports include **22 (SSH)**, **23 (Telnet)**, **80 (HTTP)**, and **3389 (RDP)** — consistent with **credential brute-force** and **enumeration activity**.  
- **Process Correlation:** `svchost.exe -k NetworkService` identified as the initiating process in several `DeviceNetworkEvents`, potentially indicating **service-level injection** or **malware persistence**.

---

### 3. SOCRadar Reputation Data Summary
- **AbuseIPDB Feeds:** Continuous listings from **15–21 Oct 2025** for malicious scanning and credential attacks.  
- **Kaspersky TI Feed:** Identified phishing infrastructure referencing AbuseIPDB, supporting malicious classification.  
- **AlienVault OTX:** Detected **103.189.80.205** under *“IPQS Abusive IP List”*, confirming cross-source validation.

---

### 4. Event Spike Analysis
Sentinel dashboards revealed a **sharp increase in inbound events** within a 3-hour window on **20 Oct 2025**, coinciding with communication from these IPs.  
The pattern suggests an **automated campaign** or **C2 beaconing** activity rather than normal background noise.

---

## Evidence Snapshots

![SOCRadar Evidence 1](https://github.com/cfazuero1/Network-Activity-Spike/blob/main/75d2dbb4-ff45-4c0f-85f0-1f95a88a592e.png)
![SOCRadar Evidence 2](https://github.com/cfazuero1/Network-Activity-Spike/blob/main/813c9ef3-52b5-42be-b575-caf366f7bdae.png)
![SOCRadar Evidence 3](https://github.com/cfazuero1/Network-Activity-Spike/blob/main/a1acacf6-d6e6-4522-9b47-68efa2b3a3d7.png)
![SOCRadar Evidence 4](https://github.com/cfazuero1/Network-Activity-Spike/blob/main/aa71c17b-f5c7-4bb0-979a-179fb2913e4c.png)
![SOCRadar Evidence 5](https://github.com/cfazuero1/Network-Activity-Spike/blob/main/e0ff24fd-ab92-4f9c-87e4-e7a20bea1a9a.png)
![SOCRadar Evidence 6](https://github.com/cfazuero1/Network-Activity-Spike/blob/main/f38a89f0-5ae0-4f75-bdad-cc0c55a1e21d.png)

---

## Assessment
The combination of known malicious IP reputation, abnormal port usage, and uniform connection patterns indicates a **likely external compromise or reconnaissance**.  
Given that multiple CTI sources independently classify these IPs as abusive, the activity is assessed as **confirmed hostile** and meets escalation criteria for incident handling.

---

## Recommended Response

| Priority | Action | Objective |
|-----------|--------|------------|
| **Containment** | Block or isolate communication with IPs `194.180.49.103`, `162.243.203.54`, and `103.189.80.205` across firewalls and proxy layers. | Stop potential C2 or scanning communication. |
| **Endpoint Review** | Examine hosts invoking `svchost.exe -k NetworkService` for DLL injections, persistence entries, or unauthorized services. | Detect compromised services or persistence mechanisms. |
| **Log Correlation** | Review RDP, SSH, and Telnet authentication logs for brute-force attempts. | Identify lateral movement or credential compromise. |
| **IOC Integration** | Feed confirmed IOCs into Sentinel, SOCRadar, and Suricata detection rules. | Improve detection fidelity and prevent reoccurrence. |
| **Compliance** | Document PCI DSS control impacts (firewall monitoring, IDS/IPS validation). | Maintain audit integrity and evidence readiness. |

---

## Conclusion
SOCRadar and Sentinel telemetry confirm **malicious external communication and reconnaissance behavior** originating from multiple abusive IPs.  
The cross-source intelligence correlation and endpoint evidence indicate a **confirmed security incident** requiring immediate containment, forensic review, and detection rule tuning.

---

**Report Generated:** 26 October 2025  
**Analyst:** Christian Azuero  
**Platform:** SOCRadar Threat Intelligence & Microsoft Sentinel
