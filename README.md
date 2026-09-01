# Linux Host File Integrity Monitor (FIM) & System Auditor 🛡️🐧

A lightweight Host-Based Intrusion Detection System (HIDS) built in Python to monitor critical Linux system paths, configuration files, and binaries for unauthorized changes, permission drifts, and backdoor implants using cryptographic SHA-256 baselines.

---

## 🎯 5-Day Development Roadmap

- [x] **Day 1: Project Architecture, POSIX Permission Extractor & SHA-256 Baseline Engine**
- [ ] **Day 2: Drift Detection Engine (Checksum, Permission, & Inode Tamper Scanner)**
- [ ] **Day 3: Real-Time Event Watcher (`watchdog` / `inotify` Live Tamper Monitor)**
- [ ] **Day 4: Threat Classification Engine (MITRE ATT&CK Privilege Escalation & Persistence)**
- [ ] **Day 5: Interactive Terminal Dashboard, SIEM Alert Exporter & HTML Forensic Report**

---

## 🚀 Key Features
* **Cryptographic Baseline:** Computes chunked SHA-256 digests of sensitive system assets (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`).
* **POSIX Security Auditing:** Tracks ownership (UID/GID), file sizes, and octal permission drifts.
* **Tamper Identification:** Detects file modification, deletion, creation, and permission escalation attacks.
* **SOC Reporting:** Structured JSON SIEM alerts and interactive visual HTML audit reports.

---

## 📦 Installation & Setup

```bash
git clone [https://github.com/Dinesh-Perera-X/Linux-Host-FIM-Auditor.git](https://github.com/Dinesh-Perera-X/Linux-Host-FIM-Auditor.git)
cd Linux-Host-FIM-Auditor
pip3 install -r requirements.txt --break-system-packages
