# 🔍 FortiGate Configuration Files Audit Tool (FCFAT)

**FortiGate configuration audit script** that analyzes **FortiGate configuration files** and checks for compliance with recommended security settings.

## 🔎 Security & Compliance Checks

The tool evaluates multiple security best practices, including but not limited to:

### 🔐 **Authentication & Access Control**
- Enforcing **strong password policies** (minimum length, complexity, expiration)  
- Ensuring **administrative users** have **restricted access** (e.g., no default passwords)  
- Verifying **multi-factor authentication (MFA)** is enabled for admin accounts  
- Checking **role-based access control (RBAC)** to minimize excessive privileges  
- Ensuring **SSH access is restricted** and using **only SSH version 2**  

### 🌐 **Network & Firewall Security**
- Ensuring **explicit deny-all rule** exists at the end of firewall policies  
- Checking for **unused or overly permissive rules**  
- Verifying **interface trust levels** (restricting unnecessary access)  
- Ensuring **VPN security settings** enforce strong encryption protocols  
- Checking **Web Filter and Application Control policies** to prevent malicious traffic  

### 📊 **Logging & Monitoring**
- Ensuring **centralized logging** is enabled (syslog, FortiAnalyzer, or SIEM)  
- Verifying **log retention policies** are in place  
- Checking that **security events, admin actions, and system events** are logged  
- Ensuring **intrusion detection and prevention (IPS/IDS) logging** is active  

### 🚀 **System Hardening**
- Checking for **default or insecure configurations**  
- Ensuring **administrative access is restricted to trusted IPs**  
- Verifying **NTP servers** are configured for time synchronization  
- Checking that **SNMP community strings** are not set to default values  
- Ensuring **strong cryptographic settings** for SSL VPN and admin access  

etc
---

🔒 **Secure your FortiGate firewall with confidence!**  
💡 **Contributions & feedback are welcome!** 🚀

### ☕ Support My Work

[![GitHub Sponsors](https://img.shields.io/badge/Sponsor%20on-GitHub-ff4081?style=for-the-badge&logo=github)](https://github.com/sponsors/Xalfie)
[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-orange?style=for-the-badge&logo=buy-me-a-coffee)](https://www.buymeacoffee.com/xalfie)

