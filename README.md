# Bughunt: OWASP-Driven Security Toolset

Dit project is gericht op het systematisch identificeren en exploiteren van kwetsbaarheden uit de **OWASP Top 10**. Door voor elke categorie specifieke tools te bouwen, creëren we een compleet verhaal voor zowel CTF's (TryHackMe) als real-world security audits.

## 🛡️ OWASP Top 10 Mapping & Tool Status

| OWASP Categorie | Beschrijving | Onze Tool | Status |
| :--- | :--- | :--- | :--- |
| **A01: Broken Access Control** | Ongeautoriseerde toegang tot data/functies. | `Directory-Scanner` | ✅ Actief |
| **A02: Cryptographic Failures** | Zwakke encryptie of hardcoded keys. | `Crypto-Audit` | ⏳ Gepland |
| **A03: Injection** | SQL, NoSQL, OS Command, LFI/RFI. | `LFI-Scanner`, `SQLi-Tester`, `Cmd-Injection-Tester` | ✅ Actief |
| **A04: Insecure Design** | Ontwerpfouten in de applicatielogica. | `Recon-Logic` | 📝 In Roadmap |
| **A05: Security Misconfiguration** | Verbose errors, default accounts. | `Verbose-Checker` / `Auth-Bruter` | ✅ Actief |
| **A06: Outdated Components** | Gebruik van software met bekende CVE's. | `Exploit-Matcher` | ✅ Actief |
| **A07: Identification & Auth** | Zwakke inlogmechanismen/sessies. | `Auth-Bruter` | ✅ Actief |
| **A08: Software & Data Integrity** | Supply chain failures, onveilige updates. | `Hunter-SCA` | ⏳ Gepland |
| **A09: Logging & Monitoring** | Gebrek aan detectie van aanvallen. | *Blue Team Scope* | - |
| **A10: SSRF** | Server-Side Request Forgery. | `SSRF-Scanner` | ⏳ Gepland |

---

## 🔥 Master-Recon Orchestrator
De `Master-Recon` tool dient als de centrale orchestrator die bovenstaande tools aanstuurt op basis van de gevonden services.

## 🚀 De Roadmap (Fasen)

### Fase 1: Reconnaissance (De "Solid Base")
*   **Port Discovery & Service Fingerprinting**
*   **CVE & Intelligence Integration** (NIST NVD API)
*   **Actionable Reporting** (Org-mode Action Plan)

### Fase 2: Vulnerability Analysis (OWASP Focused)
*   Implementatie van de resterende ⏳ tools uit de tabel.
*   Focus op **Injection (A03)** en **Broken Access Control (A01)**.

### Fase 3: Exploitation & PoC
*   Automatische koppeling met Metasploit of custom exploit scripts.

### Fase 4: Automation & reporting
*   Volledige CI/CD integratie voor automatische scans.
