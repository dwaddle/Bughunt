# Bughunt: Roadmap & Tooling

Dit project is gericht op het systematisch oplossen van security challenges (zoals op TryHackMe) en het vertalen van die lessen naar real-world bug hunting scenario's.

## 🎯 Attack Vectors (gebaseerd op klad.txt)

We focussen op de volgende kritieke aanvalspunten:

1.  **Default Credentials:** Zwakke of ongewijzigde wachtwoorden op admin panels.
    *   *Tooling:* `Auth-Bruter` (gepland)
2.  **Unnecessary Services:** Onnodige poorten of diensten die openstaan voor het internet.
    *   *Tooling:* `Master-Recon` (actief)
3.  **Cloud Misconfigurations:** Onveilig ingestelde S3 buckets of cloud permissies.
    *   *Tooling:* `Cloud-Auditor` (gepland)
4.  **Unrestricted API Access:** API's zonder authenticatie of autorisatie controle.
    *   *Tooling:* `API-Interceptor` (gepland)
5.  **Verbose Error Messages:** Lekken van stack traces of systeemdetails.
    *   *Tooling:* `Verbose-Checker` (actief)
6.  **Outdated Software:** Gebruik van verouderde frameworks met bekende CVE's.
    *   *Tooling:* `Exploit-Matcher` (actief)
7.  **Exposed AI/ML Endpoints:** AI-modellen/eindpunten zonder toegangscontrole.
    *   *Tooling:* `AI-Endpoint-Scanner` (gepland)

---

## 🚀 De Roadmap

### Fase 1: Reconnaissance (De "Solid Base")
*   **Doel:** Volledige zichtbaarheid van het aanvalsoppervlak en automatische mapping naar kwetsbaarheden.
*   **Focus:**
    1.  **Port Discovery:** Snel scannen van alle 65535 poorten.
    2.  **Service Fingerprinting:** Exacte versies en technologieën identificeren.
    3.  **CVE & Intelligence:** Automatisch zoeken naar bekende CVE's op basis van versienummers (Nmap vulners, Searchsploit).
    4.  **Endpoint Enumeration:** Ontdekken van API routes en statische mappen.
    5.  **Vulnerability Mapping:** Gevonden poorten direct koppelen aan gespecialiseerde tools.
*   **Tools:** Nmap (XML output), Custom Master-Recon Orchestrator.

### Fase 2: Vulnerability Analysis
*   **Doel:** Specifieke kwetsbaarheden identificeren (OWASP Top 10).
*   **Focus:** Misconfiguraties (AS02), Supply Chain (AS03), Broken Auth.
*   **Tools:** Nuclei, Nikto, Custom scanners.

### Fase 3: Exploitation
*   **Doel:** Bewijs van kwetsbaarheid leveren (PoC).
*   **Focus:** Command Injection, SQLi, Broken Cryptography.
*   **Tools:** Metasploit, Burp Suite, Custom exploit scripts.

### Fase 4: Reporting & Automation
*   **Doel:** Resultaten documenteren en het proces automatiseren.
*   **Focus:** Scripting van herhaalbare tests.

## 🛠 Eigen Tools in Ontwikkeling

1.  **Hunter-SCA:** Een tool om dependencies te scannen op bekende kwetsbaarheden (gericht op Supply Chain Failures).
2.  **Verbose-Checker:** Een scanner die specifiek zoekt naar verbose error messages door verschillende types "bad input" te sturen.
3.  **Crypto-Audit:** Een script dat client-side JS analyseert op hardcoded keys en zwakke algoritmen.
