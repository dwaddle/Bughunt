# Project Richtlijnen: Bughunt

## Filosofie: OWASP-Centric Development
- Elke tool in de `tools/` directory moet direct te herleiden zijn naar ten minste één categorie uit de **OWASP Top 10**.
- Het doel is om een 'compleet verhaal' te bieden: van het vinden van de service (Recon) tot het identificeren van de specifieke OWASP-kwetsbaarheid.

## Architectuur & Conventies
- **Taal:** Python 3 met een sterke focus op `requests` en `argparse`.
- **Modulariteit:** Tools moeten standalone kunnen draaien, maar hun resultaten moeten door `Master-Recon` geconsumeerd kunnen worden.
- **Output:** Standaardiseer op JSON voor data-uitwisseling tussen tools en Org-mode voor menselijke rapportage.

## Workflow voor Nieuwe Challenges
1.  **Logboek bijhouden:** Elke THM room of test wordt gedocumenteerd in de `notes/` directory met gebruik van **Emacs Org-mode** (`.org` bestanden).
2.  **Tooling gap-analyse:** Na elke challenge kijken we: "Welke stap had sneller gekund met een eigen script?"
3.  **Ontwikkeling:** Die stap automatiseren we in de `tools/` directory.

## Org-mode Conventies
- Gebruik `#+TITLE:`, `#+AUTHOR:` en `#+DATE:` headers.
- Gebruik `* Reconnaissance`, `* Vulnerability Analysis`, `* Exploitation` en `* Lessons Learned` als hoofdkoppen.
- Sla payloads op in `#+BEGIN_SRC` blokken voor eenvoudige kopieerbaarheid.

## Prioriteiten
- Focus eerst op **AS02 (Security Misconfiguration)** en **AS03 (Supply Chain Failures)** aangezien deze vaak voorkomen en lastig te vinden zijn met standaard scanners.
