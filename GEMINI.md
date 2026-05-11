# Project Richtlijnen: Bughunt

## Architectuur & Conventies
- **Taal:** Python is de voorkeurstaal voor tooling vanwege de snelheid van ontwikkeling en rijke libraries (Requests, Scapy, BeautifulSoup).
- **Modulariteit:** Elke tool moet als zelfstandige module werken, maar ook geïntegreerd kunnen worden in een groter framework.
- **Output:** Tools moeten resultaten leveren in zowel leesbare tekst als JSON voor verdere verwerking.

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
