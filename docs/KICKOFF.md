# Kickoff prompt for a new Claude Code session

Setup: open this folder as a new project in Claude Code, select **Opus 5.5** in the model picker
and set the effort to **High**. Then paste the prompt below.

---

```text
Wir starten das Projekt MyOwnPKI. Lies zuerst CLAUDE.md und docs/PLAN.md vollständig und lade den
Skill "myownpki" inklusive der Referenzdateien, die du für Phase 0 brauchst.

Wir sind in Phase 0 (Fundament). Ziel dieser Session:

1. Umgebung prüfen: go version, git, und ob templ, sqlc, golangci-lint, govulncheck und openssl
   vorhanden sind. Sag mir, was fehlt und wie ich es auf Windows Server 2025 (Git Bash/PowerShell)
   installiere – ich installiere selbst.

2. Einen konkreten Arbeitsplan für Phase 0 als Aufgabenliste erstellen, mit kleinen, einzeln
   prüfbaren Schritten:
   - Go-Modul und Verzeichnisstruktur nach PLAN §8 (drei Binaries mit leerem main)
   - Task-Runner und CI (GitHub Actions) nach go-conventions.md
   - Presets aus legacy/lib/presets.sh nach presets/*.yaml übertragen, inkl. Ladecode + Tests
   - OpenAPI-Entwurf api/openapi.yaml für den Phase-1-Umfang
   - Design-Tokens + Komponenten-CSS + Komponenten-Übersicht (/design) als erste templ-Seite

3. Bevor du Code schreibst: Stell mir Fragen zu allem, was im Plan noch offen ist
   (z. B. Taskfile vs. Make, YAML vs. TOML für die Konfiguration). Gib zu jeder Frage eine Empfehlung.

4. Danach setzt du Schritt für Schritt um. Nach jedem Schritt:
   - was du gemacht hast (kurz, auf Deutsch)
   - wie ich es prüfe (konkrete Befehle)
   - einen Commit-Vorschlag (Conventional Commits, Englisch)
   Committe erst, wenn ich zustimme. Nicht pushen.

Wichtig: Ich bin Fachinformatiker für Systemintegration, kein Entwickler. Erkläre Entscheidungen
in Admin-Sprache. Go muss ich nicht lernen, aber nutze jede Gelegenheit, mir etwas über Zertifikate
und PKI beizubringen (z. B. warum ein Preset bestimmte Key Usages hat).
```
