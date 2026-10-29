---
id: getting-started-desktop
title: Erste Schritte (Desktop)
mode: desktop
order: 20
---

## Installation {#install}

atlas-duck installiert drei Programme nebeneinander: `atlas-duck-app` (die Tray-Anwendung mit den Freigabefenstern), `atlas-duck` (die Befehlszeile und der MCP-Server, die Agents aufrufen) und `atlas-duck-sandbox` (das Hilfsprogramm, das Agent-Skripte ausführt). Befehlszeile und MCP-Server tun von sich aus nichts. Sie fragen die laufende App, und die App fragt Sie vor jedem Schreibvorgang.

| System | Versionen | Paket |
| --- | --- | --- |
| Windows | Windows 10 22H2 und neuer, Windows 11 (x86_64) | NSIS-Installer |
| macOS | macOS 13 und neuer (arm64 und x86_64, je ein Build) | `.dmg` |
| Ubuntu | 22.04 und neuer | `.deb`, AppImage |
| Fedora | 40 und neuer | `.rpm`, AppImage |

- **Windows:** Der Installer bietet eine Installation pro Benutzer und eine pro Computer an. Die Installation pro Computer (Programme) wird empfohlen, weil normale Benutzer die Programmdateien dann nicht ändern können. Führen Sie atlas-duck nicht als Administrator aus. Läuft die App mit erhöhten Rechten und das Terminal des Agents nicht, verweigert die Befehlszeile das Gespräch mit ihr; starten Sie beide mit denselben Rechten.
- **macOS:** Öffnen Sie die `.dmg` und ziehen Sie die App in den Ordner Programme.
- **Linux:** atlas-duck legt seine Schlüssel und Ihre Tokens im Schlüsselbund des Betriebssystems ab. Dafür brauchen Sie einen Secret-Service-Anbieter mit einer nutzbaren Standardsammlung, zum Beispiel GNOME Keyring oder KWallet. Ohne ihn bricht der erste Start ab und meldet: "atlas-duck needs a system keyring (Secret Service, e.g. GNOME Keyring or KWallet). Install or unlock one, then restart atlas-duck." (Diese Meldung erscheint auf Englisch.)

Der Befehl `atlas-duck` liegt nach der Installation nicht in Ihrem PATH, außer bei den Linux-Paketen `.deb` und `.rpm`. Siehe [Befehlszeile installieren](settings#cli-install).

Eine Deinstallation entfernt nur die Programme: Das Audit-Protokoll, Ihre Einstellungen und Ihre Schlüsselbund-Einträge bleiben erhalten. Verwenden Sie vor dem Deinstallieren "Auf die Entfernung vorbereiten" in den Einstellungen.

## Erster Start und Einrichtung {#first-start}

Beim ersten Start führt Sie das Einrichtungsfenster der Reihe nach durch diese Schritte. Bis die Einrichtung abgeschlossen ist, werden Anfragen von Agents zurückgewiesen, und das Fenster zeigt "Einrichtung erforderlich" mit der Zahl der zurückgewiesenen Anfragen.

1. **Wo atlas-duck seine Daten ablegt.** Das Audit-Protokoll und die Einstellungen liegen in einem Ordner auf einem lokalen Datenträger. Wählen Sie "Standardordner verwenden" oder "Anderen Ordner wählen…". Ein Netzwerkordner wird abgelehnt. Enthält der Ordner bereits ein Audit-Protokoll, meldet atlas-duck "Hier gibt es bereits ein Audit-Protokoll", behält es, und Sie wählen "Mit diesem Protokoll fortfahren".
2. **Anker-Verzeichnis (optional).** Für Fortgeschrittene: ein Ordner außerhalb dieses Computers, zum Beispiel eine Netzwerkfreigabe, in den atlas-duck seine Audit-Anker zusätzlich schreibt. Sie können ihn überspringen und später in den Einstellungen ändern.
3. **Wiederherstellungs-Passphrase.** Mit ihr können Sie das Audit-Protokoll wieder lesen, wenn der Schlüsselbund dieses Computers verloren geht. Sie geben sie zweimal im Anmeldedatenfenster ein, und atlas-duck kann sie nicht noch einmal anzeigen. Sie ist nicht Ihr Atlassian-Passwort. Bewahren Sie sie so auf, dass Ihr Compliance-Verantwortlicher sie abrufen kann.
4. **Das Audit-Protokoll wird erstellt.** atlas-duck legt das Protokoll an.
5. **Wiederherstellungsnotiz.** Das Anmeldedatenfenster bietet an, eine Notiz mit Ihrer Installations-ID, Ketten-ID und Ihrem Datenordner zu speichern. Speichern Sie sie, wenn Sie eine möchten.
6. **Jira- oder Confluence-Instanzen hinzufügen.** Siehe [Instanz verbinden](#connect-instance). Das können Sie auch später tun.
7. **Befehlszeile.** "CLI im PATH installieren" legt den Befehl `atlas-duck` in Ihren PATH, damit Agents ihn finden.
8. **Einführung für Agents.** Anweisungen, die Sie in die `CLAUDE.md` oder `AGENTS.md` der Repositories kopieren, in denen Ihre Agents arbeiten. Siehe [Agents (Desktop)](agents-desktop).
9. **Einrichtung abschließen.** "Die Einrichtung ist abgeschlossen": atlas-duck ist bereit, und das Freigabefenster öffnet sich.

Wenn Sie bereits ein Backup eines atlas-duck-Audit-Protokolls haben, bietet das Einrichtungsfenster "Aus einem Backup wiederherstellen…" an, statt ein neues Protokoll zu erstellen, solange es noch kein Protokoll gibt. Sie geben dann die Wiederherstellungs-Passphrase des Backups ein, und es wird keine neue Passphrase festgelegt.

## Instanz verbinden {#connect-instance}

Eine Instanz ist ein Jira- oder Confluence-Data-Center-Server. Im Desktopmodus legen Sie Ihre eigenen an, entweder im Einrichtungsfenster oder später in den Einstellungen unter "Instanz hinzufügen".

1. Geben Sie einen Alias, das Produkt (Jira oder Confluence) und die Basis-URL ein. Die URL muss https verwenden und den Kontextpfad enthalten. Verwendet der Server eine interne Zertifizierungsstelle, wählen Sie "Eigenes CA-Zertifikat verwenden".
2. Wählen Sie "Instanz hinzufügen". atlas-duck zeigt Alias und Origin in einem eigenen Dialog; bestätigen Sie sie ("Instanz bestätigen").
3. Fügen Sie Ihr persönliches Zugriffstoken hinzu. Das Einrichtungsfenster überlässt das den Einstellungen: "Fügen Sie ihr Token nach der Einrichtung in den Einstellungen hinzu."

Felder und Token-Schritte im Einzelnen stehen unter [Instanzen und Tokens](instances-and-tokens).

## Das Tray-Menü {#tray}

atlas-duck läuft im Infobereich der Taskleiste (Tray). Das Schließen eines Fensters blendet es nur aus. Der Tooltip zeigt, wie viele Anfragen ausstehen ("atlas-duck: N ausstehend"). Das Menü enthält diese Einträge:

| Eintrag | Wirkung |
| --- | --- |
| Freigaben öffnen (N) | Öffnet das Freigabefenster oder das Fenster, das atlas-duck stattdessen von Ihnen braucht. N ist die Zahl der ausstehenden Anfragen. |
| Entsperren… | Öffnet das Anmeldedatenfenster. Nur solange atlas-duck gesperrt ist. |
| Schlüsselbund erneut versuchen | Ein weiterer Versuch, den Schlüsselbund zu erreichen. Nur solange der Schlüsselbund nicht verfügbar ist. |
| Präsentationsmodus | Schaltet ohne Rückfrage auf "Nur Kennzeichen", bis Sie ihn wieder ausschalten. |
| Hilfe | Öffnet dieses Handbuch. |
| Beenden | Beendet atlas-duck. |

Statuszeilen über den Einträgen zeigen, warum atlas-duck nicht bedienen kann, zum Beispiel "Gesperrt", "Einrichtung erforderlich" oder "Warte auf den Schlüsselbund".
