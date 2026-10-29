---
id: settings
title: Einstellungen
mode: both
order: 80
---

::: desktop

Im Desktopmodus sind die Einstellungen ein eigenes Fenster. Neben den Themen dieser Seite enthalten sie Ihre Instanzen ([Instanzen und Tokens](instances-and-tokens)), die Limits für Anfragen und [Skripte](scripts#limits), Aufbewahrung und Legal Hold ([Audit-Protokoll](audit#retention)), die Bereinigung und "Auf die Entfernung vorbereiten".

:::

::: server

Im Servermodus gibt es keine Einstellungsseite. Die Auswahlmöglichkeiten, die Ihnen gehören, Sprache und Benachrichtigungen, befinden sich in der Kopfzeile und auf der Seite Freigaben. Instanzen, Schlüssel und der Rest der Installation gehören zu den Aufgaben der Administratoren ([Administration](admin)).

:::

## Sprache {#language}

atlas-duck gibt es auf Englisch und auf Deutsch. Die Sprache gilt für die Fenster und Seiten, die Benachrichtigungen und die nativen Dialoge sowie für dieses Handbuch. Texte, die Agents lesen, Audit-Datensätze, Protokolle, die Befehlszeile und die Betriebsdokumentation bleiben Englisch.

Zur Wahl stehen:

- **Automatisch**: Deutsch, wenn die Sprache Ihres Betriebssystems (Desktop) oder Ihres Browsers (Server) Deutsch ist, sonst Englisch.
- **Deutsch**
- **English**

::: desktop

Öffnen Sie die Einstellungen, suchen Sie den Abschnitt "Sprache" und verwenden Sie das Menü "Sprache". Alle geöffneten Fenster wechseln sofort. Die Wahl ist eine App-Einstellung, sie wird außerhalb des Audit-Protokolls gespeichert und nicht protokolliert.

:::

::: server

Verwenden Sie das Menü "Sprache" in der Kopfzeile einer beliebigen Seite. Die Seite wechselt ohne Neuladen. Die Wahl wird für Sie gespeichert, gilt also in jedem Browser, in dem Sie sich anmelden, und wird nicht protokolliert. Schlägt das Speichern fehl, meldet atlas-duck "Die Sprache konnte nicht gespeichert werden. Versuchen Sie es erneut."

:::

Jede Seite dieses Handbuchs hat einen Link auf dieselbe Seite in der anderen Sprache, sodass Sie auch hier wechseln können.

## Benachrichtigungen und Aufmerksamkeit {#notifications}

::: desktop

Der "Benachrichtigungsmodus" in den Einstellungen legt fest, was geschieht, wenn eine Anfrage Sie braucht:

| Option | Was geschieht |
| --- | --- |
| Fenster anzeigen, ohne den Fokus zu übernehmen | Das Freigabefenster erscheint, übernimmt aber nicht den Tastaturfokus. |
| Nur Kennzeichen | Es öffnet sich kein Fenster. Nur ein Kennzeichen zeigt, dass etwas aussteht. |
| Fenster anzeigen und Fokus übernehmen | Das Freigabefenster erscheint und übernimmt den Fokus. |

Wählen Sie eine Option und dann "Anwenden". Der "Präsentationsmodus" lässt sich im Tray-Menü umschalten. Er schaltet auf "Nur Kennzeichen" und wird in den Einstellungen nicht gespeichert.

:::

::: server

Wählen Sie auf der Seite Freigaben "Benachrichtigungen aktivieren", damit Ihr Browser Sie meldet, wenn eine Anfrage Ihre Entscheidung braucht. Ihr Browser fragt nach der Erlaubnis. Die Seite meldet dann "Benachrichtigungen sind aktiv." oder, wenn Sie abgelehnt haben, "Benachrichtigungen sind in diesem Browser blockiert." Die Benachrichtigung hat den festen Titel "atlas-duck: Freigabe erforderlich" und zeigt nur die Vorgangs-ID, nie einen von einem Agent geschriebenen Text.

:::

::: desktop

## Befehlszeile installieren {#cli-install}

Agents rufen den Befehl `atlas-duck` aus einem Terminal auf. Der Abschnitt "Befehlszeile" in den Einstellungen zeigt, ob er in Ihrem PATH liegt ("Der Befehl atlas-duck befindet sich in Ihrem PATH." oder "...befindet sich nicht in Ihrem PATH.") und hat die Schaltflächen "CLI im PATH installieren" und "CLI aus dem PATH entfernen". Was die Installation tut, hängt vom System ab:

| System | Installation |
| --- | --- |
| Windows | Fügt den Installationsordner Ihrem Benutzer-PATH hinzu. |
| macOS | Legt den Link `~/.local/bin/atlas-duck` auf das Programm in der App an. |
| Linux AppImage | Schreibt ein Wrapper-Skript `~/.local/bin/atlas-duck` und einen Starter in `~/.local/share/applications`. |
| Linux `.deb` und `.rpm` | Nichts zu tun: Der Befehl liegt bereits im PATH, und die Einstellungen sagen das. |

Öffnen Sie nach einer Installation ein neues Terminal und starten Sie Ihre MCP-Clients neu, damit sie den Befehl finden. Liegt `~/.local/bin` nicht im PATH Ihrer Terminals, weisen die Einstellungen darauf hin, dass Sie es hinzufügen müssen. Wenn Sie die AppImage-Datei verschieben oder umbenennen, wählen Sie "CLI im PATH installieren" erneut: Bis dahin meldet der Wrapper, dass die AppImage nicht gefunden wurde.

## Backup und Wiederherstellung {#backup}

Der Abschnitt "Wiederherstellung und Backup" in den Einstellungen schützt Ihr Audit-Protokoll.

- "Jetzt sichern…" erstellt ein Vollbackup in einem Ordner, den Sie wählen. Erstellen Sie vor jedem Upgrade eines.
- Backups enthalten nie gespeicherte Tokens. Nach einer Wiederherstellung braucht jede Instanz ihr Token erneut.
- Backups und Exporte unterliegen weder der Aufbewahrung noch dem Crypto-Shredding: Aufbewahren und Löschen liegt bei Ihnen.
- "Backup wiederherstellen…" ersetzt dieses Audit-Protokoll durch das Protokoll eines Backups. atlas-duck bittet Sie, in eigenen Dialogen zu bestätigen und die Wiederherstellungs-Passphrase des Backups einzugeben. Anfragen warten, solange die Wiederherstellung läuft. Datensätze, die nach dem Backup geschrieben wurden, sind danach nicht mehr im Protokoll, und gespeicherte Tokens werden gelöscht.
- "Wiederherstellungs-Passphrase ändern…" öffnet das Anmeldedatenfenster. Die Wiederherstellungs-Passphrase entsperrt das Audit-Protokoll nach einem Verlust des Schlüsselbunds, aus einem Backup oder auf einem neuen Computer.

Bevor Sie atlas-duck deinstallieren, führen Sie "Auf die Entfernung vorbereiten" aus: Es kann ein Backup erstellen, löscht die gespeicherten Tokens, bittet Sie, jedes Token auf seinem Server zu widerrufen, und entfernt den Autostart-Eintrag und die Befehlszeile. Das Audit-Protokoll, seine Schlüssel und seine Anker bleiben auf dem Computer.

:::
