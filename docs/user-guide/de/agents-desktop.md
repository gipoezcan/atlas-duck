---
id: agents-desktop
title: Agents (Desktop)
mode: desktop
order: 40
---

## Einen Agenten starten {#launcher}

Ein Agent erreicht atlas-duck über den Befehl `atlas-duck`. Er braucht dafür kein eigenes Passwort und kein eigenes Token. Er spricht mit der laufenden Desktop-App auf Ihrem Rechner, und jede Anfrage landet in Ihrer Warteschlange.

Läuft die App nicht, startet der Befehl sie und wartet bis zu 20 Sekunden. Dafür braucht es eine Desktop-Sitzung und eine installierte App; fehlt eines davon, scheitert der Befehl mit `launch_timeout` oder `unreachable`.

Das Fenster „Einführung“ liefert Ihnen fertige Anweisungen für den Agenten. Kopieren Sie sie in die Datei `CLAUDE.md` oder `AGENTS.md` Ihres Projekts. Die Regeln darin lauten:

- Setzen Sie den Namen des Agenten mit `ATLAS_DUCK_AGENT`, zum Beispiel `<Werkzeug>-<Repository>`, und geben Sie immer `--reason` an, damit Sie sehen, warum der Agent anfragt.
- Setzen Sie `--timeout` mindestens 10 Sekunden unter die Zeit, nach der das Werkzeug des Agenten abgebrochen wird. Oder verwenden Sie `--timeout 0`, um die Anfrage einzureichen und sofort zurückzukehren, und holen Sie die Antwort später mit `await` ab.
- Reichen Sie eine ausstehende Anfrage nie erneut ein. Ihre ID finden Sie mit `requests list`; warten Sie dann auf sie.
- Prüfen Sie `redacted`, `edited` und `meta` in der Antwort. Sie haben möglicherweise geändert, was der Agent erhält.
- Entscheiden Sie anhand von `status`, `error.code` und `error.retryable`. Bei Exit-Code 9 versuchen Sie es nicht in einer Schleife erneut: Sie müssen zuerst die App entsperren oder ein Token hinzufügen.
- Blättern Sie durch lange Ergebnisse nur mit `meta.page.next_start`.
- Nennen Sie bei Schreibzugriffen die Dinge so, wie ein Mensch sie nennt, damit Sie die Anfrage lesen können.
- Fassen Sie viele Lesezugriffe in einem Skript zusammen und führen Sie es zuerst als Probelauf aus. Siehe [Skripte](scripts#what-are-scripts).
- Geben Sie unter Windows Dateipfade an. Rufen Sie in WSL das Windows-Programm `atlas-duck.exe` auf.

## Die Befehlszeile {#cli}

```
atlas-duck [Optionen] <Befehl>
```

Optionen für jeden Befehl:

| Option | Bedeutung |
| --- | --- |
| `--agent NAME` | Der Name des Agenten; auch `ATLAS_DUCK_AGENT`. |
| `--reason TEXT` | Warum der Agent anfragt. Sie lesen es in der Warteschlange. |
| `--timeout SEKUNDEN` | Wie lange auf Ihre Entscheidung gewartet wird. Standard 100. `0` reicht ein und kehrt sofort mit `pending` zurück. |
| `--instance ALIAS` | Welche Instanz verwendet wird. |
| `--output json\|text` | Das Format der Antwort. |
| `--help` | Hilfe. |

Befehle:

| Befehl | Zweck |
| --- | --- |
| `call <op-id> --params '<json>'` | Einen Vorgang ausführen. Für eine Datei oder die Standardeingabe verwenden Sie `--params-file <Pfad>` oder `-` statt `--params`. |
| `script run <Datei> [--args <json>] [--limits <json>] [--dry-run[=full\|sparse]]` | Ein Skript ausführen. Siehe [Skripte](scripts#running-scripts). |
| `ops list`, `ops describe <op-id>` | Die Vorgänge finden und beschreiben. |
| `instances` | Ihre Instanzen auflisten. |
| `await <id>` | Auf eine noch offene Anfrage warten. |
| `status <id>` | Eine Anfrage sofort anzeigen. |
| `cancel <id>` | Eine Anfrage zurückziehen. |
| `requests list [--agent NAME] [--state pending\|recent] [--match-params-file <Pfad\|->]` | Anfragen auflisten; damit finden Sie eine Anfrage, die noch aussteht. |
| `doctor` | Die Einrichtung prüfen. |
| `mcp` | Den MCP-Server starten, siehe unten. |
| `verify-export` | Eine exportierte Audit-Datei prüfen. Siehe [Audit-Protokoll](audit#verify). |

Schreib- und Lesezugriffe warten immer auf Ihre Entscheidung. Ein Agent, der `pending` sieht, muss warten und darf nicht erneut anfragen.

## MCP-Clients {#mcp}

Viele Agents sprechen MCP. Tragen Sie atlas-duck in die MCP-Einstellungen des Agenten als Programm ein, das über Standardeingabe und Standardausgabe gestartet wird:

```
atlas-duck mcp [--tools full|generic] [--instance ALIAS] [--agent NAME]
```

Auf der Standardausgabe erscheinen nur JSON-RPC-Nachrichten.

- `--tools full` (Standard) bietet je Vorgang ein Tool, dazu `script_run`, `request_await`, `request_status`, `request_cancel`, `request_list`, `ops_list`, `ops_describe` und `instances_list`.
- `--tools generic` bietet das einzelne Tool `call` und dieselben acht Hilfs-Tools. Der Agent nennt den Vorgang dann als Parameter.

Der Agent übergibt `reason` bei jedem Tool-Aufruf. Die Umgebungsvariable `ATLAS_DUCK_MCP_TIMEOUT` legt in Sekunden fest, wie lange ein Tool-Aufruf auf Sie wartet. Standard ist 50; `0` kehrt sofort mit `pending` zurück. `ATLAS_DUCK_AGENT` setzt den Agentennamen.

Starten Sie den MCP-Server im Agenten nach einem Update von atlas-duck neu, damit der Agent die neue Version verwendet.

## Das Antwortformat {#envelope}

Jeder Befehl gibt auf der Standardausgabe ein JSON-Objekt aus, die Hülle (Envelope). Ihre Schlüssel sind immer dieselben:

| Schlüssel | Inhalt |
| --- | --- |
| `request_id` | Die ID der Anfrage. |
| `op_id` | Der Vorgang. |
| `instance` | Die Instanz. |
| `status` | `pending`, `executing`, `succeeded`, `released`, `denied`, `expired`, `cancelled`, `failed`, `outcome_unknown` oder `abandoned`. |
| `data` | Das Ergebnis, falls es eines gibt. |
| `edited` | Ob Sie die Anfrage vor der Freigabe geändert haben. |
| `redacted` | Ob Sie das Ergebnis geschwärzt haben. |
| `redaction_note` | Ein Hinweis zur Schwärzung. |
| `message` | Ein kurzer Text. |
| `error` | `{code, retryable, message, details?}`, wenn etwas schiefging. |
| `meta` | Zusätzliche Angaben wie Blättern und `dry_run`. |

Der Exit-Code des Befehls fasst das Ergebnis zusammen:

| Exit-Code | Bedeutung |
| --- | --- |
| 0 | `succeeded` oder `released`. |
| 1 | `failed` oder ein interner Fehler. |
| 2 | Falsche Verwendung oder ungültige Eingabe. |
| 3 | `denied`. |
| 4 | Noch `pending` oder `executing`. |
| 5 | atlas-duck ist nicht erreichbar. |
| 6 | Die Instanz ist fehlgeschlagen, oder das Ergebnis ist unbekannt. |
| 7 | `expired`, `cancelled` oder `abandoned`. |
| 8 | Ein Skriptfehler oder -limit, oder keine Sandbox. |
| 9 | Die App ist gesperrt, nicht eingerichtet oder braucht ein Token. |
| 10 | Das Ergebnis ist nicht mehr gespeichert. |
| 11 | atlas-duck ist ausgelastet. |

`status` endet mit 0, sobald es die Anfrage kennt. `verify-export` hat eigene Codes: 0, 20, 21 und 22. Was die einzelnen `error.code` bedeuten, steht in der [Fehlerreferenz](error-reference).
