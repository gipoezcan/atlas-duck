---
id: scripts
title: Skripte
mode: both
order: 60
---

## Was Skripte sind {#what-are-scripts}

Mit einem Skript erledigt ein Agent viele Lesezugriffe in einer Anfrage. Es ist JavaScript: der Rumpf von `async function main(args, atlas)`. Darin ruft es Lesevorgänge mit `atlas.<product>.<op>(params)` oder `atlas.call` auf, blättert mit `atlas.all` durch Ergebnisse und kann mit `atlas.ops()` und `atlas.instances()` abfragen, was es gibt. `atlas.log` schreibt eine Notiz.

Ein Skript kann nur lesen. Es kann keine Schreibvorgänge aufrufen, keine Module importieren, keine Dateien öffnen und das Netzwerk nicht nutzen. Es läuft in einer Sandbox, einem eigenen Prozess, den das Betriebssystem einschränkt, und unter Linux und macOS (also auch auf dem Server) geht seine Uhr nach UTC. Unter Windows folgen die Datumsfunktionen für die Ortszeit der Zeitzone des Systems; ein Skript sollte die UTC-Funktionen wie `getUTCHours` oder `toISOString` verwenden.

Ein Skript sendet nie von selbst etwas an den Agenten. Wenn es endet, wartet sein Endergebnis als Anfrage der Klasse „Skript“ in der Warteschlange. Sie sehen es sich an, schwärzen es bei Bedarf und übergeben es, genau wie ein Lesen. Siehe [Freigaben](approvals#approve-or-deny).

Skripte sind in der Größe begrenzt: Der Quelltext darf bis zu 256 KiB groß sein, die Argumente bis zu 1 MiB. atlas-duck übersetzt den Quelltext, sobald der Agent ihn einreicht. Ein Syntaxfehler wird sofort mit `script_syntax` (Exit 8) beantwortet, und es läuft nichts.

## Skripte ausführen {#running-scripts}

::: desktop

Ein Agent reicht ein Skript mit `atlas-duck script run <Datei>` ein oder mit dem Tool `script_run` des MCP-Servers. Siehe [Agents (Desktop)](agents-desktop#cli).

Was gerade läuft, sehen Sie in „Laufende Skripte“ in der Kopfzeile des Fensters „Freigaben“. Läuft nichts, steht dort „Es laufen keine Skripte.“; sonst führt das Fenster je Skript eine Zeile:

| Spalte | Inhalt |
| --- | --- |
| Anfrage | Die Anfrage, zu der das Skript gehört. |
| Agent | Der Name, den der Agent angegeben hat. |
| Instanzen | Die Instanzen, die das Skript verwendet. |
| Gestartet | Wann es gestartet ist. |
| Dauer | Wie lange es schon läuft. |
| Host-Aufrufe | Wie viele Aufrufe an die Instanz es gemacht hat. |
| Abgerufene Bytes | Wie viele Daten es abgerufen hat. |
| Aktionen | „Beenden“. |

:::

::: server

Ein Agent reicht ein Skript über den MCP-Endpunkt mit dem Tool `script_run` ein. Der API-Schlüssel oder die App braucht die Berechtigung `scripts`: „schreibgeschützte Skripte in der Sandbox ausführen; Sie geben jedes Endergebnis frei“. Siehe [Agents (Server)](agents-server#scopes).

Je Benutzer laufen höchstens zwei echte Skripte gleichzeitig, und der Server begrenzt auch die Gesamtzahl. Weitere Skripte warten.

:::

Ein Agent sollte ein Skript zuerst als Probelauf testen (`--dry-run`, Modus `sparse` oder `full`). Ein Probelauf braucht keine Freigabe. Er berührt Ihre Instanzen nicht: Die Aufrufe werden aus den dokumentierten Beispielen des jeweiligen Vorgangs beantwortet, und die Antwort ist mit `meta.dry_run: true` gekennzeichnet. Damit prüfen Sie, ob ein Skript läuft und die richtige Form hat, nicht, um Daten zu lesen.

## Limits und Isolierung {#limits}

Jedes Skript läuft unter Limits, damit ein einzelnes Skript weder Ihren Rechner noch eine Instanz auslastet.

::: desktop

Sie legen sie in den Einstellungen unter „Skript-Limits“ fest:

:::

::: server

Der Server führt Skripte mit den folgenden Standardwerten aus. Sie sind fest; auf dem Server gibt es dafür keine Einstellung.

:::

| Limit | Standard |
| --- | --- |
| Skript-Zeitlimit (s) | 120 |
| Skript-Heap-Limit (MiB) | 256 |
| Skript-Prozesslimit (MiB) | 512 |
| Skript-Aufruflimit | 200 |
| Skript-Abruflimit (MiB) | 50 |
| Skript-Limit je Aufrufergebnis (MiB) | 16 |
| Skript-Ergebnislimit (MiB) | 16 |
| Gleichzeitige Skript-Aufrufe | 4 |

Ein Agent darf niedrigere Limits anfordern (mit `--limits` in der Befehlszeile oder dem Parameter `limits` von `script_run`), nie höhere. Ein Skript, das ein Limit überschreitet, endet mit `script_limit` (Exit 8).

Zwei echte Skripte und zwei Probeläufe können gleichzeitig laufen. Weitere warten. Der Server wendet dieselben Zahlen je Benutzer an.

Das Heap-Limit muss mindestens das 15-Fache des Limits je Aufrufergebnis betragen und das Prozesslimit mindestens das Heap-Limit plus 88 MiB. Die Einstellungen weisen Werte zurück, die das verletzen.

**Isolierung.** Die Sandbox zählt nur, wenn das Betriebssystem sie durchsetzen kann. Beim Start prüft atlas-duck das.

::: desktop

Die Einstellungen zeigen das Ergebnis unter „Skript-Isolierung“: „erfüllt: Skripte dürfen laufen“, „nicht erfüllt: Skripte sind aus“ oder „die Prüfung beim Start ist noch nicht abgeschlossen“. Ist die Isolierung nicht erfüllt, sind Skripte aus, und ein Agent erhält `sandbox_unavailable` (Exit 8). Sie können Skripte trotzdem mit „Skripte mit eingeschränkter Isolierung erlauben“ zulassen; atlas-duck bittet Sie um eine Bestätigung. Danach steht in den Einstellungen „nicht erfüllt: Skripte laufen nur, weil eingeschränkte Isolierung erlaubt ist“, und das Banner zeigt „Vorsicht: Skripte laufen mit eingeschränkter Isolierung“. Bei eingeschränkter Isolierung könnte ein Fehler im Skript-Worker ein Skript als Ihren Benutzer handeln lassen. Wählen Sie das nur auf einem Rechner, dem Sie vertrauen, und nur so lange, wie Sie es brauchen.

:::

::: server

Auf dem Server gibt es keinen eingeschränkten Modus: Ist die Isolierung nicht erfüllt, sind Skripte aus, und Agents erhalten `sandbox_unavailable`. Denselben Fehler erhalten Agents, wenn der Betreiber Skripte abgeschaltet hat. Brauchen Sie Skripte und erhalten diesen Fehler, fragen Sie Ihren Administrator.

:::

## Ein Skript beenden {#stopping}

::: desktop

Um ein Skript zu beenden, verwenden Sie „Beenden“ in „Laufende Skripte“. Die Schaltfläche wechselt zu „Wird beendet…“, und das Fenster antwortet „Beenden angefordert“. Ist das Skript schon zu Ende, sehen Sie „Dieses Skript läuft nicht mehr.“; wird es bereits beendet, „Dieses Skript wird bereits beendet.“

Ein beendetes Skript verschwindet nicht spurlos. Es endet als fehlgeschlagen mit einem Fehler, der besagt, dass der Lauf vom Benutzer beendet wurde, und dieser Fehler wartet als Ergebnis in der Warteschlange. Er enthält keine Daten, die das Skript bis dahin gesammelt hatte. Sie können ihn übergeben, schwärzen oder ablehnen wie jede andere Anfrage.

:::

::: server

Die Serverseiten haben keine Schaltfläche „Beenden“. Ein Skript endet, wenn es fertig ist, sein Zeitlimit erreicht oder seine Anfrage storniert wird oder abläuft. Kommt sein Ergebnis in die Warteschlange, können Sie es ablehnen.

:::

Storniert der Agent eine Anfrage selbst (`atlas-duck cancel <id>`), endet sie als `cancelled`, und ihr Ergebnis erreicht die Warteschlange nie.
