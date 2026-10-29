---
id: agents-server
title: Agents (Server)
mode: server
order: 41
---

## API-Schlüssel {#api-keys}

Mit einem API-Schlüssel erreicht ein Agent atlas-duck in Ihrem Namen über MCP. Ein Schlüssel gibt nie etwas frei: Jede Anfrage des Agenten wartet weiterhin in Ihrer [Warteschlange](approvals#queue).

Öffnen Sie „API-Schlüssel“ in der Kopfzeile. So erstellen Sie einen Schlüssel:

1. Geben Sie einen „Name“ mit 1 bis 64 Zeichen ein, zum Beispiel den Namen des Agenten oder des Werkzeugs.
2. Wählen Sie die Berechtigungen, siehe [Berechtigungen](agents-server#scopes). Wählen Sie mindestens eine.
3. Geben Sie „Läuft ab in (Tagen, 1–90)“ ein.
4. Wählen Sie „Schlüssel erstellen“.

atlas-duck zeigt den Schlüssel nur einmal: „Dieser Schlüssel wird nur jetzt angezeigt.“ Verwenden Sie „Kopieren“, fügen Sie ihn in die Einstellungen Ihres Agenten ein und wählen Sie „Fertig“. atlas-duck kann ihn danach nicht erneut anzeigen. Haben Sie ihn verloren, erstellen Sie einen neuen.

Der Agent sendet den Schlüssel als `Authorization: Bearer adk_…`. Die Liste zeigt je Schlüssel den Namen, das Präfix (die ersten Zeichen, an denen Sie ihn erkennen), die Berechtigungen, wann er abläuft und zuletzt verwendet wurde sowie seinen Status: Aktiv, Widerrufen oder Abgelaufen. Sie können höchstens 25 aktive Schlüssel haben.

„Widerrufen“ stoppt einen Schlüssel: „Den Schlüssel „Name“ widerrufen? Agents, die ihn verwenden, funktionieren sofort nicht mehr.“ Widerrufen Sie jeden Schlüssel, den Sie nicht mehr brauchen, und jeden, der durchgesickert sein könnte.

## Berechtigungen {#scopes}

Eine Berechtigung (Scope) legt fest, was ein Schlüssel oder eine App anfordern darf. Wählen Sie die kleinste Menge, die der Agent braucht.

| Berechtigung | Bedeutung |
| --- | --- |
| `read` | Daten lesen und auf Ihre Entscheidungen warten. |
| `propose_write` | Änderungen zur Freigabe durch Sie vorschlagen. |
| `scripts` | Schreibgeschützte Skripte in der Sandbox ausführen; Sie geben jedes Endergebnis frei. |

Auch mit allen Berechtigungen kann ein Agent nichts entscheiden. Was er liest, erreicht ihn erst, nachdem Sie es übergeben haben, und jede Änderung braucht Ihre Freigabe. Siehe [Freigaben](approvals#approve-or-deny) und [Skripte](scripts#what-are-scripts).

## Verbundene Apps {#connected-apps}

„Verbundene Apps“ listet die Apps auf, denen Sie erlaubt haben, atlas-duck über MCP mit OAuth zu verwenden. Auch eine App gibt nie etwas frei.

Die Tabelle zeigt die App, „Rückkehr zu“ (die Adresse, zu der die App nach Ihrer Antwort zurückkehrt), die Berechtigungen, wann Sie sie erlaubt haben, wann sie zuletzt verwendet wurde und wann sie abläuft, sowie ihren Status: Aktiv, Widerrufen oder Abgelaufen.

„Widerrufen“ schneidet eine App ab: „Die App verliert sofort den Zugriff.“ Will sie zurückkehren, muss sie erneut um Ihre Erlaubnis bitten.

OAuth steht zur Verfügung, wenn Ihre Organisation es aktiviert hat. Fehlt die Seite oder der Ablauf, fragen Sie Ihren Administrator; API-Schlüssel funktionieren weiterhin.

## Eine App autorisieren {#oauth-consent}

Wenn Sie atlas-duck in einem MCP-Client hinzufügen, der OAuth unterstützt, öffnet der Client Ihren Browser auf der Seite „Einer App die Nutzung von atlas-duck erlauben?“. Melden Sie sich zuerst an, falls atlas-duck danach fragt. Die Seite zeigt:

- den Namen der App, gekennzeichnet mit „ungeprüft, von der App gewählt“: Jeder kann sich einen beliebigen Namen geben, vertrauen Sie ihm also nicht;
- „Nach Ihrer Antwort kehren Sie zurück zu“: die Adresse, zu der Ihr Browser als Nächstes geht. Prüfen Sie, dass Sie sie erwarten;
- was „Die App möchte“: `read` ist immer enthalten, `propose_write` und `scripts` erscheinen, wenn die App sie anfordert.

Sie können Berechtigungen abwählen, aber nie hinzufügen. Wählen Sie „Erlauben“ oder „Ablehnen“. Sind Sie bei einer App unsicher, wählen Sie „Ablehnen“: Dann wird nichts erlaubt. Eine erlaubte App können Sie jederzeit unter „Verbundene Apps“ widerrufen. Jede Autorisierung fragt erneut; atlas-duck merkt sich die Antwort nicht für die nächste App.

Eine App behält ihren Zugriff mit kurzlebigen Tokens, die sie selbstständig erneuert. Eine Zugriffserlaubnis gilt höchstens 90 Tage.

## Der MCP-Endpunkt {#mcp-endpoint}

Der MCP-Endpunkt des Servers ist seine öffentliche Adresse mit angehängtem `/mcp`, zum Beispiel `https://atlas-duck.example.org/mcp`. Die Adresse nennt Ihnen Ihr Administrator.

Ein Agent oder eine App verbindet sich damit als entfernter MCP-Server:

- Mit einem API-Schlüssel setzen Sie den Header `Authorization: Bearer adk_…`.
- Mit OAuth findet der Client selbst heraus, wo er sich anmeldet: Er fragt `/mcp` an, liest die `.well-known`-Dokumente des Servers, registriert sich als öffentlicher Client und verwendet PKCE. Sie sehen nur die Seite „Einer App die Nutzung von atlas-duck erlauben?“.

Die Tools sind dieselben wie auf dem Desktop: Vorgänge, `script_run` (braucht die Berechtigung `scripts`) und die Anfrage-Tools zum Abwarten, Prüfen, Stornieren und Auflisten von Anfragen. Anfragen, Status und Fehler bedeuten dasselbe wie auf dem Desktop; siehe [Fehlerreferenz](error-reference).

Weder ein Schlüssel noch eine App kann die Freigabefunktionen des Servers verwenden. Entscheiden können nur Sie, angemeldet im Browser.
