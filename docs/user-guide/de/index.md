---
id: index
title: Übersicht
mode: both
order: 10
---

Dieses Handbuch richtet sich an alle, die atlas-duck verwenden: Benutzer und im Servermodus auch Administratoren und Auditoren.

## Was atlas-duck ist {#what-is-atlas-duck}

atlas-duck lässt KI-Agents Jira und Confluence Data Center lesen und Schreibvorgänge vorschlagen, die Sie freigeben. Jede Aktion wird in einer manipulationssicheren Audit-Kette festgehalten.

Es gibt zwei Betriebsarten:

- **Desktopmodus**: atlas-duck ist auf Ihrem eigenen Computer installiert und läuft dort. Es bedient Sie und die Agents, die auf diesem Computer laufen.
- **Servermodus**: Ihre Organisation betreibt atlas-duck einmal in ihrem eigenen Netz. Es bedient viele Benutzer und ihre Agents. Auf Ihrem Computer wird nichts installiert, Sie arbeiten im Browser.

Für Sie funktionieren beide Modi gleich. Diese Begriffe kehren auf jeder Seite wieder:

| Begriff | Bedeutung |
| --- | --- |
| Agent | Ein KI-Programm, das über atlas-duck in Ihrem Auftrag handelt. Es schlägt Schreibvorgänge vor, gibt aber nie etwas frei. |
| Instanz | Ein Jira- oder Confluence-Data-Center-Server, mit dem atlas-duck spricht, bekannt unter einem Alias. |
| Persönliches Zugriffstoken (PAT) | Ihr eigenes Jira- oder Confluence-Token. atlas-duck handelt immer als Sie, nie als gemeinsames Dienstkonto. |
| Freigabe | Ihr ausdrückliches Ja oder Nein zu einem vorgeschlagenen Schreibvorgang, bevor er eine Instanz erreicht. Jeder Schreibvorgang braucht eine, in beiden Modi. |
| Audit-Kette | Ihr manipulationssicherer Nachweis über alles, was atlas-duck für Sie getan hat. Jeder Benutzer hat eine, in beiden Modi. |

::: server

Im Servermodus kommen drei weitere Begriffe hinzu:

| Begriff | Bedeutung |
| --- | --- |
| Domänenanmeldung | Sie melden sich mit Benutzername und Passwort aus dem Verzeichnis Ihrer Organisation an. Das Passwort wird gegen das Verzeichnis geprüft und nie gespeichert. |
| Rolle | Was Sie tun dürfen: Benutzer, Auditor oder Administrator. Die Rollen ergeben sich aus Ihren Verzeichnisgruppen. |
| API-Schlüssel | Ein Geheimnis, das Sie mit Berechtigungen und Ablaufdatum erstellen und mit dem ein Agent ohne Browser-Anmeldung für Sie handeln kann. |

:::

## So läuft eine Anfrage ab {#how-it-works}

1. Ein Agent bittet atlas-duck um etwas, zum Beispiel ein Jira-Ticket zu lesen oder zu ändern.
2. Die Anfrage erscheint in Ihren Freigaben. Noch erreicht nichts die Instanz.
3. Sie entscheiden. Sie geben einen Schreibvorgang frei, übergeben das Ergebnis eines Lesezugriffs oder eines Skripts an den Agent oder lehnen die Anfrage ab. Ein Agent kann nie etwas freigeben.
4. Nach Ihrer Freigabe sendet atlas-duck die Anfrage als Sie an die Instanz, mit Ihrem eigenen persönlichen Zugriffstoken.
5. atlas-duck hält fest, was geschehen ist, und zwar in Ihrer Audit-Kette.

Eine Anfrage, über die niemand entscheidet, läuft ab.

## Wo Sie anfangen {#where-to-start}

::: desktop

1. [Erste Schritte (Desktop)](getting-started-desktop) installiert atlas-duck und führt durch den ersten Start.
2. [Instanzen und Tokens](instances-and-tokens) verbindet Ihre Jira- und Confluence-Server.
3. [Agents (Desktop)](agents-desktop) zeigt, wie ein Agent atlas-duck erreicht.

:::

::: server

1. [Erste Schritte (Server)](getting-started-server) behandelt die Anmeldung, Ihre Tokens und Ihren ersten Agent.
2. [Instanzen und Tokens](instances-and-tokens) erklärt die Seite Zugangsdaten.
3. [Agents (Server)](agents-server) behandelt API-Schlüssel und verbundene Apps.

:::

Lesen Sie danach [Freigaben](approvals), die Seite, die Sie am häufigsten brauchen, und [Audit-Protokoll](audit). Wenn etwas schiefgeht, helfen [Fehlerbehebung](troubleshooting) und die [Fehlerreferenz](error-reference).
