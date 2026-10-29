---
id: getting-started-server
title: Erste Schritte (Server)
mode: server
order: 21
---

## Anmelden {#sign-in}

Öffnen Sie die Adresse von atlas-duck, die Ihnen Ihre Organisation genannt hat. Die Seite "Bei atlas-duck anmelden" fragt nach Benutzername und Passwort. Das sind Ihre Zugangsdaten für das Verzeichnis Ihrer Organisation (Domänenanmeldung). atlas-duck prüft das Passwort gegen das Verzeichnis und speichert es nie.

| Meldung | Bedeutung |
| --- | --- |
| Benutzername oder Passwort ist falsch. | Das Verzeichnis hat die Zugangsdaten nicht akzeptiert. |
| Zu viele Versuche. Versuchen Sie es in N Minuten erneut. | Fehlgeschlagene Anmeldungen sind begrenzt. Warten Sie die angezeigte Zeit ab. |
| Das Verzeichnis ist nicht erreichbar. Versuchen Sie es später erneut. | Das Verzeichnis Ihrer Organisation antwortet nicht. |
| Ihr Konto darf atlas-duck nicht verwenden. | Ihr Konto gehört zu keiner der Verzeichnisgruppen, die atlas-duck zulässt, oder es ist deaktiviert. Wenden Sie sich an Ihren Administrator. |
| Die Anmeldung ist fehlgeschlagen. Versuchen Sie es erneut. | Jeder andere Fehler. |

Nach der Anmeldung hält Ihr Browser eine Sitzung. Eine Sitzung ist kurzlebig: Sie endet nach einer Zeit ohne Aktivität und nach einer Höchstdauer, beides legen die Betreiber des Servers fest (standardmäßig 30 Minuten Inaktivität und insgesamt 8 Stunden). Danach melden Sie sich neu an. "Abmelden" in der Kopfzeile beendet die Sitzung sofort.

Die Kopfzeile verweist auf die Seiten, die Sie verwenden können: Freigaben, Zugangsdaten, API-Schlüssel, Verbundene Apps, Mein Audit-Protokoll und, wenn Sie die Rolle haben, Auditor und Administration. Dort finden Sie auch die Sprachauswahl und den Eintrag Hilfe.

## Tokens hinterlegen {#add-credentials}

atlas-duck handelt gegenüber Jira und Confluence als Sie, mit Ihrem eigenen persönlichen Zugriffstoken für jede Instanz. Die Instanzen selbst richtet ein Administrator ein. Öffnen Sie "Zugangsdaten" in der Kopfzeile:

1. Steht auf der Seite "Es ist noch keine Instanz eingerichtet. Instanzen fügt ein Administrator hinzu.", fragen Sie zuerst Ihren Administrator.
2. Wählen Sie bei einer Instanz "Token hinzufügen", fügen Sie das Token ein und wählen Sie "Prüfen und speichern". atlas-duck testet das Token gegen die Instanz, bevor es gespeichert wird.
3. Die Zeile zeigt nun "Token gespeichert", mit dem Atlassian-Benutzer, zu dem es gehört.

Wie Sie das Token erstellen, was die Status bedeuten und was die Fehlermeldungen sagen, steht unter [Instanzen und Tokens](instances-and-tokens#credentials-page).

## Agent verbinden {#connect-agent}

Ein Agent erreicht atlas-duck über MCP auf einem von zwei Wegen:

- Mit einem **API-Schlüssel**, den Sie unter "API-Schlüssel" erstellen. Ein Schlüssel hat Berechtigungen (read, propose_write, scripts), läuft nach 1 bis 90 Tagen ab und lässt sich widerrufen. Siehe [Agents (Server)](agents-server#api-keys).
- Über **OAuth**, wenn Ihre Organisation es aktiviert: Ein MCP-Client, der es unterstützt, schickt Sie zu atlas-duck, damit Sie ihn zulassen. Sie antworten auf der Zustimmungsseite und können die App später unter "Verbundene Apps" widerrufen. Siehe [Agents (Server)](agents-server#oauth-consent).

Weder ein API-Schlüssel noch eine verbundene App kann etwas freigeben. Sie entscheiden auf der Seite "Freigaben": siehe [Freigaben](approvals). Damit Sie benachrichtigt werden, wenn etwas auf Sie wartet, wählen Sie dort "Benachrichtigungen aktivieren" ([Einstellungen](settings#notifications)).

## Rollen {#roles}

Was Sie tun dürfen, hängt von Ihrer Rolle ab, und Ihre Rollen ergeben sich bei der Anmeldung aus Ihren Verzeichnisgruppen.

| Rolle | Was sie darf |
| --- | --- |
| Benutzer | Alle, die sich anmelden können. Sie besitzen Ihre Tokens, geben die Schreibvorgänge Ihrer Agents frei und besitzen Ihre Audit-Kette. |
| Auditor | Liest und exportiert die Audit-Kette jedes Benutzers. Jeder solche Lesezugriff wird in der eigenen Kette des Auditors festgehalten. Siehe [Auditor](auditor). |
| Administrator | Betreibt die Installation: Instanzen, Schlüssel, Backups. Ein Administrator hat keinen Zugriff auf die Tokens oder die Audit-Inhalte der Benutzer. Siehe [Administration](admin). |

Die Links "Auditor" und "Administration" erscheinen in der Kopfzeile nur, wenn Sie die Rolle haben. Wer zu keiner der eingerichteten Gruppen gehört, kann sich nicht anmelden.
