---
id: auditor
title: Auditor
mode: server
order: 100
---

## Die Rolle Auditor {#auditor-role}

Ein Auditor kann das Audit-Protokoll jedes Benutzers lesen, damit die Organisation prüfen kann, was Agents getan haben und wer entschieden hat. Die Rolle kommt aus einer Verzeichnisgruppe, siehe [Benutzer und Rollen](admin#users-and-roles). Benutzer ohne sie sehen die Seite nicht, und der Server weist die Anfragen mit „Nur für Auditoren.“ zurück.

Die Rolle gibt Lese- und Exportzugriff auf Audit-Protokolle, nicht mehr. Über diese Seiten kann niemand ein Protokoll ändern. Administratoren erhalten diesen Zugriff nicht: Die Rollen sind getrennt.

Auch das Auditieren wird protokolliert. Jedes Mal, wenn ein Auditor Benutzer auflistet, einen Datensatz, einen Verlauf oder Nutzdaten öffnet oder einen Export startet oder herunterlädt, schreibt atlas-duck einen Datensatz darüber in das eigene Protokoll des Auditors und in die Ankerkette des Servers: welche Aktion, und wessen Protokoll. Lässt sich dieser Datensatz nicht schreiben, weist der Server die Anfrage zurück und liefert nichts. Die Seite sagt deshalb: „Jede Ansicht wird in Ihrer eigenen Audit-Kette festgehalten.“ Das Lesen berührt das Protokoll der gelesenen Person nicht. Ein Export hält dagegen einen Export im Protokoll dieser Person fest.

Das Audit-Protokoll enthält personenbezogene Daten: Namen, Kommentare und den Inhalt, den Agents gelesen haben. Lesen Sie nur, was Ihre Aufgabe erfordert, und behandeln Sie Exporte als personenbezogene Daten.

## Das Audit-Protokoll lesen {#reading-the-audit}

Öffnen Sie „Auditor“ in der Kopfzeile. Die Seite „Benutzer“ listet jeden Benutzer auf, auch deaktivierte. „Nach Benutzername suchen“ findet eine Person, und „Status“ schränkt die Liste auf „Aktiv“ oder „Deaktiviert“ ein („Alle“ zeigt jeden). Das Protokoll eines deaktivierten Benutzers bleibt bis zum Ablauf der Aufbewahrungsfrist lesbar, siehe [Aufbewahrung und Legal Hold](audit#retention).

Wählen Sie einen Benutzer, um sein Protokoll zu öffnen. Das Banner erinnert Sie: „Sie sehen die Audit-Kette von NAME. Jede Ansicht wird in Ihrer eigenen Audit-Kette festgehalten.“ Die Ansicht entspricht „Mein Audit-Protokoll“: Filter, die Liste der Datensätze, der Verlauf einer Anfrage und die entschlüsselten Nutzdaten. Wie Sie sie lesen, steht unter [Was das Audit-Protokoll festhält](audit#audit-log). „Zurück zu den Benutzern“ führt zur Liste zurück.

## Exporte {#auditor-exports}

Ein Auditor kann das Protokoll jedes Benutzers als tar-Archiv exportieren, zum Beispiel für den Verantwortlichen für Compliance. Wählen Sie in der Ansicht des Benutzers „Alle Datensätze“ oder „Ab Datum (UTC)“ und dann „Export starten“. Sobald „Der Export ist bereit“ erscheint, verwenden Sie „Herunterladen“. Die Datei steht nur begrenzte Zeit zur Verfügung (standardmäßig 24 Stunden), und die Seite sagt, dass sie sich einmal herunterladen lässt. Nur der Auditor, der einen Export gestartet hat, kann ihn sehen und herunterladen, und nur solange er die Rolle noch hat.

Die Seite zeigt, was der Empfänger zum Prüfen des Exports braucht: das „SHA-256 des Manifests“ und den „Kopf-Anker“. Mit „Kopieren“ kopieren Sie sie. „Geben Sie dem Empfänger das SHA-256 des Manifests und den Kopf-Anker über einen anderen Kanal als das Archiv.“ Ohne sie kann der Empfänger nicht sicher sein, dass das Archiv das echte ist.

Der Empfänger prüft das Archiv offline mit dem Befehl, der unter „Prüfen mit“ steht. Die Schritte und die Exit-Codes stehen unter [Einen Export mit verify-export prüfen](audit#verify-export). Beachten Sie, dass das Archiv entschlüsselte Nutzdaten und einen Auszug der Ankerkette enthält; der Auszug zeigt die Hashes der Protokollköpfe anderer Benutzer und wie viele Benutzer verankert wurden, aber keine Namen und keinen Inhalt.
