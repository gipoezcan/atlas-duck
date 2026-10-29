---
id: admin
title: Administration
mode: server
order: 90
---

## Benutzer und Rollen {#users-and-roles}

Der Server kennt drei Rollen: Benutzer, Administrator und Auditor. atlas-duck führt weder Passwörter noch eine eigene Liste der Rollen. Eine Person meldet sich mit ihrem Verzeichniskonto an, und die Gruppen dieses Kontos bestimmen die Rolle. Ihr Betreiber hat jeder Rolle eine Verzeichnisgruppe zugeordnet (`GROUP_USERS`, `GROUP_ADMINS`, `GROUP_AUDITORS`). Um eine Rolle zu geben oder zu nehmen, ändern Sie die Gruppenmitgliedschaft im Verzeichnis. Wer in keiner der Gruppen ist, kann sich nicht anmelden.

| Rolle | Darf |
| --- | --- |
| Benutzer | Die Warteschlange verwenden, eigene Tokens speichern, API-Schlüssel erstellen und das eigene Audit-Protokoll lesen. |
| Administrator | Alles, was ein Benutzer darf, und auf der Seite „Administration“ die Instanzen verwalten. |
| Auditor | Das Audit-Protokoll jedes Benutzers lesen, siehe [Die Rolle Auditor](auditor#auditor-role). |

Administratoren haben keinen Zugriff auf die Audit-Protokolle anderer Benutzer. Ein Administrator sieht auch kein gespeichertes Token; das kann niemand, denn atlas-duck zeigt ein gespeichertes Token nie an.

**Einen Benutzer deaktivieren.** Verlässt jemand die Organisation, deaktiviert der Betreiber das Konto mit `admin users deactivate <Benutzername>`. Auf den Webseiten gibt es dafür keine Schaltfläche. Das Deaktivieren ist endgültig und bewirkt sofort Folgendes: Die Sitzungen der Person enden, ihre API-Schlüssel und OAuth-Erlaubnisse werden widerrufen, und ihre gespeicherten Tokens werden gelöscht. Jeder dieser Schritte wird im Audit-Protokoll der Person festgehalten. Eine deaktivierte Person kann sich nie wieder anmelden, auch wenn das Verzeichnis sie weiterhin führt. `admin users list` zeigt jeden Benutzer mit Rollen, letzter Anmeldung und Status: aktiv, deaktiviert oder gelöscht.

Ob der Server ausgeschiedene Benutzer selbst bemerkt, hängt davon ab, wie Ihr Betreiber ihn eingerichtet hat. Ohne ein schreibgeschütztes Verzeichniskonto weist der Server ein gesperrtes Konto erst bei der nächsten Anmeldung zurück, und bis dahin funktionieren die API-Schlüssel der Person weiter. Dann ist es Aufgabe des Betreibers, am Tag des Ausscheidens von Hand zu deaktivieren. Fragen Sie Ihren Betreiber, welcher Fall bei Ihnen gilt.

## Instanzen verwalten {#instances-admin}

Als Administrator legen Sie die Jira- und Confluence-Instanzen für alle fest. Öffnen Sie „Administration“ in der Kopfzeile. Die Seite „Instanzen“ sagt: „Jeder Benutzer sieht diese Instanzen und gibt für jede sein eigenes Token ein.“ Benutzer fügen selbst keine Instanzen hinzu, siehe [Instanzen und Tokens](instances-and-tokens).

Die Tabelle führt jede Instanz mit URL, Proxy, „Organisations-CA“ und „Standard“ auf. Zum Hinzufügen füllen Sie „Instanz hinzufügen“ aus:

| Feld | Bedeutung |
| --- | --- |
| Alias | Der Kurzname, den Benutzer und Agents verwenden. Buchstaben, Ziffern, `-` und `_`. |
| Produkt | Jira oder Confluence. |
| Basis-URL | Die Adresse des Servers. Sie muss mit `https://` beginnen. |
| Proxy (optional: direct, system oder eine Proxy-URL) | Wie atlas-duck den Server erreicht. |
| CA-Bundle der Organisation verwenden | Das Serverzertifikat gegen die Zertifizierungsstelle der Organisation prüfen, die Ihr Betreiber installiert hat. Verwenden Sie das für Server mit einem internen Zertifikat. |
| Standardinstanz für dieses Produkt | Kennzeichnet die Standardinstanz ihres Produkts. Ein Produkt kann nur eine Standardinstanz haben. |

Wählen Sie „Instanz hinzufügen“. Die Meldungen sagen Ihnen, was nicht stimmt: Der Alias existiert bereits, die Instanz ist nicht gültig, oder die Änderung ist fehlgeschlagen.

„Entfernen“ entfernt eine Instanz für alle. atlas-duck fragt zuvor: „Die Instanz ALIAS entfernen? Die Tokens aller Benutzer für diese Instanz werden gelöscht.“ Jeder Benutzer muss dann ein neues Token speichern, falls die Instanz wiederkommt. Das Entfernen wird im Audit-Protokoll jedes betroffenen Benutzers festgehalten.

Instanzen lassen sich auch in der Befehlszeile im Server-Container verwalten, mit `admin instances list`, `add` und `remove`.

## Wartung {#maintenance}

Manche Arbeiten brauchen einen stillstehenden Server, zum Beispiel das Wiederherstellen eines Backups. Der Betreiber schaltet den Server mit `admin maintenance on` in den Wartungsmodus. Solange er aktiv ist, antwortet jede Seite und jede Anfrage außer den Health-Probes und den Metriken mit 503, und die Seiten sagen „Der Server befindet sich in Wartung.“ Es geht nichts verloren; versuchen Sie es später erneut. Nach der Arbeit schaltet der Betreiber die Wartung wieder ab.

Was der Betreiber tut, beschreiben die Betriebsdokumente, die zum Server gehören: Backup und Wiederherstellung, Wechsel des Hauptschlüssels, Offboarding und die tägliche Bereinigung der Aufbewahrung. Sie setzen Zugriff auf den Server-Container voraus und gehören nicht zu den Webseiten. Dauert die Wartung länger als erwartet, fragen Sie Ihren Betreiber.
