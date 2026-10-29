---
id: audit
title: Audit-Protokoll
mode: both
order: 70
---

## Was das Audit-Protokoll festhält {#audit-log}

atlas-duck hält alles fest, was rund um eine Anfrage geschieht: dass sie eingegangen ist, was Sie gesehen haben, was Sie entschieden haben, was an die Instanz gesendet wurde und was zurückkam, und was der Agent erhalten hat. Die Datensätze sind verkettet: Jeder enthält einen Fingerabdruck seines Vorgängers, sodass ein geänderter oder entfernter Datensatz die Kette bricht und sich finden lässt. Den Inhalt jedes Datensatzes (die „Nutzdaten“) speichert atlas-duck verschlüsselt.

::: desktop

Das Protokoll gehört Ihnen und liegt auf Ihrem Computer. Sie öffnen es mit „Audit-Protokoll“ in der Kopfzeile des Fensters „Freigaben“. Das Fenster hat diese Bereiche:

- „Prüfung“ mit „Jetzt prüfen“ (siehe [Die Kette prüfen](audit#verify)) und die Liste „Integritätsvorfälle“;
- „Anker-Verzeichnis“: der Ordner, der zusätzliche Kopien des Protokollkopfs enthält, oder „keines“ (siehe unten);
- „Datensätze“: die Liste der Datensätze, neueste zuerst, mit „Filter“;
- „Export und Backup“ (siehe [Das Protokoll exportieren](audit#export)).

:::

::: server

Jeder Benutzer hat ein eigenes, getrenntes Audit-Protokoll. Die Seite „Mein Audit-Protokoll“ in der Kopfzeile zeigt Ihres: die Liste der Datensätze mit Filtern, den Verlauf einer Anfrage und die Nutzdaten eines Datensatzes. Das Lesen Ihres eigenen Protokolls wird nicht festgehalten. Prüfung, Kenntnisnahme von Vorfällen, Backup und Anker-Verzeichnis gehören zur Desktop-App; auf dem Server kümmert sich der Betreiber darum. Benutzer mit der Rolle Auditor können die Protokolle anderer Benutzer lesen, siehe [Die Rolle Auditor](auditor#auditor-role).

:::

**Filter.** Sie können nach Zeitraum („Von (UTC)“, „Bis (UTC)“), „Agent-Name“, „Vorgang“, „Klasse“, „Instanz-ID“, „Ziel (beginnt mit)“, „Entscheidung“ und „Markierungen (eine davon)“ filtern. Die Filter treffen nur auf die Klartextspalten eines Datensatzes zu; Nutzdaten werden nicht durchsucht. „Mehr laden“ setzt eine Suche fort.

**Entscheidungen** im Protokoll sind: freigegeben, freigegeben (bearbeitet), übergeben, übergeben (geschwärzt), abgelehnt, abgelaufen, storniert und zurückgewiesen. **Markierungen** sind: bearbeitet, geschwärzt, Sammelentscheidung, veraltet, Uhr ging zurück, Uhr sprang vor, Uhr geht nach und Integritätsvorfall. Die Uhr-Markierungen kennzeichnen Datensätze, die geschrieben wurden, als die Uhr des Computers zurückging, vorsprang oder hinter dem von den Servern gemeldeten Datum nachging. Sie sorgen dafür, dass eine falsche Uhr die Aufbewahrung nicht verkürzen kann.

**Ein Datensatz.** „Datensatz öffnen“ zeigt die Felder: Zeit (UTC), Ereignis, Anfrage, Vorgang, Klasse, Instanz-ID, Ziel, Entscheidung, Markierungen, Agent-Name und seine Herkunft, Client, Verbindung, Prozess-ID der Gegenstelle, Programm der Gegenstelle, Ursprungsprogramm, Betriebssystem-Benutzer, Atlassian-Benutzer und „Nutzdaten in Bytes“. „Entschlüsselte Nutzdaten anzeigen“ öffnet den Inhalt seitenweise.

**Verlauf einer Anfrage.** „Verlauf der Anfrage“ zeigt alle Datensätze einer Anfrage in der Reihenfolge. „N-mal zugestellt“ zählt, wie oft die Antwort übergeben wurde. „mehrfach zugestellt“ und „an ein anderes Programm zugestellt“ sind Hinweise: Sie vergleichen das Programm, das gefragt hat, mit dem Programm, das die Antwort erhalten hat, und weisen auf etwas hin, das zu prüfen ist, nicht auf einen Beweis.

**Was das Protokoll kann und was nicht.** Das Protokoll zeigt, wer wann was entschieden hat, und es macht spätere Änderungen sichtbar. Es hindert niemanden am Handeln. Es schützt nicht vor Schadsoftware, die als Ihr eigener Benutzer läuft, während Sie angemeldet sind: Solcher Code kann die Schlüssel lesen und das Protokoll umschreiben. Auch der protokollierte Benutzer selbst kann das Protokoll löschen oder zerstörerische Aktionen bestätigen. Schutz davor braucht ein Anker-Verzeichnis, das Sie nicht umschreiben können, siehe [Die Kette prüfen](audit#verify).

Das Protokoll enthält personenbezogene Daten, zum Beispiel Namen und Kommentare aus Jira und Confluence. Gehen Sie mit Exporten entsprechend um.

## Die Kette prüfen {#verify}

Die Prüfung stellt fest, dass die Kette vollständig und unverändert ist: Jeder Datensatz gehört zu seinem Vorgänger, die Nutzdaten passen zu ihren Fingerabdrücken, und der Protokollkopf stimmt mit den an anderer Stelle gehaltenen Kopien überein.

::: desktop

atlas-duck prüft das Protokoll beim Start und einmal täglich im Hintergrund. „Jetzt prüfen“ startet die Prüfung auf Wunsch. Das Ergebnis ist eines von:

| Ergebnis | Bedeutung |
| --- | --- |
| verifiziert | Die Kette ist intakt. |
| Prüfung nicht abgeschlossen | atlas-duck konnte die Prüfung nicht beenden. Das ist kein Befund, dass etwas nicht stimmt; versuchen Sie es erneut. |
| Integritätsvorfall: siehe Audit | Die Prüfung hat etwas Falsches gefunden. Siehe [Integritätsvorfälle](audit#integrity-incident). |

Zwei Arten von Kopien schützen den Kopf der Kette. atlas-duck hält eine im Schlüsselbund Ihres Computers. Das erkennt ein Protokoll, das abgeschnitten wurde, doch wer Ihr Konto kontrolliert, kann auch den Schlüsselbund ändern. Für mehr Schutz legen Sie in den Einstellungen ein **Anker-Verzeichnis** fest („Externes Anker-Verzeichnis“, „Anker-Verzeichnis festlegen…“): atlas-duck schreibt dann einmal täglich und nach wichtigen Änderungen, etwa bei Änderungen von Aufbewahrung oder Legal Hold, Kopien des Protokollkopfs in einen Ordner. Das schützt vor einer umgeschriebenen Historie nur dann, wenn Sie den Ordner nicht selbst umschreiben können, zum Beispiel bei einer Freigabe, die jemand anderes verwaltet und die nur Anhängen erlaubt. atlas-duck bittet Sie, jede Änderung des Anker-Verzeichnisses in einem eigenen Dialog zu bestätigen, weil Ändern oder Entfernen den Schutz schwächt. „Anker-Verzeichnis“ im Fenster Audit-Protokoll zeigt Ihnen, wenn das Schreiben dorthin fehlschlägt; die Zeilen warten dann und werden erneut versucht.

:::

::: server

Der Server prüft Ketten nicht auf den Webseiten. Der Betreiber prüft sie mit `admin anchor verify`. Neben der Kette jedes Benutzers führt der Server eine **Ankerkette**, die sich mindestens alle 15 Minuten auf den Kopf der Kette jedes Benutzers festlegt. Sie macht sichtbar, wenn eine Kette nachträglich verändert oder gekürzt wurde. Auch die Ankerkette schreibt der Server selbst; sie schützt also vor Fehlern einzelner Benutzer und vor Teilschäden, aber nicht vor jemandem, der den Server und seine Schlüssel kontrolliert.

:::

## Das Protokoll exportieren {#export}

Ein Export kopiert die Datensätze eines Zeitraums samt entschlüsselten Nutzdaten, damit jemand anderes sie prüfen kann, zum Beispiel ein Auditor oder der Verantwortliche für Compliance. Die Dateien kann jeder lesen, der sie öffnen kann. Schützen Sie sie so gut wie die Originaldaten.

::: desktop

Im Fenster Audit-Protokoll hat „Compliance-Export“ unter „Export und Backup“ die Felder „Export von (UTC)“ und „Export bis (UTC)“. Lassen Sie beide leer, um das ganze Protokoll zu exportieren. Wählen Sie „Exportieren…“. atlas-duck zeigt eine Warnung und fragt in eigenen Dialogen nach dem Ordner. Es schreibt den Export in einen neuen Ordner und gibt ihm seinen endgültigen Namen erst, wenn alles geschrieben ist. Ein Ordner, dessen Name noch auf „.partial“ endet, ist unfertig und darf nicht weitergegeben werden.

Ist der Export fertig, zeigt atlas-duck ein SHA-256 des Manifests, den Fingerabdruck, der die Dateien zusammenbindet. Geben Sie es dem Empfänger **über einen anderen Kanal** als die Dateien. Ohne es kann der Empfänger nicht sicher sein, dass die Dateien die sind, die Sie erstellt haben.

„Vollbackup“ mit „Jetzt sichern…“ ist etwas anderes: Es sichert das ganze Protokoll mit seinen Wiederherstellungsdaten, damit Sie es wiederherstellen können. Ein Backup enthält nie gespeicherte Tokens, daher braucht nach einer Wiederherstellung jede Instanz wieder ihr Token. Backups und Exporte unterliegen nicht der Aufbewahrung; Aufbewahren und Löschen liegt bei Ihnen.

:::

::: server

Die Exportfunktion finden Sie unter „Mein Audit-Protokoll“. Wählen Sie „Alle Datensätze“ oder „Ab Datum (UTC)“ und dann „Export starten“. Sobald „Der Export ist bereit“ erscheint, verwenden Sie „Herunterladen“. Der Download ist eine tar-Datei mit den Datensätzen, den entschlüsselten Nutzdaten und den weiteren Dateien, die das Prüfprogramm braucht. Die Seite zeigt außerdem das „SHA-256 des Manifests“ und den „Kopf-Anker“. Geben Sie beides dem Empfänger über einen anderen Kanal als das Archiv.

Von demselben Protokoll läuft immer nur ein Export („Ein Export läuft bereits“). Der Server löscht Exportdateien standardmäßig nach 24 Stunden; danach heißt es „Dieser Export ist nicht mehr verfügbar. Starten Sie einen neuen.“

Auditoren können das Protokoll jedes Benutzers auf dieselbe Weise exportieren, siehe [Exporte](auditor#auditor-exports).

:::

## Einen Export mit verify-export prüfen {#verify-export}

Der Empfänger prüft einen Export mit dem Befehl `atlas-duck verify-export`. Er braucht dafür keinen Zugriff auf Ihren Computer oder Server und arbeitet offline.

```
atlas-duck verify-export <Ordner> --manifest-sha256 <hex> [--anchor-dir <Ordner>]
```

Er berechnet jeden Datensatz-Fingerabdruck und die Kette neu, prüft, dass die entschlüsselten Nutzdaten zu ihren Fingerabdrücken passen, und vergleicht das Ergebnis mit dem, was Sie ihm als **Vertrauensanker** geben:

- `--manifest-sha256` ist der Fingerabdruck, den Sie getrennt weitergegeben haben. Er belegt, dass die Dateien die exportierten sind.
- `--anchor-dir` ist eine Kopie des Anker-Verzeichnisses. Sie zeigt, dass die Historie zu dem passt, was dort früher geschrieben wurde.

::: server

Bei einem Server-Export zeigt die Seite den vollständigen Befehl, einschließlich `--anchor-chain <Ordner>/anchor-chain.jsonl` und `--anchor-chain-head <seq>:<hash>`. Die Ankerkette im Archiv ist nur ein Auszug. Ohne den Kopf, den Sie vorgeben, gilt sie als nicht verankert und zählt nichts, weil sich ein in sich stimmiger Auszug vollständig erfinden lässt. Nehmen Sie den Kopf von der Exportseite oder vom Betreiber, nicht aus dem Archiv. Das Server-Image enthält das Prüfprogramm ebenfalls: `atlas-duck-server verify-export …`.

:::

Der Exit-Code sagt Ihnen, wie weit Sie dem Ergebnis trauen können:

| Exit-Code | Bedeutung |
| --- | --- |
| 0 | Verifiziert gegen einen Vertrauensanker, der den ganzen Export abdeckt. |
| 20 | In sich stimmig, aber kein Vertrauensanker deckt alles ab. Der Befehl meldet „internally consistent; trust root NOT verified“. Behandeln Sie das als nicht verifiziert. |
| 21 | Manipulation oder eine Verzweigung: zwei Exporte, die denselben Anfang haben und dann auseinanderlaufen. |
| 22 | Der Befehl konnte nicht laufen: falsche Verwendung, nicht lesbare Dateien oder ein unfertiger Ordner mit „.partial“. |

Eine Verzweigung ist nicht zwingend ein Angriff. Sie entsteht, wenn ein Protokoll aus einem Backup wiederhergestellt wurde, während die alte Installation weiterlief. Die alte Installation sollte außer Betrieb genommen werden.

## Aufbewahrung und Legal Hold {#retention}

Das Audit-Protokoll wird nicht ewig aufbewahrt. Die Aufbewahrungsfrist legt fest, wie lange Datensätze bleiben.

::: desktop

In den Einstellungen hat „Aufbewahrung und Legal Hold“ das Feld „Aufbewahrung des Audit-Protokolls (Tage)“. Der Standard sind 100 Tage, das Minimum 92. atlas-duck löscht die ältesten Datensätze erst, wenn sie älter als die Frist sind, und nur vom Anfang des Protokolls her, damit die Kette prüfbar bleibt. Jede Löschung wird selbst festgehalten. Die Nutzdaten schützen Schlüssel je Monat. Der Schlüssel eines Monats wird vernichtet, sobald ihn kein Datensatz mehr braucht, sodass sich die gelöschten Datensätze nicht aus Resten lesen lassen (Crypto-Shredding).

„Legal Hold (Bereinigung stoppt)“ hält jede Löschung an, und die Schlüssel bleiben. Verwenden Sie es, wenn Sie Datensätze aufbewahren müssen, zum Beispiel für eine Untersuchung. Das Ein- und Ausschalten wird im Protokoll und im Anker-Verzeichnis festgehalten. Das Aufheben oder das Verkürzen der Frist braucht Ihre Bestätigung in der App; eine Änderung allein in der Konfigurationsdatei genügt nicht.

Die Einstellungen zeigen „Bereinigung“. War atlas-duck längere Zeit aus, holt es langsam auf, und die Seite sagt „Die Bereinigung ist N Tage im Rückstand“. „Rückstand jetzt bereinigen“ holt nach Ihrer Bestätigung sofort auf. Wurde die Bereinigung übersprungen, nennen die Einstellungen den Grund, zum Beispiel „Legal Hold ist aktiv“, „noch kein Serverdatum hat das aktuelle Datum bestätigt“ oder „die Systemuhr geht hinter dem Serverdatum nach“. atlas-duck vertraut einem Datum nur, wenn ein Atlassian-Server es bestätigt hat, damit eine falsche Uhr keine Datensätze zu früh löschen kann.

Die Aufbewahrung erreicht keine Backups, keine Exporte und keine Kopien Ihrer Daten, die das Betriebssystem angelegt hat, etwa Snapshots. Sie können weiterhin Datensätze enthalten, die gelöscht wurden. Entfernen Sie sie selbst, wenn Sie sie nicht mehr brauchen. Auch das Deinstallieren von atlas-duck löscht das Protokoll nicht. „Auf die Entfernung vorbereiten“ sagt Ihnen, wie lange der neueste Datensatz noch aufbewahrt werden muss.

:::

::: server

Auf dem Server legt der Betreiber die Aufbewahrungsfrist fest, nicht der einzelne Benutzer. Diese Anleitung beschreibt, was der Server tut, wenn ein Benutzer deaktiviert wird, zum Beispiel weil er die Organisation verlassen hat: Sein Protokoll bleibt für Auditoren standardmäßig 365 Tage lang verfügbar. Danach löscht der Server es samt den Schlüsseln des Benutzers und hält die Löschung in der Ankerkette fest. Ein Auditor, der ein Protokoll länger braucht, muss es vorher exportieren. Backups bleiben davon unberührt: Ein früher erstelltes Backup enthält das gelöschte Protokoll weiterhin, der Betreiber muss also auch alte Backups entfernen.

:::

## Integritätsvorfälle {#integrity-incident}

Ein Integritätsvorfall bedeutet, dass eine Prüfung etwas gefunden hat, das nicht sein sollte. Die Ursache kann harmlos sein, etwa die Wiederherstellung eines Backups, oder eine Manipulation. atlas-duck kann nicht unterscheiden, was es ist.

::: desktop

Tritt er auf, hält atlas-duck den Befund im Protokoll fest, bevor es etwas anderes tut, und zeigt in der App und im Tray ein rotes Banner. Das Fenster Audit-Protokoll listet ihn unter „Integritätsvorfälle“ mit seinem „Ergebnis“ und wann er „Erkannt“ wurde.

Was Sie tun sollten:

1. Ignorieren Sie ihn nicht, und nehmen Sie ihn nicht zur Kenntnis, bevor Sie die Ursache kennen. Informieren Sie den Verantwortlichen für Compliance oder Ihren Administrator.
2. Erstellen Sie einen Export des Protokolls, damit der Zustand erhalten bleibt, siehe [Das Protokoll exportieren](audit#export).
3. Finden Sie die Ursache. Typische Gründe sind: eine Wiederherstellung aus einem älteren Backup, ein verlorener Schlüsselbund-Eintrag oder ein benutztes Anker-Verzeichnis, das zu einer früheren Installation gehört.
4. Wenn Sie ihn verstanden haben, wählen Sie „Integritätsvorfall zur Kenntnis nehmen“, schreiben Sie eine Notiz (bis zu 1000 Zeichen) und bestätigen Sie im eigenen Dialog von atlas-duck. Die Notiz und Ihr Benutzername werden festgehalten. Das rote Banner verschwindet dann für diesen Vorfall.

Die Kenntnisnahme repariert nichts. Sie hält fest, dass Sie den Vorfall gesehen haben und was Sie daraus geschlossen haben. Der Vorfall selbst bleibt im Protokoll.

Melden die Einstellungen, dass ein Anker-Eintrag im Schlüsselbund fehlt, schreibt „Neu verankern…“ ihn aus dem Protokoll in seinem jetzigen Zustand neu. Das ist nur sicher, wenn Sie dem Protokoll vertrauen, und es wird als Integritätsvorfall festgehalten, den Sie dann zur Kenntnis nehmen.

:::

::: server

Der Server zeigt Vorfälle nicht auf den Webseiten. Der Betreiber findet sie mit `admin anchor verify`; der Befehl nennt den Benutzer und den Datensatz, der nicht passt, und endet mit einem Fehler. Wenn Sie vermuten, dass Ihr Protokoll betroffen ist, wenden Sie sich an Ihren Administrator.

:::
