---
id: approvals
title: Freigaben
mode: both
order: 50
---

## Die Warteschlange {#queue}

Nichts, was ein Agent anfordert, verlässt atlas-duck ohne Ihre Entscheidung. Jede Anfrage, die eine Entscheidung braucht, wartet in der Warteschlange unter „Ausstehende Freigaben“. Wartet nichts, steht dort „Keine ausstehenden Anfragen“.

::: desktop

Das Fenster „Freigaben“ ist das Hauptfenster der Desktop-App. Seine Kopfzeile führt zu den übrigen Fenstern: Einstellungen, Audit-Protokoll, Laufende Skripte, Einführung und Beenden. Ein Banner unter der Kopfzeile beginnt mit „Vorsicht:“ oder „Hinweis:“, wenn etwas Ihre Aufmerksamkeit braucht.

:::

::: server

Nach der Anmeldung ist die Seite „Freigaben“ Ihre Startseite. Ihre Kopfzeile führt zu den übrigen Seiten des Servers.

:::

Die Anfragen sind nach Sitzung gruppiert, sodass Sie sehen, welcher Lauf eines Agenten was gesendet hat. Jede Zeile zeigt:

- die Klasse der Anfrage: „Lesen“, „Schreiben“ oder „Skript“;
- die Begründung des Agenten oder „keine Begründung angegeben“;
- wie lange die Anfrage schon wartet;
- Warnungen: „veraltet“ (die Revision hat sich geändert, nachdem Sie die Anfrage geöffnet haben; öffnen Sie sie erneut), „Vorsicht“ (siehe [Ungeprüfter Text](approvals#unverified-text)), „mögliches Duplikat“ und „ähnliche Anfrage“ (eine frühere Anfrage desselben Agenten sieht gleich aus).

Mit „Öffnen“ sehen Sie sich eine Anfrage an. Mit „auswählen“ nehmen Sie eine Zeile in eine [Sammelentscheidung](approvals#batch-decisions) auf, mit „alle der Sitzung auswählen“ alle Zeilen einer Sitzung.

Eine Anfrage, die niemand entscheidet, läuft ab. Der Agent erhält dann `expired`.

## Eine Anfrage lesen {#reading-a-request}

Das Öffnen einer Anfrage füllt den Bereich „Anfragedetails“. Zunächst bietet er nur „Vorschau öffnen“ an. Erst das Öffnen der Vorschau macht eine Entscheidung möglich: Sie entscheiden über das, was Sie gesehen haben.

Der Bereich hat vier Registerkarten:

| Registerkarte | Inhalt |
| --- | --- |
| Vorschau | Was ausgeführt oder an den Agenten gesendet würde, in lesbarer Form. |
| Strukturiert | Derselbe Inhalt als Baum; hier bearbeiten oder schwärzen Sie. |
| Rohdaten | Der genaue Inhalt, Seite für Seite. |
| Anfrage | Wer was angefordert hat. |

Die Registerkarte „Anfrage“ nennt:

- Parameter und deren Prüfsumme `params_sha256`;
- Begründung, Instanz, Vorgang und Ziel;
- Angeforderte Grenzen (nur bei Skripten);
- Eingereicht und Alter;
- Verbindung, Client-Art, Agentenname, Quelle des Agentennamens und `cwd_basename`;
- Verbindungs-ID und die Angaben zum Peer: Peer-PID, Peer-Programm, Ursprungsprogramm des Peers und Peer-Kette.

Den Agentennamen wählt der Agent selbst. Betrachten Sie ihn als Beschriftung, nicht als Beleg dafür, wer anfragt.

## Freigeben, übergeben oder ablehnen {#approve-or-deny}

Welche Schaltflächen erscheinen, hängt von der Klasse der Anfrage ab:

| Anfrage | Schaltflächen | Was geschieht |
| --- | --- | --- |
| Schreiben | „Freigeben“ | atlas-duck führt die Änderung aus. |
| Lesen | „Übergeben“ | Die Daten, die die Instanz geliefert hat, gehen an den Agenten. |
| Skript | „Übergeben“ | Das Endergebnis des Skripts geht an den Agenten. |
| Fehlgeschlagenes Lesen | „Ergebnis übergeben“ oder „Nur Status übergeben“ | Der Agent erhält `failed` (Exit 6) mit dem HTTP-Status, mit oder ohne den Text der Meldung. |
| Jede | „Ablehnen“ | Der Agent erhält `denied` (Exit 3) und Ihre Begründung. |

Unter den Schaltflächen steht in einer Zeile, was der Agent erhalten wird.

Tastenkürzel: Strg/Cmd+Umschalt+Eingabe gibt frei oder übergibt, Strg/Cmd+Umschalt+D lehnt ab, Strg/Cmd+Umschalt+Pfeil runter und Strg/Cmd+Umschalt+Pfeil hoch wechseln zur nächsten und zur vorherigen Anfrage.

Zum Ablehnen öffnet „Ablehnen“ das Formular „Diese Anfrage ablehnen“. Geben Sie die „Begründung für den Agenten“ ein und drücken Sie die Eingabetaste oder wählen Sie „Ablehnung senden“; Esc bricht ab. Der Agent sieht Ihre Begründung, schreiben Sie sie also für den Agenten. Sie können auch einen „Tipp anhängen“: höchstens einen Tipp aus den angebotenen, zum Beispiel den HTTP-Status der Instanz, die Ergebnisklasse, den nicht aufgelösten Namen oder die fehlenden Pflichtfelder. Der Tipp hilft dem Agenten, es mit besserer Eingabe erneut zu versuchen.

## Bearbeiten und schwärzen {#edit-and-redact}

Sie können ändern, was ausgeführt wird, oder Teile dessen zurückhalten, was übergeben wird. Beides erzeugt eine neue Revision der Anfrage. atlas-duck ändert die alte Revision nie.

**Einen Schreibzugriff bearbeiten.** „Vor der Freigabe bearbeiten“ zeigt die Parameter als Felder. Felder, die das Ziel nennen, tragen den Hinweis „schreibgeschützt: zum Ändern des Ziels ablehnen“; ist das Ziel falsch, lehnen Sie ab und lassen den Agenten neu anfragen. Fehlende Pflichtfelder stehen unter „Fehlende Pflichtfelder“. „Bearbeiten und freigeben“ sendet Ihre Änderung, „Änderungen verwerfen“ verwirft sie. Eine Bearbeitung ergibt eine neue Revision: Öffnen Sie deren Vorschau, prüfen Sie sie und geben Sie sie dann in einem zweiten Schritt frei. Solange Änderungen nicht gesendet sind, bleibt „Freigeben“ deaktiviert („Ungesendete Änderungen…“).

**Ein Lesen oder ein Skriptergebnis schwärzen.** „Vor der Übergabe schwärzen“ zeigt den Kandidaten, also die Daten, die an den Agenten gingen, als Baum. Sie können:

- „Eintrag entfernen“: einen Eintrag einer Liste weglassen;
- „Feld entfernen (dieser Eintrag)“ oder „Feld entfernen (alle Einträge)“: ein Feld weglassen;
- „Text maskieren“: einen Text durch `[REDACTED]` ersetzen. Geben Sie den „Zu maskierenden Text“ ein oder verwenden Sie den ausgewählten Text. „Nur dieses Vorkommen“ maskiert nur eine Stelle;
- eine Voreinstellung wählen: „Nur Status übergeben“ oder „Nur Fehlerklasse behalten“;
- mit „Alle Schwärzungen entfernen“ von vorn beginnen.

„Übergeben“ sendet die Schwärzungen und erzeugt eine neue Revision. Öffnen Sie sie, prüfen Sie, was der Agent erhielte („Übergebene Größe“ nennt die Zahl der Bytes), und übergeben Sie sie dann.

Kommt der Text, den Sie maskieren wollen, auch an anderer Stelle vor, sagt atlas-duck Ihnen, wo. „Trotzdem übergeben: Die anderen Vorkommen bleiben in dem, was der Agent erhält“ ist Ihre ausdrückliche Entscheidung, sie stehen zu lassen.

**Wenn eine Übergabe blockiert ist.** atlas-duck verweigert eine Übergabe, die preisgeben könnte, was Sie geschwärzt haben, und nennt den Grund:

| Meldung | Bedeutung und was zu tun ist |
| --- | --- |
| ein maskierter Text kommt weiterhin vor | Der Text steht noch da, zum Beispiel in einem anderen Feld. Maskieren Sie ihn auch dort oder entfernen Sie das Feld. |
| ein Wert ändert sich nach 3 Dekodierungsrunden weiterhin | Ein Wert ist in Schichten kodiert, die sich nicht zuverlässig prüfen lassen. Entfernen Sie den Eintrag oder das Feld. |
| ein Treffer ließ sich nicht sauber maskieren | Der Text steckt in einem kodierten Wert. Entfernen Sie stattdessen den Eintrag oder das Feld. |
| ein gespiegelter Eintrag hat keine Entsprechung | Zwei Listen im Ergebnis gehören zusammen, und ein Eintrag hat keinen Partner. Verwenden Sie „Markierte Einträge entfernen“. |
| gespiegelte Einträge lassen sich nicht zuordnen | Dasselbe, nur kann atlas-duck nicht erkennen, welche Einträge zusammengehören. Verwenden Sie „Markierte Einträge entfernen“. |
| eine Schwärzung nennt nichts im Kandidaten | Die Schwärzung passt nicht mehr zu den Daten. Entfernen Sie sie. |
| der geschwärzte Kandidat überschreitet die Übergabegrenze von 16 MiB | Das Ergebnis ist zu groß für eine Übergabe. Entfernen Sie Einträge oder Felder oder lehnen Sie ab. |

Haben Einträge keine Entsprechung, listet der Bereich sie auf („Diese Einträge haben keine Entsprechung und blockieren die Übergabe:“). Lässt sich der Kandidat nicht exakt erstellen, ist die Übergabe ebenfalls blockiert; lehnen Sie die Anfrage ab oder entfernen Sie die markierten Einträge.

## Sammelentscheidungen {#batch-decisions}

Warten viele gleichartige Anfragen, entscheiden Sie sie gemeinsam. Wählen Sie die Zeilen aus oder verwenden Sie „alle der Sitzung auswählen“, dann erscheint die Leiste „Sammelentscheidung“. „N ausgewählte freigeben oder übergeben“ zeigt zuerst, was geschehen wird, zum Beispiel wie viele Lesezugriffe und Skripte übergeben und wie viele Schreibzugriffe freigegeben werden. Dann bestätigen Sie mit „Bestätigen“, und die Desktop-App fragt noch einmal mit einer nativen Bestätigung nach.

Eine Sammelentscheidung gilt ganz oder gar nicht. Hat sich auch nur eine Anfrage inzwischen geändert, wird die gesamte Sammelentscheidung zurückgewiesen: „Die Sammelentscheidung wurde zurückgewiesen, und es wurde nichts entschieden“. Der Grund wird je Anfrage genannt:

- die Revision hat sich geändert (veraltet);
- die Vorschau wurde nicht geöffnet;
- die Anfrage ist nicht freigabefähig;
- sie ist als mögliches Duplikat oder ähnliche Anfrage markiert und muss einzeln freigegeben werden;
- sie ist nicht mehr ausstehend;
- ihr Ziel kann nicht bearbeitet werden.

Eine Anfrage, die Sie selbst ansehen wollen, nehmen Sie aus der Sammelentscheidung heraus: Sie zeigt dann „Nicht Teil der Sammelentscheidung“, oder Sie wählen „einzeln freigeben“.

Um gesammelt abzulehnen, verwenden Sie „Ausgewählte ablehnen“ oder „Alle ausstehenden dieser Sitzung ablehnen“. Beide verlangen eine Begründung für den Agenten und senden sie mit „Ablehnung senden“.

## Braucht Aufmerksamkeit {#needs-attention}

Unter der Warteschlange listet „Zuletzt entschieden (24 Std.)“ auf, was in den letzten 24 Stunden entschieden wurde. Einträge unter „Braucht Aufmerksamkeit“ sind freigegebene Schreibzugriffe, die nicht gut ausgegangen sind: Der Schreibzugriff ist fehlgeschlagen, endete mit unbekanntem Ergebnis oder traf auf einen Versionskonflikt. „Ziel prüfen“ heißt: Sehen Sie sich das Jira- oder Confluence-Objekt selbst an, denn bei unbekanntem Ergebnis kann atlas-duck nicht sagen, ob die Änderung stattgefunden hat.

Mit „Zur Kenntnis nehmen“ nehmen Sie einen Eintrag aus der Liste, mit „Alle zur Kenntnis nehmen“ alle. Wurde nichts entschieden, steht in der Liste „In den letzten 24 Stunden wurde nichts entschieden“.

Die Statusbezeichnungen, denen Sie begegnen, sind: ausstehend, wird ausgeführt, erfolgreich, übergeben, abgelehnt, abgelaufen, storniert, fehlgeschlagen, abgebrochen, Ergebnis unbekannt und „zur erneuten Prüfung zurückgegeben“.

## Ungeprüfter Text {#unverified-text}

Alles, was ein Agent schreibt, ist nicht vertrauenswürdig: die Begründung, der Agentenname und die Parameter. atlas-duck kennzeichnet deshalb, was es nicht prüfen konnte.

- „ungeprüft“ kennzeichnet einen Text, den der Agent geschrieben hat und der nicht geprüft wurde.
- „ungewöhnliche Zeichen“ kennzeichnet einen Text mit Zeichen, die unsichtbar oder leicht mit anderen zu verwechseln sind. Sie werden sichtbar gemacht, damit Sie sie erkennen.
- „Vorsicht:“ in einer Anfrage ist eine Warnung von atlas-duck, dass Sie die Anfrage genau lesen sollten, bevor Sie entscheiden.

Lesen Sie gekennzeichneten Text langsam und lehnen Sie im Zweifel ab. Eine Ablehnung kostet den Agenten eine neue Anfrage; eine falsch freigegebene Anfrage kann Sie eine Änderung kosten, die sich nicht rückgängig machen lässt.
