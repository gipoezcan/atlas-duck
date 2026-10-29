---
id: troubleshooting
title: Fehlerbehebung
mode: both
order: 110
---

## Eine Instanz ist nicht erreichbar {#cannot-connect}

Anzeichen: Agents erhalten `unreachable`, `upstream_network` oder `upstream_unavailable`; eine Token-Prüfung meldet, dass die Instanz nicht erreichbar ist (`pat/instance_unreachable` auf dem Server).

Unterscheiden Sie zuerst zwei Fälle. Lautet der Fehler `unreachable` mit dem Grund `not_running` oder `launch_timeout`, ist die App nicht erreichbar, nicht die Instanz. Siehe [`unreachable`](error-reference#err-unreachable). Sonst liegt es an der Instanz:

1. Öffnen Sie die Adresse der Instanz in einem Browser auf demselben Computer. Lädt sie nicht, liegt die Ursache beim Netzwerk, beim VPN oder bei der Instanz selbst. atlas-duck kann nicht mehr als Ihr Browser.
2. Prüfen Sie den Status der Instanz. Auf dem Desktop listen die Einstellungen ihn unter „Instanzen“ auf. Die Status „unbestätigt“, „braucht Token“ und „unsicheres Schema (http)“ sagen, was zu tun ist, siehe [Instanzen und Tokens](instances-and-tokens).
3. Nutzt die Instanz eine interne Zertifizierungsstelle, fügen Sie sie als eigene CA der Instanz hinzu oder bitten Sie auf dem Server den Administrator, das CA-Bundle der Organisation zu verwenden.
4. Brauchen Sie einen Proxy, legen Sie ihn für die Instanz fest. Die Desktop-App wertet keine Proxy-Auto-Config-Skripte aus: Geben Sie den Proxy als Host und Port an.
5. `upstream_unavailable` mit `identity_header_missing` oder `identity_header_mismatch` bedeutet, dass ein Proxy vor Jira den Header `X-AUSERNAME` entfernt oder verändert. Fragen Sie die Jira-Administration.

Eine Anfrage, die mit `upstream_network` scheiterte, bevor sie gesendet wurde, lässt sich einfach erneut senden.

## Ein Token wird zurückgewiesen {#token-rejected}

Anzeichen: „Die Instanz hat das Token zurückgewiesen.“, Status „braucht Token“, Agents erhalten `needs_token`.

- Das Token ist möglicherweise falsch eingegeben oder beim Kopieren abgeschnitten worden. Fügen Sie es erneut ein.
- Das Token ist möglicherweise in Jira oder Confluence abgelaufen oder widerrufen worden. Erstellen Sie dort ein neues persönliches Zugriffstoken und ersetzen Sie das gespeicherte.
- Das Token muss zu Ihrem eigenen Konto gehören. Ersetzen Sie es durch das Token eines anderen Atlassian-Benutzers, weist atlas-duck es zurück: „Dieses Token gehört einem anderen Atlassian-Benutzer. Entfernen Sie zuerst das gespeicherte Token.“
- Auf dem Server zeigt die Seite „Zugangsdaten“ „Token gespeichert, nicht verwendbar“, wenn die Instanz das gespeicherte Token zurückweist.

Siehe [Instanzen und Tokens](instances-and-tokens). Agents dürfen `needs_token` nicht in einer Schleife wiederholen: Es heilt nicht von selbst, siehe [`needs_token`](error-reference#err-needs-token).

## Eine Anfrage bleibt offen {#nothing-happens}

Eine Anfrage wartet, bis Sie entscheiden. Sie hängt nicht, sie wartet auf Sie. Prüfen Sie:

1. Öffnen Sie das Fenster „Freigaben“ und sehen Sie unter „Ausstehende Freigaben“ nach. Die Anfrage wartet vielleicht dort, womöglich unter anderen.
2. Ist nichts aufgelistet, ist die Anfrage möglicherweise abgelaufen, abgelehnt oder storniert worden. Sehen Sie unter „Zuletzt entschieden (24 Std.)“ nach.
3. Sieht der Agent Ihre Entscheidung nicht, hat er möglicherweise aufgehört zu warten. Ein Agent, der mit einem kurzen `--timeout` eingereicht hat, erhält `pending` und muss das Ergebnis mit `await <id>` holen. Er darf die Anfrage nie erneut einreichen.
4. Hat der Agent die ID verloren, findet er die Anfrage mit `requests list`.
5. Eine Anfrage kann auch warten, weil die App neu gestartet wurde: Anfragen, die dann ausstanden, werden `abandoned`.

Ein Schreibzugriff, den Sie freigegeben haben, kann eine Weile „wird ausgeführt“ zeigen. Endet er als `outcome_unknown`, prüfen Sie das Ziel selbst, siehe [`upstream_unknown_outcome`](error-reference#err-upstream-unknown-outcome).

## Die App ist gesperrt {#locked}

Anzeichen: Agents erhalten `locked` (Exit 9); das Tray zeigt eine Wartemeldung oder eine Sperrmeldung.

Dies betrifft die Desktop-App. Die App ist gesperrt, wenn sie den Schlüssel zu ihrem Audit-Protokoll nicht bekommt. `details.reason` sagt Ihnen, um welchen Fall es sich handelt:

- **`keychain_unavailable`**: Der Schlüsselbund des Systems ist noch nicht bereit, was direkt nach der Anmeldung vorkommen kann. atlas-duck versucht es ein bis zwei Minuten lang erneut und bietet dann einen manuellen neuen Versuch an. Entsperren oder starten Sie Ihren Schlüsselbund; unter Linux braucht das einen Secret-Service-Anbieter wie GNOME Keyring oder KWallet.
- **`keychain_lost`**: Die Schlüsselbund-Einträge sind weg, zum Beispiel nach einem Passwort-Reset, dem Löschen des Profils oder einer Neuinstallation. Das Protokoll ist unversehrt. Das Fenster für die Zugangsdaten bietet an, das Protokoll wiederherzustellen: Geben Sie Ihre Wiederherstellungs-Passphrase ein. Danach braucht jede Instanz wieder ihr Token, und es wird ein Integritätsvorfall festgehalten, den Sie zur Kenntnis nehmen, siehe [Integritätsvorfälle](audit#integrity-incident). Ohne die Passphrase bleibt nur, das alte Protokoll zu archivieren und neu zu beginnen; das alte Protokoll wird dann beiseitegelegt, und Sie müssen es für seine Aufbewahrungsfrist behalten.
- **`keyring_not_local`**: Die Dateien des Schlüsselbunds liegen auf einem Netzlaufwerk. atlas-duck verwendet einen solchen Schlüsselbund nicht, weil zwei Computer ihre Einträge gegenseitig überschreiben würden. Verwenden Sie ein lokales Home-Verzeichnis.

Löschen Sie nie die Schlüsselbund-Einträge oder das Datenverzeichnis, um die Sperre loszuwerden: Damit verlieren Sie das Audit-Protokoll. Siehe [`locked`](error-reference#err-locked).

## Der Speicher für das Audit-Protokoll ist knapp {#audit-storage}

Anzeichen: Agents erhalten `audit_storage_low`; in der App und im Tray erscheint eine Warnung; Entscheidungen scheitern mit einem Audit-Fehler.

Dies betrifft die Desktop-App; auf dem Server überwacht der Betreiber den Speicher. atlas-duck handelt nur, wenn es das festhalten kann. Fällt der freie Platz auf dem Laufwerk mit dem Audit-Protokoll unter eine Schwelle (standardmäßig 2 GiB), weist es neue Anfragen zurück. Systemeinträge und die Bereinigung laufen weiter.

1. Schaffen Sie auf diesem Laufwerk Platz. Leeren Sie den Papierkorb, entfernen Sie alte Downloads, Backups und Exporte, die Sie nicht mehr brauchen.
2. Prüfen Sie „Aufbewahrung und Legal Hold“ in den Einstellungen. Ist ein Legal Hold aktiv, wird nichts bereinigt. Eine lange Aufbewahrungsfrist behält mehr Daten.
3. Versuchen Sie es erneut. Zurückgewiesene Anfragen wurden nicht eingereiht, der Agent muss sie also erneut einreichen.

Siehe [`audit_storage_low`](error-reference#err-audit-storage-low) und [Aufbewahrung und Legal Hold](audit#retention).
