---
id: error-reference
title: Fehlerreferenz
mode: both
order: 120
---

## Fehler der Befehlszeile und der Agents {#errors-envelope}

Jede fehlgeschlagene Anfrage eines Agenten enthält ein Objekt `error` mit einem `code`, einem Kennzeichen `retryable` und einer Meldung. Der Code sagt, was schiefgegangen ist. Das Kennzeichen sagt dem Agenten, ob es helfen kann, dieselbe Anfrage erneut zu senden. Agents sollten anhand von `status`, `error.code` und `error.retryable` zusammen entscheiden, nicht allein anhand des Exit-Codes.

::: desktop

Die Befehlszeile setzt außerdem einen Exit-Code, siehe [Das Antwortformat](agents-desktop#envelope).

:::

Viele dieser Fehler erreichen Sie nur über den Agenten. Sehen Sie einen in der App, zum Beispiel unter „Zuletzt entschieden (24 Std.)“, sagt der Eintrag, was zu tun ist.

### `usage` {#err-usage}

Die Anfrage war nicht gültig: ein Befehl, eine Option oder eine Kombination von Optionen, die atlas-duck nicht kennt. Es wurde nichts eingereiht. Exit 2, nicht wiederholbar. Prüfen Sie den Befehl mit `--help`.

### `validation` {#err-validation}

Die Anfrage war wohlgeformt, hat aber die Prüfung nicht bestanden, zum Beispiel wegen eines fehlenden oder falschen Parameters eines Vorgangs. Es wurde nichts eingereiht. Exit 2, nicht wiederholbar. Schlagen Sie den Vorgang mit `ops describe <op-id>` nach und korrigieren Sie die Parameter.

### `markdown_placeholders` {#err-markdown-placeholders}

Schreibt ein Agent eine Confluence-Seite oder einen Kommentar in Markdown, weist atlas-duck einen Text zurück, der noch Platzhalter enthält, die atlas-duck eingesetzt hat, als der Agent eine Seite als Markdown las (zum Beispiel für Makros oder Erwähnungen). Zurückgeschrieben würden sie nicht mehr bedeuten, wofür sie standen. Es wurde nichts eingereiht. Exit 2, nicht wiederholbar. Der Agent sollte die Seite erneut mit `--format storage` abrufen und seine Änderung mit `body_format=storage` einreichen. Das Storage-Format behält Makros und Erwähnungen unverändert bei. Wer die Platzhalter von Hand ersetzt oder den Teil weglässt, verliert sie.

### `op_unsupported_by_instance` {#err-op-unsupported-by-instance}

Diese Instanz unterstützt den Vorgang nicht, zum Beispiel weil ihre Version zu alt ist. Exit 2, nicht wiederholbar. Verwenden Sie einen anderen Vorgang oder eine andere Instanz, oder fragen Sie den Administrator der Instanz.

### `internal` {#err-internal}

In atlas-duck oder im Server ist ein interner Fehler aufgetreten. Nicht wiederholbar: Agents dürfen nicht selbstständig wiederholen. Sie selbst können die Aktion später erneut versuchen. Tritt er weiter auf, informieren Sie Ihren Administrator und nennen Sie ihm die Anfrage-ID und die Uhrzeit.

### `audit_failure` {#err-audit-failure}

Das Audit-Protokoll konnte nicht geschrieben werden, daher wurde nichts ausgeführt. atlas-duck handelt nie, ohne es festzuhalten. Exit 1. Bei Lesezugriffen und Skripten darf der Agent es erneut versuchen; bei Schreibzugriffen ist es nicht wiederholbar, denn der Schreibzugriff muss neu entschieden werden. Prüfen Sie, dass der Datenträger des Audit-Protokolls nicht voll ist, siehe [Der Speicher für das Audit-Protokoll ist knapp](troubleshooting#audit-storage).

### `audit_storage_low` {#err-audit-storage-low}

Der Speicher für das Audit-Protokoll ist fast voll. atlas-duck weist neue Anfragen zurück, damit das Protokoll immer geschrieben werden kann. Es wurde nichts eingereiht. Exit 1, wiederholbar. Schaffen Sie auf dem Laufwerk mit dem Audit-Protokoll Platz und versuchen Sie es dann erneut. Siehe [Der Speicher für das Audit-Protokoll ist knapp](troubleshooting#audit-storage).

### `busy` {#err-busy}

atlas-duck begrenzt, wie viele Verbindungen und offene Anfragen es annimmt, insgesamt, je Programm und je Agent-Sitzung, damit ein einzelner Agent die Warteschlange nicht überflutet. Eine dieser Grenzen ist erreicht. Es wurde nichts eingereiht. Exit 11, wiederholbar nach der Zeit, die `retry_after_s` nennt. Warten hilft nicht, wenn die Grenze für ausstehende Anfragen die Ursache ist: Entscheiden oder lehnen Sie zuerst die ausstehenden Anfragen ab, zum Beispiel mit „Alle ausstehenden dieser Sitzung ablehnen“. Versuchen Sie es dann erneut.

### `unreachable` {#err-unreachable}

Die Befehlszeile konnte die App nicht erreichen. Außer bei `connection_lost` wurde nichts eingereiht, und der Exit-Code ist 5. `details.reason` nennt den Grund:

| Grund | Was zu tun ist |
| --- | --- |
| `not_running` | Die App läuft nicht. Starten Sie sie. |
| `launch_timeout` | Die App ist nicht rechtzeitig gestartet, oder das `--timeout` ist vor dem Einreichen abgelaufen. Starten Sie die App selbst und versuchen Sie es erneut. |
| `no_gui_session` | Es gibt keine Desktop-Sitzung, in der die App starten könnte. Starten Sie sie in einer Desktop-Sitzung. |
| `launch_blocked_by_job` | Unter Windows ließ sich die App nicht aus dem Prozess des Agenten starten. Starten Sie die App selbst. |
| `app_upgraded` | Die Befehlszeile ist neuer als die laufende App. Starten Sie die App neu. |
| `app_shutting_down` | Die App wird beendet. Starten Sie sie erneut. |
| `store_newer` | Die Audit-Daten wurden von einem neueren atlas-duck geschrieben. Installieren Sie diese oder eine neuere Version. |
| `store_unavailable` | Der Audit-Speicher ließ sich nicht öffnen. Starten Sie atlas-duck neu. Nicht wiederholbar. |
| `connection_lost` | Die Verbindung brach ab, nachdem die Anfrage gesendet war. Die Anfrage existiert, mit Status `pending`, Exit 4, nicht wiederholbar. Warten Sie mit `await <id>` auf sie; sie kann `abandoned` sein. |

Außer bei `store_unavailable` und `connection_lost` ist der Fehler wiederholbar.

### `server_identity` {#err-server-identity}

Das Programm, das geantwortet hat, ist nicht die App Ihres Benutzers. atlas-duck weigert sich, mit ihm zu sprechen. Exit 5, nicht wiederholbar. Das ist eine Sicherheitsprüfung. Stellen Sie sicher, dass kein anderes Programm die Verbindung der App verwendet, und starten Sie atlas-duck neu. Bleibt es bestehen, informieren Sie Ihren Administrator.

### `protocol_mismatch` {#err-protocol-mismatch}

Die Befehlszeile und die App sprechen Protokollversionen, die nicht zusammenpassen. Exit 5. Aktualisieren Sie beide auf dieselbe Version und starten Sie die App neu. Starten Sie auch den MCP-Server des Agenten neu.

### `upstream_http` {#err-upstream-http}

Der Jira- oder Confluence-Server hat mit einem Fehler geantwortet. Dieser Code erscheint, wenn ein Schreibzugriff nach Ihrer Freigabe fehlgeschlagen ist, wenn Sie den Fehler eines Lesezugriffs übergeben haben oder wenn Sie eine Anfrage abgelehnt und den HTTP-Status als Tipp angehängt haben. Exit 6 oder 3, nicht wiederholbar. `details` enthält den HTTP-Status und die Fehlermeldungen der Instanz. Lesen Sie sie: Meist geht es um eine Berechtigung, um einen Wert, den die Instanz zurückweist, oder um ein gelöschtes Objekt.

### `upstream_network` {#err-upstream-network}

Die Verbindung zur Instanz ist fehlgeschlagen. Exit 6. Geschah das, bevor die Anfrage gesendet wurde, ist es wiederholbar. Stammt es aus einem Lesezugriff, den Sie übergeben haben, ist es eine feste Meldung ohne Daten und nicht wiederholbar. Prüfen Sie, ob die Instanz erreichbar ist, siehe [Eine Instanz ist nicht erreichbar](troubleshooting#cannot-connect).

### `upstream_unavailable` {#err-upstream-unavailable}

Die Instanz ist gerade nicht verfügbar. Exit 6. Lesezugriffe lassen sich später wiederholen. Lautet der Grund `identity_header_missing` oder `identity_header_mismatch`, verändert ein Proxy vor Jira den Benutzer-Header, und eine Wiederholung hilft nicht; fragen Sie den Administrator der Instanz. Siehe [Instanzen und Tokens](instances-and-tokens).

### `upstream_unknown_outcome` {#err-upstream-unknown-outcome}

Ein Schreibzugriff wurde gesendet, aber atlas-duck weiß nicht, ob die Instanz ihn ausgeführt hat, zum Beispiel nach einem Zeitlimit, einem Serverfehler oder einem Absturz. Status `outcome_unknown`, Exit 6, nicht wiederholbar. **Prüfen Sie das Ziel in Jira oder Confluence, bevor Sie etwas anderes tun.** Nur wenn die Änderung fehlt, sollte sie erneut angefordert werden. Der Eintrag steht unter „Braucht Aufmerksamkeit“ mit „Ziel prüfen“, siehe [Braucht Aufmerksamkeit](approvals#needs-attention).

### `result_too_large` {#err-result-too-large}

Das Ergebnis ist zu groß, um es zurückzugeben. Exit 6, nicht wiederholbar. Der Agent sollte weniger anfordern: eine kleinere Seite, weniger Felder oder eine engere Suche.

### `needs_token` {#err-needs-token}

Für diese Instanz wird ein Token benötigt. Das Token fehlt, oder die Instanz hat es zurückgewiesen. Exit 9. Fügen Sie das Token hinzu oder ersetzen Sie es, siehe [Instanzen und Tokens](instances-and-tokens) und [Ein Token wird zurückgewiesen](troubleshooting#token-rejected). Agents sollten nicht in einer Schleife wiederholen.

### `locked` {#err-locked}

Die App ist gesperrt: Sie kann ihr Audit-Protokoll oder ihre Schlüssel nicht öffnen. Exit 9. `details.reason` nennt den Grund, zum Beispiel dass der Schlüsselbund noch nicht verfügbar ist, dass er verloren ging oder dass der Schlüsselbund auf einem Netzlaufwerk liegt. Folgen Sie [Die App ist gesperrt](troubleshooting#locked).

### `not_configured` {#err-not-configured}

Diese Instanz oder die App ist noch nicht eingerichtet. Exit 9. `details.reason` nennt die Lücke: Der Einrichtungsassistent ist nicht abgeschlossen, für das Produkt gibt es keine Instanz, eine Instanz verwendet `http://` statt `https://`, eine Instanz ist nicht bestätigt, das Datenverzeichnis fehlt oder liegt nicht auf einem lokalen Laufwerk, oder die Einstellungsdatei lässt sich nicht lesen. Bei den ersten Gründen schließen Sie die Einrichtung ab. Lässt sich die Einstellungsdatei nicht lesen, wurde sie möglicherweise von einem neueren atlas-duck geschrieben: Aktualisieren Sie atlas-duck. Sind die Pfade oder das Datenverzeichnis unbrauchbar, korrigieren Sie das Verzeichnis oder seine Berechtigungen.

::: desktop

Siehe [Erste Schritte](getting-started-desktop).

:::

### `script_syntax` {#err-script-syntax}

Das Skript hat einen Syntaxfehler. atlas-duck übersetzt jedes Skript beim Einreichen und weist ein fehlerhaftes zurück. Exit 8, nicht wiederholbar. Korrigieren Sie das Skript. Siehe [Skripte](scripts#what-are-scripts).

### `script_limit` {#err-script-limit}

Das Skript hat ein Limit erreicht und wurde gestoppt: Zeit, Speicher, Zahl der Aufrufe, abgerufene Daten oder Größe des Ergebnisses. Exit 8, nicht wiederholbar. Lassen Sie das Skript weniger tun oder erhöhen Sie das Limit in den Einstellungen, siehe [Limits und Isolierung](scripts#limits).

### `sandbox_unavailable` {#err-sandbox-unavailable}

Die Skript-Sandbox ist nicht verfügbar, daher können keine Skripte laufen. Exit 8, nicht wiederholbar. Lautet der Grund `app_upgraded`, starten Sie die App neu und versuchen Sie es erneut. Sonst erlaubt das Betriebssystem die Isolierung nicht, siehe [Limits und Isolierung](scripts#limits).

### `result_evicted` {#err-result-evicted}

Das Ergebnis ist bekannt, aber nicht mehr gespeichert. Exit 10. Bei Lesezugriffen und Skripten kann der Agent die Anfrage erneut einreichen; einen Schreibzugriff wiederholen Sie nicht einfach: Sein Ergebnis ist bereits entschieden und kann ein Fehlschlag gewesen sein. Prüfen Sie zuerst das Ziel in Jira oder Confluence.

### `denied` {#err-denied}

Sie haben die Anfrage abgelehnt. Die Meldung enthält Ihre Begründung. Exit 3, nicht wiederholbar. Der Agent sollte nur erneut einreichen, wenn die Begründung um eine Änderung bittet. Siehe [Freigeben, übergeben oder ablehnen](approvals#approve-or-deny).

### `resolution_failed` {#err-resolution-failed}

Ein Name in der Anfrage ließ sich nicht auflösen, zum Beispiel ein Benutzer, ein Feld oder ein Projekt, das es unter diesem Namen nicht gibt. Exit 3, wenn Sie es als Tipp an eine Ablehnung angehängt haben. `details` nennt den Parameter und kann Kandidaten auflisten. Der Agent sollte den genannten Parameter korrigieren.

### `expired` {#err-expired}

Niemand hat die Anfrage rechtzeitig entschieden. Exit 7, nicht wiederholbar. Reichen Sie sie nur erneut ein, wenn Sie das wünschen.

### `cancelled` {#err-cancelled}

Die Anfrage wurde storniert: durch den Agenten (`cancel`, nicht wiederholbar) oder weil die App beendet oder das System heruntergefahren wurde (wiederholbar). Exit 7. Es wurde nichts ausgeführt, und ein storniertes Ergebnis erreicht Ihre Warteschlange nie.

Im Fenster „Freigaben“ bedeutet derselbe Code „Die Entscheidung wurde abgebrochen“: Sie haben die Bestätigung einer Sammelentscheidung abgebrochen. Es wurde nichts entschieden, und die Anfragen sind wie zuvor.

### `abandoned` {#err-abandoned}

Die Anfrage war noch ausstehend, als die App abstürzte oder beendet wurde. Exit 7, wiederholbar. Reichen Sie sie erneut ein. Ein Schreibzugriff, der schon freigegeben war, wird stattdessen `outcome_unknown`, siehe [upstream_unknown_outcome](error-reference#err-upstream-unknown-outcome).

### `unknown_request` {#err-unknown-request}

Es gibt keine Anfrage mit dieser ID. Exit 2. Prüfen Sie die ID oder finden Sie sie mit `requests list`.

### `protocol_error` {#err-protocol-error}

Die App und das Kommandozeilenwerkzeug haben sich nicht verstanden. Exit 1, nicht wiederholbar. Meist heißt das, dass sie verschiedene Versionen haben. Aktualisieren Sie beide und starten Sie die App neu.

## Fehler beim Entscheiden {#errors-decision}

Diese Fehler erscheinen im Fenster „Freigaben“, wenn sich eine Entscheidung nicht anwenden lässt. In jedem Fall wurde nichts entschieden, und die Anfrage ist wie zuvor. Den Fehler `cancelled` beschreibt [der Abschnitt oben](error-reference#err-cancelled).

### `stale` {#err-stale}

Die Anfrage hat sich inzwischen geändert, zum Beispiel hat sie eine neue Revision erhalten. Lesen Sie die Warteschlange neu ein, öffnen Sie die Anfrage erneut und entscheiden Sie über das, was Sie sehen.

### `invalid` {#err-invalid}

Die Entscheidung ist für diese Anfrage nicht zulässig, zum Beispiel eine Freigabe für etwas, das sich nicht freigeben lässt, oder eine Übergabe, deren Vorschau Sie nicht geöffnet haben. Öffnen Sie zuerst die Vorschau oder entscheiden Sie einzeln.

### `edit_rejected` {#err-edit-rejected}

Die Bearbeitung wurde zurückgewiesen, zum Beispiel weil sie das Ziel ändert, nicht gültig oder zu groß ist. Die Meldung nennt den Grund. Korrigieren Sie das Feld oder lehnen Sie die Anfrage ab. Siehe [Bearbeiten und schwärzen](approvals#edit-and-redact).

### `audit` {#err-audit}

Die Entscheidung konnte nicht im Audit-Protokoll festgehalten werden, daher wurde nichts ausgeführt. Prüfen Sie den freien Platz des Audit-Protokolls und versuchen Sie es erneut. Siehe [Der Speicher für das Audit-Protokoll ist knapp](troubleshooting#audit-storage).

### `batch_rejected` {#err-batch-rejected}

Die Sammelentscheidung wurde zurückgewiesen, und es wurde nichts entschieden. Mindestens eine Anfrage kam nicht infrage. Die Gründe stehen je Anfrage dabei, siehe unten und [Sammelentscheidungen](approvals#batch-decisions).

### `not_decidable` {#err-not-decidable}

Die Anfrage wartet nicht auf eine Entscheidung. Jemand anderes hat sie entschieden, sie ist abgelaufen oder wurde storniert. Lesen Sie die Warteschlange neu ein.

## Fehler bei Sammelentscheidungen {#errors-batch}

Eine Sammelentscheidung nennt diese Gründe je Anfrage. Nehmen Sie die Anfrage aus der Sammelentscheidung heraus oder entscheiden Sie sie einzeln.

### `not_pending` {#err-not-pending}

Die Anfrage steht nicht mehr aus. Sie wurde inzwischen entschieden, ist abgelaufen oder wurde storniert.

### `target_param_edit` {#err-target-param-edit}

Eine Bearbeitung wollte das Ziel der Anfrage ändern, was nicht erlaubt ist. Lehnen Sie die Anfrage ab, damit der Agent mit dem richtigen Ziel neu anfragt.

### `not_opened` {#err-not-opened}

Die Vorschau der Anfrage wurde nicht geöffnet. Öffnen Sie die Vorschau jeder ausgewählten Anfrage, bevor Sie gesammelt entscheiden.

### `not_approvable` {#err-not-approvable}

Die Anfrage lässt sich so nicht freigeben, zum Beispiel weil Pflichtfelder fehlen, eine Schwärzung blockiert ist oder sich die Anfrage nicht neu aufbauen lässt. Einzeln entscheiden ändert daran nichts. Ergänzen Sie die fehlenden Felder oder beheben Sie die blockierte Schwärzung, oder lehnen Sie die Anfrage ab.

### `batch_item_flagged` {#err-batch-item-flagged}

Die Anfrage ist als mögliches Duplikat oder als ähnliche Anfrage markiert. Sehen Sie sie sich an und geben Sie sie einzeln frei.

::: server

## Fehler der Serverbefehle {#errors-cmd}

Die Serverseiten senden Befehle an den Server. Diese Fehler kommen zurück, wenn ein Befehl fehlschlägt. Den Fehler `internal` beschreibt [der Abschnitt oben](error-reference#err-internal).

### `invalid_argument` {#err-invalid-argument}

Die Anfrage enthält einen ungültigen Wert. Prüfen Sie Ihre Eingabe und versuchen Sie es erneut.

### `not_found` {#err-not-found}

Die Anfrage oder das, was sie nennt, gibt es nicht mehr. Laden Sie die Seite neu.

### `release_blocked` {#err-release-blocked}

Diese Anfrage kann nicht übergeben werden. Die Schwärzungen, die Sie vorgenommen haben, oder die Daten selbst würden etwas durchlassen, das zurückgehalten werden sollte, oder das Ergebnis ließ sich nicht exakt aufbauen. Die Seite nennt den Grund. Lehnen Sie die Anfrage ab oder nehmen Sie die markierten Einträge heraus. Siehe „Wenn eine Übergabe blockiert ist“ unter [Bearbeiten und schwärzen](approvals#edit-and-redact).

### `unknown_command` {#err-unknown-command}

Der Server kennt diesen Befehl nicht. Die Seite und der Server haben verschiedene Versionen. Laden Sie die Seite neu; bleibt es bestehen, informieren Sie Ihren Administrator.

### `not_ready` {#err-not-ready}

Ihr Speicher ist noch nicht bereit, zum Beispiel direkt nach einem Neustart. Versuchen Sie es gleich noch einmal.

### `audit_unreadable` {#err-audit-unreadable}

Ein Audit-Eintrag konnte nicht gelesen werden, was bedeuten kann, dass er beschädigt ist. Informieren Sie Ihren Administrator schon beim ersten Mal und bitten Sie ihn, das Audit-Protokoll zu prüfen, siehe [Die Kette prüfen](audit#verify).

### `audit_failed` {#err-audit-failed}

Das Audit-Protokoll konnte nicht gelesen werden. Versuchen Sie es später erneut. Bleibt es bestehen, informieren Sie Ihren Administrator.

:::

::: server

## Fehler der Server-API {#errors-server}

Der Server beantwortet Fehler mit einem HTTP-Status und einem Code. Die Webseiten übersetzen den Code in eine Meldung. Der Code hilft Ihnen, wenn Sie mit Ihrem Administrator sprechen.

### `auth/invalid_credentials` {#err-auth-invalid-credentials}

HTTP 401. Benutzername oder Passwort ist falsch. Melden Sie sich erneut mit Ihrem Verzeichniskonto an.

### `auth/empty_password` {#err-auth-empty-password}

HTTP 400. Sie haben kein Passwort eingegeben.

### `auth/directory_unavailable` {#err-auth-directory-unavailable}

HTTP 503. Der Server erreicht das Verzeichnis nicht, das Ihr Passwort prüft. Wer schon angemeldet ist, kann weiterarbeiten. Versuchen Sie es später noch einmal oder informieren Sie Ihren Administrator.

### `auth/not_permitted` {#err-auth-not-permitted}

HTTP 403. Dieses Konto darf atlas-duck nicht verwenden: Es gehört zu keiner der Gruppen, die der Server zulässt, oder es wurde deaktiviert. Fragen Sie Ihren Administrator, siehe [Benutzer und Rollen](admin#users-and-roles).

### `auth/no_session` {#err-auth-no-session}

HTTP 401. Sie sind nicht angemeldet. Melden Sie sich zuerst an.

### `auth/session_expired` {#err-auth-session-expired}

HTTP 401. Die Sitzung ist abgelaufen. Melden Sie sich erneut an.

### `auth/csrf_mismatch` {#err-auth-csrf-mismatch}

HTTP 403. Das Anfrage-Token passt nicht zu Ihrer Sitzung, zum Beispiel weil die Seite sehr lange oder in zwei Sitzungen offen war. Laden Sie die Seite neu.

### `auth/origin_mismatch` {#err-auth-origin-mismatch}

HTTP 403. Die Anfrage kommt von einer anderen Adresse als der des Servers selbst. Verwenden Sie die Adresse, die Ihr Administrator Ihnen genannt hat, und rufen Sie den Server nicht von einer anderen Website aus auf.

### `auth/role_required` {#err-auth-role-required}

HTTP 403. Die Seite oder Aktion braucht eine Rolle, die Ihr Konto nicht hat, etwa Administrator oder Auditor. Siehe [Benutzer und Rollen](admin#users-and-roles).

### `auth/bearer_not_accepted` {#err-auth-bearer-not-accepted}

HTTP 403. API-Schlüssel und OAuth-Tokens können hier nicht verwendet werden. Nur der MCP-Endpunkt nimmt sie an; Entscheidungen kann nur eine angemeldete Person treffen. Siehe [Der MCP-Endpunkt](agents-server#mcp-endpoint).

### `auth/api_key_invalid` {#err-auth-api-key-invalid}

HTTP 401. Der API-Schlüssel oder das Token ist nicht gültig: falsch eingegeben, widerrufen oder abgelaufen, oder sein Benutzer wurde deaktiviert. Erstellen Sie einen neuen Schlüssel, siehe [API-Schlüssel](agents-server#api-keys).

### `auth/scope_missing` {#err-auth-scope-missing}

HTTP 403. Dem Schlüssel fehlt die Berechtigung, die dafür nötig ist. Erstellen Sie einen Schlüssel mit dieser Berechtigung, siehe [Berechtigungen](agents-server#scopes).

### `api/bad_request` {#err-api-bad-request}

HTTP 400. Die Anfrage ist fehlerhaft aufgebaut. Wenn Sie die Webseiten verwenden, laden Sie sie neu. Sendet ein eigenes Programm sie, prüfen Sie den Anfragetext.

### `api/not_found` {#err-api-not-found}

HTTP 404. Nicht gefunden. Die Adresse oder das Objekt gibt es nicht.

### `api/unknown_command` {#err-api-unknown-command}

HTTP 404. Der Server kennt diesen Befehl nicht. Laden Sie die Seite neu; Seite und Server haben möglicherweise verschiedene Versionen.

### `api/body_too_large` {#err-api-body-too-large}

HTTP 413. Der Anfragetext ist zu groß. Senden Sie weniger Daten.

### `api/too_many_streams` {#err-api-too-many-streams}

HTTP 429. Sie haben zu viele Seiten offen, die auf Live-Aktualisierungen warten. Schließen Sie einige Tabs.

### `instance/invalid` {#err-instance-invalid}

HTTP 400. Die Instanz ist nicht gültig. Prüfen Sie den Alias (Buchstaben, Ziffern, `-` und `_`), das Produkt, eine Basis-URL mit `https://` und den Proxy, und dass ein Produkt nur eine Standardinstanz hat. Siehe [Instanzen verwalten](admin#instances-admin).

### `instance/exists` {#err-instance-exists}

HTTP 409. Es gibt bereits eine Instanz mit diesem Alias. Wählen Sie einen anderen Alias.

### `instance/unknown` {#err-instance-unknown}

HTTP 404. Keine Instanz hat diesen Alias, vielleicht weil ein Administrator sie entfernt hat. Laden Sie die Seite neu.

### `pat/check_failed` {#err-pat-check-failed}

HTTP 422. Die Instanz hat das Token zurückgewiesen. Prüfen Sie, dass Sie es vollständig kopiert haben und dass es nicht abgelaufen oder widerrufen ist. Siehe [Ein Token wird zurückgewiesen](troubleshooting#token-rejected).

### `pat/instance_unreachable` {#err-pat-instance-unreachable}

HTTP 502. Der Server erreicht die Instanz nicht, um das Token zu prüfen. Versuchen Sie es später erneut oder fragen Sie Ihren Administrator. Siehe [Eine Instanz ist nicht erreichbar](troubleshooting#cannot-connect).

### `api_key/limit_reached` {#err-api-key-limit-reached}

HTTP 409. Sie haben die Höchstzahl von 25 aktiven Schlüsseln erreicht. Widerrufen Sie zuerst einen, siehe [API-Schlüssel](agents-server#api-keys).

### `api_key/expiry_out_of_range` {#err-api-key-expiry-out-of-range}

HTTP 400. Das Ablaufdatum muss eine ganze Zahl von Tagen zwischen 1 und 90 sein.

### `api_key/name_invalid` {#err-api-key-name-invalid}

HTTP 400. Der Name muss 1 bis 64 Zeichen lang sein und darf keine Steuerzeichen enthalten.

### `api_key/scope_invalid` {#err-api-key-scope-invalid}

HTTP 400. Wählen Sie mindestens eine Berechtigung, und nur bekannte.

### `store/unavailable` {#err-store-unavailable}

HTTP 503. Der Speicher ist nicht verfügbar. Versuchen Sie es gleich noch einmal. Bleibt es bestehen, informieren Sie Ihren Administrator.

### `oauth/disabled` {#err-oauth-disabled}

HTTP 404. OAuth ist auf diesem Server nicht aktiviert. Verwenden Sie stattdessen einen API-Schlüssel, siehe [API-Schlüssel](agents-server#api-keys).

### `oauth/request_unknown` {#err-oauth-request-unknown}

HTTP 404. Diese Autorisierungsanfrage ist unbekannt. Sie wurde möglicherweise schon beantwortet oder gehört zu einer anderen Sitzung. Beginnen Sie in der App von vorn, siehe [Eine App autorisieren](agents-server#oauth-consent).

### `oauth/request_expired` {#err-oauth-request-expired}

HTTP 410. Diese Autorisierungsanfrage ist abgelaufen. Beginnen Sie in der App von vorn.

### `oauth/grant_unknown` {#err-oauth-grant-unknown}

HTTP 404. Diese verbundene App gibt es nicht. Möglicherweise ist sie schon widerrufen. Laden Sie „Verbundene Apps“ neu.

### `audit/user_unknown` {#err-audit-user-unknown}

HTTP 404. Diesen Benutzer gibt es nicht. Gehen Sie zurück zur Liste der Benutzer.

### `audit/read_not_recorded` {#err-audit-read-not-recorded}

HTTP 503. Das Lesen konnte nicht protokolliert werden, daher wurde nichts gelesen. Auch das Auditieren wird protokolliert, und der Server verweigert Daten, die er nicht festhalten kann. Versuchen Sie es später erneut. Siehe [Die Rolle Auditor](auditor#auditor-role).

### `audit/export_busy` {#err-audit-export-busy}

HTTP 409. Ein Export dieses Protokolls läuft bereits, oder der Server führt die Höchstzahl an Exporten aus. Versuchen Sie es nach seinem Ende noch einmal.

### `audit/export_unknown` {#err-audit-export-unknown}

HTTP 404. Es gibt diesen Export nicht, oder er gehört jemand anderem.

### `audit/export_expired` {#err-audit-export-expired}

HTTP 410. Der Export ist nicht mehr verfügbar: Er ist abgelaufen oder wurde schon heruntergeladen. Starten Sie einen neuen, siehe [Das Protokoll exportieren](audit#export).

### `audit/export_failed` {#err-audit-export-failed}

HTTP 500. Der Export ist fehlgeschlagen. Starten Sie einen neuen. Schlägt er weiter fehl, informieren Sie Ihren Administrator.

### `server/maintenance` {#err-server-maintenance}

HTTP 503. Der Server befindet sich in Wartung, zum Beispiel für eine Wiederherstellung. Versuchen Sie es später erneut. Siehe [Wartung](admin#maintenance).

### `auth/rate_limited` {#err-auth-rate-limited}

HTTP 429. Zu viele fehlgeschlagene Anmeldungen. Warten Sie die Zeit ab, die der Header `Retry-After` nennt, und versuchen Sie es dann erneut.

:::
