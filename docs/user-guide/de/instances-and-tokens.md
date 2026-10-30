---
id: instances-and-tokens
title: Instanzen und Tokens
mode: both
order: 30
---

## Instanzen {#instances}

Eine Instanz ist ein Jira- oder Confluence-Data-Center-Server, mit dem atlas-duck spricht. Sie ist unter einem Alias bekannt, zum Beispiel dem Kurznamen des Servers.

::: desktop

Im Desktopmodus legen Sie Ihre eigenen Instanzen an. Die Einstellungen listen sie unter "Instanzen" auf:

| Spalte | Inhalt |
| --- | --- |
| Alias | Der Name, den Sie der Instanz gegeben haben. |
| Produkt | Jira oder Confluence. |
| Origin | Die bestätigte Adresse des Servers oder "(nicht bestätigt)". |
| Status | Siehe unten. |
| Ausführung als | Der Atlassian-Benutzer, zu dem Ihr Token gehört. |
| Token-Ablauf | Das Ablaufdatum, falls Sie eines eingegeben haben. |
| Proxy | Der Proxy dieser Instanz oder "Systemeinstellung oder keiner". |

Der Status zeigt, ob die Instanz verwendbar ist:

| Status | Bedeutung |
| --- | --- |
| in Ordnung | Bereit. |
| braucht Token | Es ist noch kein Token gespeichert. Verwenden Sie "Token hinzufügen". |
| unbestätigt | Sie haben die Origin noch nicht bestätigt. Verwenden Sie "Instanz bestätigen". |
| unsicheres Schema (http) | Die URL beginnt mit http. atlas-duck verlangt https. Verwendet Ihr Server eine interne CA, fügen Sie sie als eigene CA der Instanz hinzu. |
| Identitäts-Header fehlt | "X-AUSERNAME wurde nicht empfangen, möglicherweise von einem Reverse-Proxy vor Jira entfernt; wenden Sie sich an die Jira-Administration". |
| Identitäts-Header stimmt nicht überein | Der Header X-AUSERNAME passt nicht zum Benutzer des Tokens. |

:::

::: server

Im Servermodus legt ein Administrator die Instanzen für alle fest. Sie sehen sie auf der Seite "Zugangsdaten" und fügen nur Ihr eigenes Token für jede hinzu. Steht auf der Seite "Es ist noch keine Instanz eingerichtet. Instanzen fügt ein Administrator hinzu.", fragen Sie Ihren Administrator. Für Administratoren: siehe [Administration](admin#instances-admin).

:::

## Instanz hinzufügen {#add-instance}

::: desktop

Öffnen Sie die Einstellungen, "Instanz hinzufügen" (das Einrichtungsfenster hat dasselbe Formular), und füllen Sie aus:

- **Alias** und **Produkt** (Jira oder Confluence).
- **Basis-URL (https, mit Kontextpfad)**. atlas-duck verlangt https.
- **Proxy** als Host:Port, `direct` oder leer für die Systemeinstellung. Verwendet Ihr System ein Proxy-Auto-Config-Skript, wertet atlas-duck es nicht aus: Legen Sie den Proxy der Instanz hier fest.
- **Eigenes CA-Zertifikat verwenden**, wenn Ihr Server eine interne Zertifizierungsstelle nutzt. atlas-duck fragt nach der Datei.
- **Standardinstanz für ihr Produkt**. Ein Produkt kann nur eine Standardinstanz haben.

Wählen Sie "Instanz hinzufügen". atlas-duck zeigt dann Alias und Origin in einem eigenen Dialog; bestätigen Sie sie. Danach erscheint "Die Instanz wurde hinzugefügt. Fügen Sie als Nächstes ihr Token hinzu." Später bietet die Zeile auch "URL ändern" und "Proxy anwenden".

:::

::: server

Benutzer fügen im Servermodus keine Instanzen hinzu. Bitten Sie Ihren Administrator, eine hinzuzufügen. Prüfen Sie, bevor Sie ein Token speichern, dass die URL auf der Seite "Zugangsdaten" der Server ist, den Sie meinen.

:::

## Tokens {#tokens}

atlas-duck handelt immer als Sie, mit Ihrem eigenen persönlichen Zugriffstoken (PAT), nie mit einem gemeinsamen Dienstkonto. Erstellen Sie das Token in Jira oder Confluence (Profil → Persönliche Zugriffstoken) und geben Sie ihm nur die Berechtigungen, die Ihre Arbeit braucht. Was das Token in Jira oder Confluence nicht darf, kann auch ein Agent nicht.

::: desktop

Geben Sie das Token im [Anmeldedatenfenster](#credential-window) ein. Sie können auch ein Ablaufdatum angeben. atlas-duck warnt Sie dann rechtzeitig ("Das Token läuft in N Tagen ab", "Das Token läuft heute ab", "Das Token ist am ... abgelaufen"). Das ist nur eine Warnung: Ob ein Token funktioniert, entscheidet der Server.

In jeder Instanzzeile der Einstellungen:

- "Token hinzufügen" oder "Token ersetzen" öffnet das Anmeldedatenfenster.
- "Gespeichertes Token erneut prüfen" fragt den Server noch einmal. Die Antwort lautet "Verbunden als ..." oder "Die erneute Prüfung ist fehlgeschlagen:" mit dem Grund.

:::

::: server

Geben Sie das Token auf der [Seite Zugangsdaten](#credentials-page) ein.

:::

Wenn Sie ein Token speichern, testet atlas-duck es zuerst gegen die Instanz. Das sind die Gründe für eine Ablehnung:

| Grund | Was Sie tun können |
| --- | --- |
| Der Server hat das Token zurückgewiesen (401). | Prüfen Sie, ob es ein gültiges persönliches Zugriffstoken ist, das nicht abgelaufen ist. |
| Das Token gehört einem anderen Benutzer. | Für die Instanz ist schon ein Token eines anderen Atlassian-Benutzers gespeichert. Entfernen Sie zuerst das gespeicherte Token. |
| Das TLS-Zertifikat des Servers konnte nicht geprüft werden. | Verwendet Ihr Server eine interne CA, braucht die Instanz sie als eigene CA. |
| Ein Proxy hat die Verbindung blockiert oder verändert. | Prüfen Sie die Proxy-Einstellungen. |
| Der Server war nicht erreichbar. | Versuchen Sie es später erneut. |
| Die Serverversion liegt unter dem Minimum, das atlas-duck unterstützt. | Die Instanz muss aktualisiert werden. |

## Wo Tokens gespeichert werden {#token-storage}

::: desktop

Ihre Tokens liegen im Schlüsselbund des Betriebssystems dieses Computers. atlas-duck zeigt ein gespeichertes Token nie wieder an. Backups enthalten nie Tokens: Nach einer Wiederherstellung braucht jede Instanz ihr Token erneut. "Auf die Entfernung vorbereiten" in den Einstellungen löscht die gespeicherten Tokens und bittet Sie dann, jedes Token auf seinem Server zu widerrufen.

:::

::: server

Ihre Tokens werden auf dem Server gespeichert, im Ruhezustand verschlüsselt mit dem Hauptschlüssel des Servers. Betreiber, die Zugriff auf diesen Schlüssel haben, können jedes gespeicherte Token entschlüsseln; behandeln Sie das Schlüsselmaterial des Servers deshalb wie die Tokens selbst. atlas-duck zeigt ein gespeichertes Token nie wieder an. Ihre Tokens werden sofort gelöscht, wenn Ihr Konto deaktiviert wird, und wenn ein Administrator eine Instanz entfernt, werden die Tokens aller Benutzer für sie gelöscht.

:::

Tokens geben Zugriff auf Jira und Confluence in Ihrem Namen. Erneuern Sie sie regelmäßig und widerrufen Sie ein Token auf seinem Server, wenn Sie es nicht mehr brauchen.

::: desktop

## Das Anmeldedatenfenster {#credential-window}

Tokens und Passphrasen geben Sie in einem eigenen Fenster ein, dem Anmeldedatenfenster, und sonst nirgends. Für ein Token trägt es den Titel "Token hinzufügen" oder "Token ersetzen". Bevor Sie etwas eingeben, zeigt es Instanz, Produkt und Adresse, damit Sie prüfen können, dass Sie mit dem richtigen Server sprechen. Sind einzelne Zeichen der Adresse ungewöhnlich, werden sie als Escape-Folgen mit einer Warnung angezeigt: Prüfen Sie die Adresse, bevor Sie fortfahren.

1. Fügen Sie das Token in "Persönliches Zugriffstoken" ein. Auf Wunsch füllen Sie "Token läuft ab am (optional)" aus.
2. Wählen Sie "Testen und speichern".
3. Bei Erfolg meldet das Fenster "Verbunden als *Benutzer*, *Produkt* *Version*. Sie können dieses Fenster schließen."

Dasselbe Fenster fragt auch nach der Wiederherstellungs-Passphrase, um atlas-duck zu entsperren und ein Backup wiederherzustellen.

:::

::: server

## Die Zugangsdaten-Seite {#credentials-page}

"Zugangsdaten" in der Kopfzeile listet jede Instanz mit Produkt, URL und Token-Status:

| Status | Bedeutung |
| --- | --- |
| Kein Token | Sie haben keines gespeichert. |
| Token gespeichert | Das Token funktioniert. Die Zeile zeigt den Atlassian-Benutzer, zum Beispiel "als jdoe". |
| Token gespeichert, nicht verwendbar | Das gespeicherte Token funktioniert nicht mehr. Ersetzen Sie es. |

Verwenden Sie "Token hinzufügen" oder "Token ersetzen", geben Sie das Token unter "Persönliches Zugriffstoken für *Alias*" ein und wählen Sie "Prüfen und speichern". "Entfernen" löscht Ihr Token für diese Instanz nach einer Rückfrage. atlas-duck zeigt ein gespeichertes Token nie an.

Fehlermeldungen, die Sie sehen können: "Die Instanz hat dieses Token zurückgewiesen. Prüfen Sie es und versuchen Sie es erneut."; "Dieses Token gehört einem anderen Atlassian-Benutzer. Entfernen Sie zuerst das gespeicherte Token."; "Diese Instanz lässt sich gerade nicht verwenden. Wenden Sie sich an einen Administrator."; "Die Instanz ist nicht erreichbar. Versuchen Sie es später erneut."; "Diese Instanz gibt es nicht mehr."; "Das Token ist leer oder zu lang."

:::
