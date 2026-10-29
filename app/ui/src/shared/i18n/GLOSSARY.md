# German glossary (M15)

Every German text in `de/*.ts`, in the Rust text table of `app/src-tauri` and in the M16 user guide
uses these terms. `de/terms.ts` (`GLOSSARY_DE`) holds the CONTEXT.md terms in code; this file is the
longer list for the texts of the windows.

## Form and style

- Address the reader with **Sie**, never "du". Imperatives: "Geben Sie ... ein", "Öffnen Sie ...".
- Sentence case. Buttons name the action ("Freigeben", "Ablehnen"), not the question.
- One term per concept, everywhere. A new text uses the term below; if a concept is missing, add it
  here in the same commit.
- Dates and times: UTC with the suffix ` UTC`, `14.10.2026, 09:30 UTC` (`formatDateTime`,
  `formatTimestamp`). Numbers and byte counts through `formatNumber` / `formatBytes`
  (`12.345`, German decimal comma).
- Plurals are functions of the count, never `n === 1 ? '' : 's'` copied from English.

## When English stays

Keep the English word when it is a product or protocol name or the German speaker says it that way:
Token, Agent, Audit, Admin(istrator) role names as in CONTEXT.md, `API-Schlüssel` (API key is
hyphenated), Jira, Confluence, Rust (in the texts that name Rust's own native dialog), op ids, aliases,
URLs, wire field names (`params_sha256`, `cwd_basename`), `UTC`, `[REDACTED]`. Agent-supplied text is
never translated. A German leaf equal to its English one needs an allowlist entry with a reason in
`ci/check-i18n.mjs`.

## Terms

| English | German | Notes |
|---|---|---|
| Approval | Freigabe | the user's yes or no; window title "Freigaben" |
| approve | freigeben | the positive action on a write |
| release | übergeben | the positive action on a read: the result goes to the agent |
| deny | ablehnen | the user's no; "Ablehnung", "abgelehnt" |
| refused / rejected by the system (an edit, a batch, a token) | zurückgewiesen | not "abgelehnt": that is the user's deny |
| cancelled | storniert | a request or decision cancelled |
| abandoned | abgebrochen | status `abandoned` |
| discard (edits) | verwerfen | "Änderungen verwerfen" |
| batch decision | Sammelentscheidung | never "Sammelfreigabe" |
| request | Anfrage | |
| queue | Warteschlange | |
| session | Sitzung | |
| instance | Instanz | a Jira or Confluence server |
| operation (op) | Vorgang | |
| target | Ziel | |
| preview | Vorschau | |
| revision | Revision | |
| candidate | Kandidat | what would be released or sent |
| redact | schwärzen | the action; "Schwärzung" |
| mask | maskieren | a text replaced by `[REDACTED]` |
| drop | entfernen | an entry or field removed from a candidate |
| occurrence | Vorkommen | |
| agent | Agent | |
| user | Benutzer | |
| token | Token | PAT: "persönliches Zugriffstoken" on first use, then "Token" |
| API key | API-Schlüssel | |
| audit log / chain | Audit-Protokoll / Audit-Kette | window title "Audit-Protokoll" |
| auditor | Auditor | |
| admin | Administrator | |
| unverified | ungeprüft | the badge before agent-supplied text |
| unusual characters | ungewöhnliche Zeichen | |
| caution | Vorsicht | banner prefix "Vorsicht:" |
| info (banner prefix) | Hinweis | only for the banner prefix |
| hint attached to a deny | Tipp | not "Hinweis" |
| needs attention | Braucht Aufmerksamkeit | |
| acknowledge | zur Kenntnis nehmen | |
| settings | Einstellungen | |
| running scripts | Laufende Skripte | |
| onboarding | Einführung | |
| setup | Einrichtung | |
| cancel (button) | Abbrechen | the action of leaving a dialog |
| close / save / retry | Schließen / Speichern / Erneut versuchen | |
| integrity incident | Integritätsvorfall | "Integritätsvorfall zur Kenntnis nehmen" |
| verify (the log) | prüfen | "Jetzt prüfen"; result "verifiziert" |
| record (audit) | Datensatz | plural "Datensätze" |
| payload | Nutzdaten | "entschlüsselte Nutzdaten" |
| export / backup | Export / Backup | "Vollbackup", "Compliance-Export"; verb "sichern" only on the button "Jetzt sichern…" |
| restore | Wiederherstellung / wiederherstellen | |
| recovery passphrase | Wiederherstellungs-Passphrase | |
| anchor | Anker | "Anker-Verzeichnis", "Kopf-Anker", "neu verankern" |
| keychain | Schlüsselbund | |
| retention | Aufbewahrung | "Aufbewahrungsfrist" |
| legal hold | Legal Hold | kept in English (the term of art) |
| prune | bereinigen | "Bereinigung" |
| confinement (scripts) | Isolierung | "eingeschränkte Isolierung" for degraded |
| command line (CLI) | Befehlszeile | the button says "CLI im PATH installieren"; PATH stays |
| kill (a running script) | beenden | "Beenden angefordert" |
| flag (audit) | Markierung | |
| old installs (orphans) | alte Installationen | "vergessen" for forget |
| host call | Host-Aufruf | |
| elapsed | Dauer | |
| tray menu | Tray-Menü | |
| badge (attention mode "badge only") | Kennzeichen | |
| credential window | Anmeldedatenfenster | the separate window where tokens and passphrases are typed |
| candidate cache | Kandidaten-Cache | |
| backlog (pruning) | Rückstand | |
| heap (script limit) | Heap | stays English |