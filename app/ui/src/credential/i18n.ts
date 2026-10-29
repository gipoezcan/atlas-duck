// The credential page's own two-language table (M15 T7, PD-71, PD-297). Local on purpose: nothing
// under src/credential/ imports from src/shared/, so this is a copy of the shared pattern (English
// is the source, German must satisfy its widened type) and not an import of it. The page never
// reads the browser language or storage: Rust sends the resolved language in `credential_context`.

export type CredentialLang = 'en' | 'de';

/** Widens the `as const` English table: literals become `string`, functions keep their shape. */
type Widen<T> = T extends string
  ? string
  : T extends (...a: infer A) => string
    ? (...a: A) => string
    : T extends object
      ? { [K in keyof T]: Widen<T[K]> }
      : T;

/** Grouped digits per language (`12,345` / `12.345`). */
function num(lang: CredentialLang, n: number): string {
  return new Intl.NumberFormat(lang === 'de' ? 'de-DE' : 'en-US').format(n);
}

const en = {
  /** §8.6 verbatim: the purpose of the recovery passphrase (Rust: `passphrase_purpose(En)`). */
  // One literal on purpose: credential/mod.rs's test finds it here verbatim.
  // prettier-ignore
  purpose_line: 'Unlocks and restores the audit log (after a keychain loss, from a backup, or on a new machine). Stored tokens are never recovered (from a backup or after a keychain loss); you re-enter them. It is not your Atlassian password. Store it where your compliance owner can retrieve it.',
  /** plan text (PD-168): the one line of the `restore_backup` window. */
  restore_line: 'Restore a backup: enter the recovery passphrase of the backup.',
  titles: {
    add_pat: 'Add token',
    replace_pat: 'Replace token',
    recovery_passphrase: 'Set recovery passphrase',
    unlock: 'Locked',
    recover_this_log: 'Recover this log',
    finish_restore: 'Finish restore',
    restore_backup: 'Restore a backup',
    change_recovery_passphrase: 'Change recovery passphrase',
  },
  submit: {
    recovery_passphrase: 'Set passphrase',
    change_recovery_passphrase: 'Change passphrase',
    restore_backup: 'Restore',
    pat: 'Test and store',
    unlock: 'Unlock',
  },
  failures: {
    http_401:
      'The server rejected the token (401). Check that it is a valid personal access token that has not expired.',
    tls: 'The TLS certificate of the server could not be verified. If your server uses an internal CA, add it as the instance custom CA.',
    proxy: 'A proxy blocked or changed the connection. Check the proxy settings.',
    network: 'The server could not be reached.',
    version_below_floor: 'The server version is below the minimum atlas-duck supports.',
    identity_header_missing:
      'X-AUSERNAME not received, possibly stripped by a reverse proxy in front of Jira.',
    identity_header_mismatch: 'The X-AUSERNAME header does not match the user of the token.',
    other_user: 'The token belongs to a different user than the one stored for this instance.',
    not_known_user: 'The token belongs to a user that is not known for this instance.',
    unavailable: 'The server answered with an error. Try again later.',
    context_changed:
      'The instance changed while this window was open. Nothing was sent. Close this window and start again from Settings.',
    passphrase_mismatch: 'The two passphrases differ.',
    wrong_passphrase: 'This is not the recovery passphrase of this log.',
    keychain_unavailable: 'The OS keychain is not available.',
    keyring_not_local: 'The OS keychain is not on this machine.',
    store_newer: 'The audit log was written by a newer atlas-duck.',
    integrity: 'The audit log failed its integrity check.',
    io: 'The audit log could not be read or written.',
    invalid: 'The audit log is not valid.',
    core_start: 'atlas-duck could not start after the unlock.',
    not_locked: 'atlas-duck is not locked.',
    busy: 'Another unlock is running. Try again in a moment.',
    shutting_down: 'atlas-duck is shutting down.',
    cancelled: 'Cancelled.',
    not_ready: 'This window cannot take that now.',
    passphrase_not_changed: 'The recovery passphrase was not changed.',
    not_a_backup: 'That folder is not a backup of atlas-duck. Nothing was changed.',
    broken: 'The backup does not verify. Nothing was changed.',
    anchor_dir_mismatch: 'The backup does not match the anchor directory. Nothing was changed.',
    committed_incomplete: 'Restore will be completed at the next start. Restart atlas-duck.',
    archive_first:
      'The locked audit log cannot be moved aside because its records cannot be read. Use "Archive old DB and start fresh" first.',
  },
  passphrase_too_short: (min: number) => `The passphrase needs at least ${min} characters.`,
  /** A failed "Restore a backup instead": these classes are about the chosen backup. */
  restore_failures: {
    wrong_passphrase: 'This is not the recovery passphrase of that backup.',
    store_newer: 'The backup was written by a newer atlas-duck.',
  },
  unknown_failure: (cls: string) => `The operation failed (${cls}).`,
  not_completed: 'The request could not be completed.',
  meter: (n: number, min: number) => `${n} of ${min} characters`,
  differ: 'The two passphrases differ.',
  connected: (user: string, product: string, version: string) =>
    `Connected as ${user}, ${product} ${version}. You can close this window.`,
  product_server: 'server',
  escapes_user_version: 'Some characters in the user or version are shown as escapes.',
  passphrase_changed: 'Recovery passphrase changed.',
  restore_running: 'Passphrase sent. The restore is running.',
  passphrase_accepted: 'Passphrase accepted.',
  unlocked: 'Unlocked.',
  detail: (d: string) => `Detail: ${d}`,
  archived: 'The old audit log was moved aside. Set up atlas-duck again in the setup window.',
  note_saved: 'Recovery note saved.',
  note_not_saved: 'The recovery note was not saved.',
  keychain_retry: 'Trying the keychain again.',
  keychain_retry_running: 'A keychain retry is already running.',
  facts: { instance: 'Instance', product: 'Product', address: 'Address' },
  escapes_warning:
    'Some characters above are not ordinary and are shown as escapes. Check the address before you continue.',
  /** §2.5 / §10.3 verbatim: "Locked — N requests refused", "Setup required — N requests refused". */
  locked_line: (setup: boolean, n: string) =>
    `${setup ? 'Setup required' : 'Locked'} — ${n} requests refused`,
  retry_keychain: 'Retry keychain',
  save_note: 'Save recovery note',
  archive: 'Archive old DB and start fresh',
  restore_instead: 'Restore a backup instead',
  close: 'Close',
  cancel: 'Cancel',
  quit: 'Quit atlas-duck',
  fallback_title: 'Credential entry',
  context_unavailable: 'The window context is unavailable. Quit and start atlas-duck again.',
  pat_label: 'Personal access token',
  expires_label: 'Token expires on (optional)',
  new_passphrase: 'New recovery passphrase',
  passphrase: 'Recovery passphrase',
  repeat: 'Repeat the passphrase',
  keychain_hint: 'The OS keychain is not available. Unlock it, then try again.',
} as const;

export type CredentialText = Widen<typeof en>;

const de: CredentialText = {
  /** §8.6 (Rust: `passphrase_purpose(De)`). */
  // prettier-ignore
  purpose_line: 'Entsperrt und stellt das Audit-Protokoll wieder her (nach einem Verlust des Schlüsselbunds, aus einem Backup oder auf einem neuen Computer). Gespeicherte Token werden nie wiederhergestellt (weder aus einem Backup noch nach einem Verlust des Schlüsselbunds); Sie geben sie erneut ein. Sie ist nicht Ihr Atlassian-Passwort. Bewahren Sie sie so auf, dass Ihr Compliance-Verantwortlicher sie abrufen kann.',
  restore_line: 'Backup wiederherstellen: Geben Sie die Wiederherstellungs-Passphrase des Backups ein.',
  titles: {
    add_pat: 'Token hinzufügen',
    replace_pat: 'Token ersetzen',
    recovery_passphrase: 'Wiederherstellungs-Passphrase festlegen',
    unlock: 'Gesperrt',
    recover_this_log: 'Dieses Protokoll wiederherstellen',
    finish_restore: 'Wiederherstellung abschließen',
    restore_backup: 'Backup wiederherstellen',
    change_recovery_passphrase: 'Wiederherstellungs-Passphrase ändern',
  },
  submit: {
    recovery_passphrase: 'Passphrase festlegen',
    change_recovery_passphrase: 'Passphrase ändern',
    restore_backup: 'Wiederherstellen',
    pat: 'Testen und speichern',
    unlock: 'Entsperren',
  },
  failures: {
    http_401:
      'Der Server hat das Token zurückgewiesen (401). Prüfen Sie, ob es ein gültiges persönliches Zugriffstoken ist, das nicht abgelaufen ist.',
    tls: 'Das TLS-Zertifikat des Servers konnte nicht geprüft werden. Wenn Ihr Server eine interne CA verwendet, fügen Sie sie als eigene CA der Instanz hinzu.',
    proxy: 'Ein Proxy hat die Verbindung blockiert oder verändert. Prüfen Sie die Proxy-Einstellungen.',
    network: 'Der Server war nicht erreichbar.',
    version_below_floor: 'Die Serverversion liegt unter dem Minimum, das atlas-duck unterstützt.',
    identity_header_missing:
      'X-AUSERNAME wurde nicht empfangen, möglicherweise von einem Reverse Proxy vor Jira entfernt.',
    identity_header_mismatch: 'Der Header X-AUSERNAME passt nicht zum Benutzer des Tokens.',
    other_user: 'Das Token gehört einem anderen Benutzer als dem, der für diese Instanz gespeichert ist.',
    not_known_user: 'Das Token gehört einem Benutzer, der für diese Instanz nicht bekannt ist.',
    unavailable: 'Der Server hat mit einem Fehler geantwortet. Versuchen Sie es später erneut.',
    context_changed:
      'Die Instanz hat sich geändert, während dieses Fenster offen war. Es wurde nichts gesendet. Schließen Sie dieses Fenster und beginnen Sie erneut in den Einstellungen.',
    passphrase_mismatch: 'Die beiden Passphrasen unterscheiden sich.',
    wrong_passphrase: 'Das ist nicht die Wiederherstellungs-Passphrase dieses Protokolls.',
    keychain_unavailable: 'Der Schlüsselbund des Betriebssystems ist nicht verfügbar.',
    keyring_not_local: 'Der Schlüsselbund des Betriebssystems liegt nicht auf diesem Computer.',
    store_newer: 'Das Audit-Protokoll wurde von einem neueren atlas-duck geschrieben.',
    integrity: 'Das Audit-Protokoll hat seine Integritätsprüfung nicht bestanden.',
    io: 'Das Audit-Protokoll konnte nicht gelesen oder geschrieben werden.',
    invalid: 'Das Audit-Protokoll ist nicht gültig.',
    core_start: 'atlas-duck konnte nach dem Entsperren nicht starten.',
    not_locked: 'atlas-duck ist nicht gesperrt.',
    busy: 'Ein anderes Entsperren läuft. Versuchen Sie es gleich erneut.',
    shutting_down: 'atlas-duck wird beendet.',
    cancelled: 'Abgebrochen.',
    not_ready: 'Dieses Fenster kann das gerade nicht annehmen.',
    passphrase_not_changed: 'Die Wiederherstellungs-Passphrase wurde nicht geändert.',
    not_a_backup: 'Dieser Ordner ist kein Backup von atlas-duck. Es wurde nichts geändert.',
    broken: 'Das Backup lässt sich nicht verifizieren. Es wurde nichts geändert.',
    anchor_dir_mismatch: 'Das Backup passt nicht zum Anker-Verzeichnis. Es wurde nichts geändert.',
    committed_incomplete:
      'Die Wiederherstellung wird beim nächsten Start abgeschlossen. Starten Sie atlas-duck neu.',
    archive_first:
      'Das gesperrte Audit-Protokoll kann nicht beiseitegelegt werden, weil seine Datensätze nicht lesbar sind. Verwenden Sie zuerst „Alte DB archivieren und neu beginnen“.',
  },
  passphrase_too_short: (min) => `Die Passphrase braucht mindestens ${min} Zeichen.`,
  restore_failures: {
    wrong_passphrase: 'Das ist nicht die Wiederherstellungs-Passphrase dieses Backups.',
    store_newer: 'Das Backup wurde von einem neueren atlas-duck geschrieben.',
  },
  unknown_failure: (cls) => `Der Vorgang ist fehlgeschlagen (${cls}).`,
  not_completed: 'Die Anfrage konnte nicht abgeschlossen werden.',
  meter: (n, min) => `${n} von ${min} Zeichen`,
  differ: 'Die beiden Passphrasen unterscheiden sich.',
  connected: (user, product, version) =>
    `Verbunden als ${user}, ${product} ${version}. Sie können dieses Fenster schließen.`,
  product_server: 'Server',
  escapes_user_version: 'Einige Zeichen im Benutzer oder in der Version werden als Escape-Folgen angezeigt.',
  passphrase_changed: 'Wiederherstellungs-Passphrase geändert.',
  restore_running: 'Passphrase gesendet. Die Wiederherstellung läuft.',
  passphrase_accepted: 'Passphrase angenommen.',
  unlocked: 'Entsperrt.',
  detail: (d) => `Detail: ${d}`,
  archived:
    'Das alte Audit-Protokoll wurde beiseitegelegt. Richten Sie atlas-duck im Einrichtungsfenster neu ein.',
  note_saved: 'Wiederherstellungsnotiz gespeichert.',
  note_not_saved: 'Die Wiederherstellungsnotiz wurde nicht gespeichert.',
  keychain_retry: 'Der Schlüsselbund wird erneut versucht.',
  keychain_retry_running: 'Ein erneuter Versuch mit dem Schlüsselbund läuft bereits.',
  facts: { instance: 'Instanz', product: 'Produkt', address: 'Adresse' },
  escapes_warning:
    'Einige Zeichen oben sind ungewöhnlich und werden als Escape-Folgen angezeigt. Prüfen Sie die Adresse, bevor Sie fortfahren.',
  locked_line: (setup, n) =>
    `${setup ? 'Einrichtung erforderlich' : 'Gesperrt'} — ${n} ${n === '1' ? 'Anfrage' : 'Anfragen'} abgewiesen`,
  retry_keychain: 'Schlüsselbund erneut versuchen',
  save_note: 'Wiederherstellungsnotiz speichern',
  archive: 'Alte DB archivieren und neu beginnen',
  restore_instead: 'Stattdessen ein Backup wiederherstellen',
  close: 'Schließen',
  cancel: 'Abbrechen',
  quit: 'atlas-duck beenden',
  fallback_title: 'Anmeldedaten eingeben',
  context_unavailable:
    'Der Fensterkontext ist nicht verfügbar. Beenden Sie atlas-duck und starten Sie es erneut.',
  pat_label: 'Persönliches Zugriffstoken',
  expires_label: 'Token läuft ab am (optional)',
  new_passphrase: 'Neue Wiederherstellungs-Passphrase',
  passphrase: 'Wiederherstellungs-Passphrase',
  repeat: 'Passphrase wiederholen',
  keychain_hint:
    'Der Schlüsselbund des Betriebssystems ist nicht verfügbar. Entsperren Sie ihn und versuchen Sie es erneut.',
};

export const CREDENTIAL_TEXT: { readonly en: CredentialText; readonly de: CredentialText } = { en, de };

/** The table of `lang`. */
export function pageText(lang: CredentialLang): CredentialText {
  return lang === 'de' ? de : en;
}

/** A count in the page's language. */
export function formatCount(lang: CredentialLang, n: number): string {
  return num(lang, n);
}
