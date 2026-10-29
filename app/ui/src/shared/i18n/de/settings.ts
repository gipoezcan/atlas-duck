import { formatIsoDate, formatNumber } from '../format';
import type { Dict } from '../index';

/** Die Beschriftungen der acht Skript-Limits (auch die Namen, die Rusts Zurückweisungen tragen). */
const SCRIPT_LIMIT_LABELS = {
  timeout_s: 'Skript-Zeitlimit (s)',
  heap_mb: 'Skript-Heap-Limit (MiB)',
  process_mb: 'Skript-Prozesslimit (MiB)',
  max_calls: 'Skript-Aufruflimit',
  max_fetch_mb: 'Skript-Abruflimit (MiB)',
  max_call_result_mb: 'Skript-Limit je Aufrufergebnis (MiB)',
  max_result_mb: 'Skript-Ergebnislimit (MiB)',
  max_concurrent_calls: 'Gleichzeitige Skript-Aufrufe',
};

const tage = (n: number) => `${formatNumber('de', n)} ${n === 1 ? 'Tag' : 'Tage'}`;

export const settings: Dict['settings'] = {
  https_required_hint:
    'atlas-duck verlangt https; wenn Ihr Server eine interne CA verwendet, fügen Sie sie als eigene CA der Instanz hinzu',
  identity_header_hint:
    'X-AUSERNAME wurde nicht empfangen, möglicherweise von einem Reverse-Proxy vor Jira entfernt; wenden Sie sich an die Jira-Administration',
  pac_hint:
    'Ihr System verwendet ein Proxy-Auto-Config-Skript, das atlas-duck nicht auswertet: Legen Sie den Proxy dieser Instanz (Host:Port oder direct) in den Einstellungen fest',
  committed_incomplete: 'Die Wiederherstellung wird beim nächsten Start abgeschlossen',
  loading: 'Einstellungen werden geladen',
  load_failed: 'Die Einstellungen konnten nicht geladen werden',
  retry: 'Erneut versuchen',
  url_change: 'config.toml fordert eine URL-Änderung an für',
  url_change_requested: 'Angeforderte URL:',
  url_change_accept: 'URL-Änderung übernehmen',
  read_only_prefix: 'Die Einstellungen sind schreibgeschützt:',
  config_banner: (kind, version, parsed) => {
    const by = version === null ? 'einer neueren atlas-duck-Version' : `atlas-duck ${version}`;
    return kind === 'unreadable' && !parsed
      ? 'Die Konfiguration konnte nicht gelesen werden; die Einstellungen sind nicht verfügbar, bis sie lesbar ist'
      : kind === 'unreadable'
        ? `Die Konfiguration von ${by} konnte nicht gelesen werden; aktualisieren Sie atlas-duck`
        : `Die Konfiguration wurde von ${by} geschrieben; die Einstellungen sind schreibgeschützt, bis Sie aktualisieren`;
  },
  prune_backlog_line: (days) =>
    `Die Bereinigung ist ${formatNumber('de', days)} ${days === 1 ? 'Tag' : 'Tage'} im Rückstand`,
  instances: 'Instanzen',
  no_instances: 'Es sind keine Instanzen eingerichtet',
  col_alias: 'Alias',
  col_product: 'Produkt',
  col_origin: 'Origin',
  col_state: 'Status',
  col_executes_as: 'Ausführung als',
  col_expiry: 'Token-Ablauf',
  col_proxy: 'Proxy',
  col_actions: 'Aktionen',
  product: { jira: 'Jira', confluence: 'Confluence' },
  no_origin: '(nicht bestätigt)',
  none: '(keine)',
  proxy_os: 'Systemeinstellung oder keiner',
  states: {
    ok: 'in Ordnung',
    needs_token: 'braucht Token',
    identity_header_missing: 'Identitäts-Header fehlt',
    identity_header_mismatch: 'Identitäts-Header stimmt nicht überein',
    insecure_scheme: 'unsicheres Schema (http)',
    instance_unconfirmed: 'unbestätigt',
  },
  confirm_hint: 'Bestätigen Sie diese Instanz: Rust zeigt Alias und Origin in einem nativen Dialog.',
  confirm: 'Instanz bestätigen',
  retest: 'Gespeichertes Token erneut prüfen',
  replace_token: 'Token ersetzen',
  add_token: 'Token hinzufügen',
  retest_connected: 'Verbunden als',
  retest_failed: 'Die erneute Prüfung ist fehlgeschlagen:',
  retest_classes: {
    http_401: 'der Server hat das Token zurückgewiesen',
    other_user: 'das Token gehört jetzt einem anderen Benutzer',
    network: 'der Server war nicht erreichbar',
    tls: 'das TLS-Zertifikat wurde nicht akzeptiert',
    proxy: 'der Proxy hat die Verbindung zurückgewiesen oder war nicht erreichbar',
    unavailable: 'der Server hat keine Identität geliefert',
    identity_header_missing: 'der Identitäts-Header wurde nicht empfangen: siehe den Hinweis bei dieser Instanz',
    identity_header_mismatch: 'der Identitäts-Header stimmte nicht überein: siehe den Hinweis bei dieser Instanz',
    version_below_floor: 'die Serverversion liegt unter dem unterstützten Minimum',
    not_known_user: 'das Token gehört einem Benutzer, den atlas-duck nicht kennt',
  },
  retest_class_unknown: 'der Server hat in einer Weise geantwortet, die atlas-duck nicht erkennt',
  retest_warnings: 'Warnungen:',
  change_url: 'URL ändern',
  change_url_label: 'Neue Basis-URL',
  change_url_apply: 'URL-Änderung anwenden',
  proxy_label: 'Proxy (Host:Port, direct oder leer für die Systemeinstellung)',
  proxy_apply: 'Proxy anwenden',
  expires_on: 'Läuft ab am',
  expiry_in: (n) => `Das Token läuft in ${formatNumber('de', n)} ${n === 1 ? 'Tag' : 'Tagen'} ab`,
  expiry_today: 'Das Token läuft heute ab',
  expiry_past: (date) => `Das Token ist am ${formatIsoDate('de', date)} abgelaufen`,
  expiry_soon: 'Das Token läuft bald ab',
  expiry_note: 'Nur eine Warnung: Ob ein Token funktioniert, entscheidet der Server.',
  add_heading: 'Instanz hinzufügen',
  add_alias: 'Alias',
  add_product: 'Produkt',
  add_url: 'Basis-URL (https, mit Kontextpfad)',
  add_proxy: 'Proxy (Host:Port, direct oder leer für die Systemeinstellung)',
  add_ca: 'Eigenes CA-Zertifikat verwenden (Rust fragt nach der Datei)',
  add_default: 'Standardinstanz für ihr Produkt',
  add_submit: 'Instanz hinzufügen',
  add_done: 'Die Instanz wurde hinzugefügt.',
  add_done_token: 'Die Instanz wurde hinzugefügt. Fügen Sie als Nächstes ihr Token hinzu.',
  limits: 'Limits',
  limit_labels: {
    jira_comments_cap: 'Obergrenze für Jira-Kommentare',
    candidate_cache_mb: 'Kandidaten-Cache (MB)',
    max_pending_bytes_mb: 'Obergrenze für ausstehende Bytes (MB, leer = aus)',
    expiry_hours: 'Ablauf von Anfragen (Stunden)',
    ...SCRIPT_LIMIT_LABELS,
  },
  script_limits: 'Skript-Limits',
  script_limit_labels: SCRIPT_LIMIT_LABELS,
  script_default: (n) => `Standard ${formatNumber('de', n)}`,
  script_limits_note:
    'Eine Änderung gilt für Skripte, die danach eingereicht werden. Das Erhöhen eines Limits wird in einem nativen Dialog bestätigt.',
  restart_marker: 'gilt nach dem Neustart',
  restart_waiting: 'ein geänderter Wert wartet auf den nächsten Start',
  retention: 'Aufbewahrung und Legal Hold',
  retention_days: 'Aufbewahrung des Audit-Protokolls (Tage)',
  legal_hold: 'Legal Hold (Bereinigung stoppt)',
  attention: 'Benachrichtigungsmodus',
  attention_modes: {
    show_without_activating: 'Fenster anzeigen, ohne den Fokus zu übernehmen',
    badge_only: 'Nur Kennzeichen',
    show_and_focus: 'Fenster anzeigen und Fokus übernehmen',
  },
  presentation_note: 'Der Präsentationsmodus lässt sich im Tray-Menü umschalten und wird hier nicht gespeichert.',
  apply: 'Anwenden',
  applied: 'Angewendet',
  not_a_number: 'Geben Sie eine ganze Zahl ein',
  prune: 'Bereinigung',
  prune_button: 'Rückstand jetzt bereinigen',
  prune_failed_last: 'Die letzte Bereinigung ist fehlgeschlagen.',
  pruned: (n, cutoff) => `${formatNumber('de', n)} ${n === 1 ? 'Datensatz' : 'Datensätze'} vor dem ${formatIsoDate('de', cutoff)} bereinigt`,
  pruned_clamped: 'Der Stichtag wurde durch das Aufbewahrungsminimum begrenzt.',
  prune_skipped: 'Die Bereinigung wurde übersprungen',
  prune_reasons: {
    legal_hold: 'Legal Hold ist aktiv',
    not_corroborated: 'noch kein Serverdatum hat das aktuelle Datum bestätigt',
    head_epoch_null: 'der neueste Audit-Datensatz hat noch kein Datum',
    already_ran_this_epoch: 'die Bereinigung ist für das aktuelle Datum schon gelaufen',
    clock_before_head: 'die Systemuhr geht vor dem neuesten Audit-Datensatz',
    clock_before_last_prune: 'die Systemuhr geht vor der letzten Bereinigung',
    nothing_to_advance: 'es gibt nichts Älteres zu bereinigen',
    config_not_reconciled: 'config.toml wurde in diesem Lauf noch nicht gelesen',
    clock_behind: 'die Systemuhr geht hinter dem Serverdatum nach',
  },
  confinement: 'Skript-Isolierung',
  confinement_met: 'erfüllt: Skripte dürfen laufen',
  confinement_not_met: 'nicht erfüllt: Skripte sind aus',
  confinement_not_met_degraded:
    'nicht erfüllt: Skripte laufen nur, weil eingeschränkte Isolierung erlaubt ist',
  confinement_pending: 'die Prüfung beim Start ist noch nicht abgeschlossen',
  confinement_mode: 'Modus',
  confinement_failed: 'Fehlgeschlagene Prüfungen',
  confinement_layers: 'Zusätzliche Schichten',
  scripts_states: {
    enabled: 'Skripte sind aktiviert',
    disabled: 'Skripte sind deaktiviert',
    degraded: 'Skripte sind mit eingeschränkter Isolierung aktiviert',
  },
  degraded_toggle: 'Skripte mit eingeschränkter Isolierung erlauben',
  scripts_degraded_caution: 'Skripte laufen mit eingeschränkter Isolierung',
  degraded_inactive: 'Erlaubt, aber nicht in Gebrauch: Die Isolierungsgrenze ist erfüllt.',
  degraded_note:
    'Das Einschalten wird in einem nativen Dialog bestätigt. Ein kompromittierter Skript-Worker könnte dann als Ihr Benutzer handeln.',
  layer_on: 'an',
  layer_off: 'aus',
  cli: 'Befehlszeile',
  cli_installed: 'Der Befehl atlas-duck befindet sich in Ihrem PATH.',
  cli_not_installed: 'Der Befehl atlas-duck befindet sich nicht in Ihrem PATH.',
  cli_installed_dir_not_on_path:
    'Der Befehl atlas-duck ist installiert, aber sein Ordner liegt nicht im PATH, mit dem diese App gestartet wurde. Ein Terminal, das Sie öffnen, findet ihn möglicherweise trotzdem; falls nicht, fügen Sie diesen Ordner dem PATH Ihrer Shell hinzu.',
  cli_not_installed_dir_on_path:
    'Der Ordner für den Befehl atlas-duck liegt bereits in Ihrem PATH, aber die Installation ist noch nicht abgeschlossen. Schließen Sie sie mit der Schaltfläche ab.',
  cli_install: 'CLI im PATH installieren',
  cli_uninstall: 'CLI aus dem PATH entfernen',
  cli_outcomes: {
    installed:
      'Installiert. Öffnen Sie ein neues Terminal und starten Sie Ihre MCP-Clients neu, damit sie den Befehl atlas-duck finden.',
    installed_local_bin:
      'Nach ~/.local/bin installiert; dieser Ordner liegt möglicherweise nicht im PATH der Terminals, die Sie öffnen. Falls ein neues Terminal den Befehl atlas-duck nicht findet, fügen Sie ~/.local/bin dem PATH Ihrer Shell hinzu (unter Ubuntu: ab- und wieder anmelden) und starten Sie danach Ihre MCP-Clients neu.',
    installed_local_bin_on_path:
      'Nach ~/.local/bin installiert; dieser Ordner liegt im PATH, mit dem diese App gestartet wurde. Öffnen Sie ein neues Terminal und starten Sie Ihre MCP-Clients neu, damit sie den Befehl atlas-duck finden.',
    replaced_stale_entry:
      'Installiert. Der PATH-Eintrag eines früheren atlas-duck-Ordners, den es nicht mehr gibt, wurde entfernt. Öffnen Sie ein neues Terminal und starten Sie Ihre MCP-Clients neu, damit sie den Befehl atlas-duck finden.',
    already_installed: 'Der Befehl atlas-duck war bereits installiert.',
    removed: 'Entfernt. Neue Terminals finden den Befehl atlas-duck nicht mehr.',
    already_on_path:
      'Der Befehl atlas-duck gehört zum Paket und liegt bereits in Ihrem PATH: Es gibt nichts zu installieren oder zu entfernen.',
  },
  cli_errors: {
    no_stable_path:
      'atlas-duck kann nicht bestimmen, welche Datei in Ihren PATH gehört: Starten Sie es aus der installierten App (oder der AppImage-Datei selbst) und versuchen Sie es erneut',
    unsafe_path:
      'Der Installationsort enthält ein Zeichen, das sich nicht sicher in den PATH aufnehmen lässt (zum Beispiel ein Semikolon oder ein Anführungszeichen): Verschieben Sie die App in einen anderen Ordner',
    occupied:
      'Eine Datei oder ein Link namens atlas-duck steht im Weg und wurde nicht angetastet: Entfernen Sie sie und versuchen Sie es erneut',
    unsupported: 'Die Installation im PATH wird auf diesem System nicht unterstützt',
    registry: 'Ihr Benutzer-PATH konnte nicht gelesen oder geändert werden',
    path_too_long:
      'Ihr Benutzer-PATH ist zu lang, um den atlas-duck-Ordner hinzuzufügen: Kürzen Sie ihn und versuchen Sie es erneut',
    io: 'Die Befehlsdatei konnte nicht geschrieben oder entfernt werden',
    cli_toml: 'Die Datei, die den Ort der App festhält, konnte nicht geschrieben werden',
    newer_version:
      'Die Befehlsdatei wurde von einem neueren atlas-duck installiert und nicht angetastet: Verwenden Sie diese Version oder entfernen Sie die Datei und versuchen Sie es erneut',
    other: 'Die Befehlszeile konnte nicht installiert oder entfernt werden',
  },
  removal: 'Auf die Entfernung vorbereiten',
  removal_intro:
    'Bevor Sie atlas-duck deinstallieren: Erstellen Sie ein Backup, wenn Sie eines möchten, löschen Sie die gespeicherten Tokens, widerrufen Sie jedes Token auf seinem Server und entfernen Sie die Befehlszeile und den Autostart-Eintrag. Das Audit-Protokoll, seine Schlüssel und seine Anker bleiben erhalten, damit das Protokoll bis zum Ende der Aufbewahrungsfrist prüfbar bleibt.',
  removal_retention: (days, hold) =>
    `Der neueste Audit-Datensatz bleibt ${hold ? 'bis zur Aufhebung des Legal Hold und danach noch' : 'noch'} mindestens ${tage(days)} erhalten.`,
  removal_retention_left: (days) => `Der neueste Audit-Datensatz bleibt noch mindestens ${tage(days)} erhalten.`,
  removal_retention_hold: 'Der neueste Audit-Datensatz bleibt unbegrenzt erhalten: Ein Legal Hold ist aktiv.',
  removal_export: 'Audit-Protokoll exportieren…',
  removal_export_note:
    'Exportiert das gesamte Audit-Protokoll mit seinen entschlüsselten Nutzdaten in einen neuen Ordner. atlas-duck zeigt eine Warnung und fragt in eigenen Dialogen nach dem Ordner.',
  removal_export_running: 'Ein Export läuft',
  removal_export_starting: 'Der Export wird gestartet',
  removal_export_cancel: 'Export abbrechen',
  removal_export_cancel_requested: 'Abbruch angefordert. Das eigene Ergebnis des Exports folgt.',
  removal_export_cancel_none: 'Es lief kein Export.',
  removal_recorded:
    'Ihre Antworten sind im Audit-Protokoll festgehalten und endgültig. Wenn atlas-duck inzwischen neu gestartet wurde, wird dieser Ablauf hier fortgesetzt. Er endet nur mit „Entfernung abschließen“.',
  removal_backup: 'Vollbackup erstellen',
  removal_backup_note: 'Ein Backup enthält nie ein Token. Den Ordner wählen Sie im nächsten Dialog.',
  removal_backup_saved: 'Das Backup wurde gespeichert.',
  removal_backup_cancelled: 'Es wurde kein Backup erstellt.',
  removal_backup_made: 'In diesem Ablauf wurde ein Backup erstellt.',
  removal_begin: 'Gespeicherte Tokens löschen',
  removal_retry: 'Verbleibende Tokens löschen',
  removal_revoke_step: 'Widerrufen Sie dieses Token in Jira/Confluence (Profil → Persönliche Zugriffstoken)',
  removal_checklist: 'Tokens widerrufen',
  removal_alias: 'Instanz',
  removal_identity: 'Token-Identität',
  removal_identity_unknown: 'nicht bekannt (für diese Instanz ist keine Token-Identität festgehalten)',
  removal_not_deleted: 'Das Token ist noch gespeichert: Es konnte nicht gelöscht werden.',
  removal_token_back: 'Für diese Instanz ist wieder ein Token gespeichert: Löschen Sie es erneut.',
  removal_done: 'Ich habe es widerrufen',
  removal_skip: 'Überspringen',
  removal_choice_done: 'Als widerrufen markiert.',
  removal_choice_skipped: 'Übersprungen: Das Token bleibt auf dem Server gültig, bis es dort widerrufen wird.',
  removal_choice_pending: 'Noch nicht beantwortet.',
  removal_undo: 'Erneut beantworten',
  removal_finish: 'Entfernung abschließen',
  removal_finish_hint:
    'Zum Abschließen muss jede Instanz abgehakt oder übersprungen sein. Der Abschluss entfernt den Autostart-Eintrag und die Befehlszeile (PATH-Eintrag, Link oder Wrapper, Starter und cli.toml) und behält das Audit-Protokoll, seine Schlüssel und seine Anker.',
  removal_cli: {
    removed: 'Die Befehlszeile wurde entfernt.',
    already_on_path: 'Die Befehlszeile gehört zum Paket: Entfernen Sie das Paket, um sie zu entfernen.',
    not_found: 'Es wurde keine Befehlszeile von atlas-duck gefunden.',
    not_removed: 'Die Befehlszeile wurde nicht entfernt.',
  },
  removal_cli_reasons: {
    no_stable_path:
      'atlas-duck kann von diesem Ort aus nicht bestimmen, wo es installiert ist, daher liegt die Befehlszeile möglicherweise noch in Ihrem PATH',
    unsafe_path:
      'Der Installationsort enthält ein Zeichen, das sich nicht sicher behandeln lässt (zum Beispiel ein Semikolon oder ein Anführungszeichen), daher liegt die Befehlszeile möglicherweise noch in Ihrem PATH',
    unsupported: 'Das Entfernen der Befehlszeile wird auf diesem System nicht unterstützt',
    io: 'Die Dateien dieses Computers konnten nicht gelesen werden',
    registry: 'Ihr Benutzer-PATH konnte nicht gelesen oder geändert werden',
    cli_toml: 'Die Datei, die den Ort der App festhält, konnte nicht entfernt werden',
    newer_version:
      'Die Befehlsdatei wurde von einem neueren atlas-duck installiert und nicht angetastet: Verwenden Sie diese Version, um sie zu entfernen, oder entfernen Sie die Datei selbst',
    other: 'Die Befehlszeile konnte nicht entfernt werden',
  },
  removal_autostart: {
    removed: 'atlas-duck startet nicht mehr bei der Anmeldung.',
    was_off: 'atlas-duck startete nicht bei der Anmeldung.',
  },
  removal_complete:
    'Fertig. Sie können atlas-duck jetzt deinstallieren. Das Audit-Protokoll, seine Schlüssel und seine Anker bleiben auf diesem Computer; die Dokumentation nennt, wo, damit Sie sie nach Ablauf der Aufbewahrungsfrist löschen können.',
  removal_incomplete:
    'Nicht fertig: Die Befehlszeile ist möglicherweise noch installiert. Entfernen Sie den Befehl atlas-duck und die Datei cli.toml von Hand oder starten Sie atlas-duck von seinem Installationsort und führen Sie diesen Ablauf erneut aus. Die Tokens sind gelöscht und Ihre Antworten festgehalten; das Audit-Protokoll, seine Schlüssel und seine Anker bleiben auf diesem Computer.',
  removal_errors: {
    no_procedure: 'Löschen Sie zuerst die gespeicherten Tokens',
    unticked: 'Haken Sie zuerst jede Instanz ab oder überspringen Sie sie',
    token_stored: 'Für eine Instanz ist wieder ein Token gespeichert: Löschen Sie es erneut und schließen Sie dann ab',
    autostart: 'Der Autostart-Eintrag konnte nicht gelesen oder entfernt werden',
    recorded: 'Die Antworten sind bereits festgehalten: Schließen Sie die Entfernung ab',
    running:
      'Ein anderer Schritt der Entfernung oder ein Backup läuft: Warten Sie, bis er beendet ist, und versuchen Sie es erneut',
  },
  working: 'In Arbeit',
  errors: {
    busy: 'Das Anmeldedatenfenster ist geöffnet oder eine andere Aufgabe läuft (ein Export, ein Backup, eine Wiederherstellung oder ein Schritt der Entfernung): Schließen Sie das Fenster oder warten Sie und versuchen Sie es erneut',
    not_found: 'Diese Instanz gibt es nicht mehr',
    not_ready: 'Die App startet noch: Versuchen Sie es gleich noch einmal',
    internal: 'Der Befehl ist fehlgeschlagen',
    refused: 'Der Befehl wurde zurückgewiesen',
    cancelled: 'Abgebrochen: Es wurde nichts geändert',
    backup: 'Das Backup ist fehlgeschlagen. Wenn im gewählten Ordner ein unfertiger Backup-Ordner zurückgeblieben ist, löschen Sie ihn.',
    config_read_only: 'config.toml wurde von einer neueren Version geschrieben: Die Einstellungen sind schreibgeschützt',
    no_config_file: 'Es gibt keine config.toml, die geändert werden könnte',
    conflict: 'config.toml hat sich inzwischen geändert: Laden Sie neu und versuchen Sie es erneut',
    config_write_failed: 'config.toml konnte nicht geschrieben werden',
    audit: 'Die Änderung wurde zurückgewiesen',
    duplicate_alias: 'Eine andere Instanz verwendet diesen Alias bereits: Wählen Sie einen anderen Alias',
    second_default: 'Dieses Produkt hat bereits eine Standardinstanz: Es kann nur eine haben',
    unusable_ca_bundle: 'Diese Datei enthält kein verwendbares CA-Zertifikat: Wählen Sie eine PEM-Datei mit dem Zertifikat',
    invalid_url: 'Das ist keine gültige URL',
    keychain: 'Der Token-Speicher ist nicht verfügbar oder enthält kein Token für diese Instanz',
    shutting_down: 'Die App wird beendet',
    unconfirmed: 'Bestätigen Sie zuerst die Instanz',
    connection_failed: 'Der Verbindungstest ist fehlgeschlagen',
    other: 'Die Änderung wurde zurückgewiesen',
  },
  invalid_field: (what) => `Prüfen Sie diesen Wert: ${what}`,
  invalid_field_unknown: 'ein Feld',
  invalid_setting_unknown: 'eine Einstellung',
  invalid_arguments: {
    alias: 'Alias',
    product: 'Produkt',
    base_url: 'Basis-URL',
    proxy: 'Proxy',
    use_custom_ca: 'CA-Datei (wählen Sie eine andere Datei)',
  },
  recovery: {
    recovery: 'Wiederherstellung und Backup',
    backup_tokens:
      'Backups enthalten nie gespeicherte Tokens; nach einer Wiederherstellung braucht jede Instanz ihr Token erneut.',
    backup_retention:
      'Backups und Exporte unterliegen weder der Aufbewahrung noch dem Crypto-Shredding: Aufbewahren und Löschen liegt bei Ihnen.',
    upgrade_backup: 'Erstellen Sie vor jedem Upgrade ein Vollbackup.',
    backup_start: 'Jetzt sichern…',
    backup_running: 'Ein Backup läuft',
    backup_saved: 'Das Backup wurde gespeichert.',
    backup_not_saved: 'Es wurde kein Backup erstellt.',
    backup_cancelled: 'Abgebrochen: Es wurde kein Backup erstellt.',
    restore_note:
      'Die Wiederherstellung ersetzt dieses Audit-Protokoll durch das Protokoll eines Backups. atlas-duck bittet Sie in eigenen Dialogen um Bestätigung und um die Wiederherstellungs-Passphrase des Backups.',
    restore_start: 'Backup wiederherstellen…',
    restore_running: 'Eine Wiederherstellung läuft',
    restore_starting: 'Die Wiederherstellung wird gestartet',
    restore_wait: 'Anfragen warten, solange die Wiederherstellung läuft',
    restore_cancel: 'Wiederherstellung abbrechen',
    restore_cancel_requested: 'Abbruch angefordert.',
    restore_cancel_none: 'Es läuft keine Wiederherstellung.',
    restore_cancel_too_late: 'Die Wiederherstellung schreibt bereits und lässt sich nicht mehr abbrechen.',
    restore_done: 'Die Wiederherstellung ist abgeschlossen.',
    restore_records_lost: (n) =>
      n === 0
        ? 'Es gingen keine Datensätze verloren.'
        : `${formatNumber('de', n)} ${n === 1 ? 'Datensatz' : 'Datensätze'}, ${n === 1 ? 'der' : 'die'} nach dem Backup geschrieben wurde${n === 1 ? '' : 'n'}, ${n === 1 ? 'steht' : 'stehen'} nicht mehr im Protokoll.`,
    restore_tokens: (n) =>
      `Gespeicherte Tokens werden nie wiederhergestellt: ${n === 0 ? 'Es wurde kein Token gelöscht' : `${formatNumber('de', n)} gespeichert${n === 1 ? 'es Token wurde' : 'e Tokens wurden'} gelöscht`}, und jede Instanz braucht ihr Token erneut.`,
    restore_follow_up_failed:
      'Die Wiederherstellung ist abgeschlossen, aber ihr Folgeschritt ist fehlgeschlagen. Beenden Sie atlas-duck und starten Sie es erneut, um sie abzuschließen.',
    restore_restart:
      'Beenden Sie atlas-duck und starten Sie es erneut. Bis dahin lassen sich neue Anfragen nicht festhalten.',
    restore_passphrase_offer:
      'Die Wiederherstellungs-Passphrase des Backups ist jetzt die Wiederherstellungs-Passphrase dieses Protokolls. Sie können sie jetzt mit „Wiederherstellungs-Passphrase ändern…“ ändern.',
    restore_errors: {
      wrong_passphrase: 'Diese Wiederherstellungs-Passphrase öffnet das Backup nicht. Es wurde nichts geändert.',
      not_a_backup: 'Dieser Ordner ist kein Backup von atlas-duck. Es wurde nichts geändert.',
      newer:
        'Das Backup wurde von einem neueren atlas-duck geschrieben: Installieren Sie diese oder eine neuere Version. Es wurde nichts geändert.',
      broken: 'Das Backup besteht die Prüfung nicht. Es wurde nichts geändert.',
      anchor_dir_mismatch: 'Das Backup passt nicht zum Anker-Verzeichnis. Es wurde nichts geändert.',
      keychain: 'Der Schlüsselbund konnte nicht verwendet werden. Es wurde nichts geändert.',
      failed: 'Die Wiederherstellung ist fehlgeschlagen. Es wurde nichts geändert.',
    },
    passphrase_change: 'Wiederherstellungs-Passphrase ändern…',
    passphrase_note:
      'Die Wiederherstellungs-Passphrase entsperrt das Audit-Protokoll nach einem Verlust des Schlüsselbunds, aus einem Backup oder auf einem neuen Computer. Beim Ändern öffnet sich das Anmeldedatenfenster.',
    passphrase_opened: 'Das Anmeldedatenfenster ist geöffnet: Geben Sie dort die neue Passphrase ein.',
    reanchor_heading: 'Anker',
    anchors_missing: {
      head: 'Der Kopf-Anker-Eintrag fehlt im Schlüsselbund.',
      first_retained: 'Der Eintrag des ersten aufbewahrten Ankers fehlt im Schlüsselbund.',
      both: 'Die Einträge des Kopf-Ankers und des ersten aufbewahrten Ankers fehlen im Schlüsselbund.',
    },
    reanchor: 'Neu verankern…',
    reanchor_note:
      'Beim Neuverankern werden der Kopf-Anker und der Anker des ersten aufbewahrten Datensatzes aus dem Audit-Protokoll in seinem jetzigen Zustand neu geschrieben. Das wird als Integritätsvorfall festgehalten, den Sie im Audit-Fenster zur Kenntnis nehmen.',
    reanchor_done:
      'Neu verankert. Ein Integritätsvorfall wurde festgehalten: Nehmen Sie ihn im Audit-Fenster zur Kenntnis.',
    reanchor_errors: {
      nothing_missing: 'Es fehlt kein Anker-Eintrag: Es wurde nichts geändert.',
      held: 'Die Anker sind gesperrt, solange ein anderer Schritt läuft: Versuchen Sie es später erneut.',
      does_not_verify:
        'Das Protokoll besteht die Prüfung nicht, daher wurde nichts neu verankert. Ein Integritätsvorfall wurde festgehalten: siehe Audit.',
      restored: 'Eine Wiederherstellung hat die Anker inzwischen geändert: Es wurde nichts geändert.',
      keychain:
        'Der Schlüsselbund konnte nicht beschrieben werden. Ein Integritätsvorfall wurde festgehalten: siehe Audit.',
      failed: 'Das Neuverankern ist fehlgeschlagen. Es wurde nichts geändert.',
    },
    orphans: 'Alte Installationen',
    orphans_intro:
      'Diese Installationen haben ein archiviertes Audit-Protokoll oder Schlüsselbund-Einträge auf diesem Computer hinterlassen. Wenn Sie eine vergessen, werden ihre Schlüsselbund-Einträge nach nativen Bestätigungen gelöscht; die Schlüssel, die ihr archiviertes Protokoll öffnen, werden nur gelöscht, wenn Sie das ebenfalls bestätigen.',
    orphans_none: 'Es wurden keine alten Installationen gefunden.',
    orphans_load_failed: 'Die alten Installationen konnten nicht aufgelistet werden.',
    orphan_install: 'Installation',
    orphan_files: 'Archivierte Protokolle',
    orphan_entries: 'Schlüsselbund-Einträge',
    orphan_forget: 'Vergessen',
    orphan_forget_label: (installId) => `Installation ${installId} vergessen`,
    forgotten: (keysDeleted) =>
      keysDeleted
        ? 'Vergessen: Seine Schlüsselbund-Einträge und die Schlüssel seines archivierten Protokolls wurden gelöscht.'
        : 'Vergessen: Seine Token-Einträge wurden gelöscht; die Schlüssel seines archivierten Protokolls blieben erhalten.',
    forget_errors: {
      unreadable:
        'Die Schlüsselbund-Einträge der alten Installationen konnten nicht gelesen werden: Es wurde nichts gelöscht.',
      keychain:
        'Einige Einträge konnten nicht gelöscht werden. Vergessen Sie die Installation erneut, um den Rest zu löschen.',
      failed: 'Das Vergessen der Installation ist fehlgeschlagen.',
    },
    forget_deleted: 'Gelöscht',
    forget_not_deleted: 'Nicht gelöscht',
    anchor_dir: 'Externes Anker-Verzeichnis',
    anchor_dir_none: '(nicht festgelegt)',
    anchor_dir_note:
      'Kopien des Protokollkopfs werden in diesen Ordner geschrieben. Das schützt nur dann vor einem Zurückdrehen der Historie, wenn Sie den Ordner nicht selbst umschreiben können, zum Beispiel bei einer Freigabe, die jemand anderes verwaltet. atlas-duck fragt in eigenen Dialogen nach einem Ordner und bestätigt jede Änderung.',
    anchor_dir_set: 'Anker-Verzeichnis festlegen…',
    anchor_dir_change: 'Anker-Verzeichnis ändern…',
    anchor_dir_remove: 'Anker-Verzeichnis entfernen…',
    anchor_dir_changed: 'Das Anker-Verzeichnis wurde geändert.',
    anchor_dir_removed: 'Das Anker-Verzeichnis wurde entfernt.',
    anchor_dir_pending: (n) =>
      `${formatNumber('de', n)} ${n === 1 ? 'Zeile wartet' : 'Zeilen warten'} darauf, in das Anker-Verzeichnis geschrieben zu werden.`,
    anchor_dir_errors: {
      not_writable: 'In diesen Ordner kann nicht geschrieben werden',
      writer_busy: 'Das Audit-Protokoll ist beschäftigt: Versuchen Sie es gleich noch einmal.',
      unchanged: 'Das ist bereits das verwendete Anker-Verzeichnis: Es wurde nichts geändert.',
      not_set: 'Es ist kein Anker-Verzeichnis festgelegt: Es wurde nichts geändert.',
      failed: 'Dieser Ordner lässt sich nicht als Anker-Verzeichnis verwenden: Es wurde nichts geändert.',
    },
  },
};
