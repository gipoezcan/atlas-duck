/** The Settings window and the setup wizard's instance forms: the former SETTINGS_TEXT, RECOVERY_TEXT and the spec 7.1/7.2 hints. */
/**
 * M8 T23 (spec 9.4, PD-139): the labels of the eight script limits. They are also the names Rust's
 * refusals carry (`invalid` key, `invalid_argument` field), so `errorText` finds them by the wire key.
 */
const SCRIPT_LIMIT_LABELS = {
  timeout_s: 'Script timeout (s)',
  heap_mb: 'Script heap limit (MiB)',
  process_mb: 'Script process limit (MiB)',
  max_calls: 'Script call limit',
  max_fetch_mb: 'Script fetch limit (MiB)',
  max_call_result_mb: 'Script call result limit (MiB)',
  max_result_mb: 'Script result limit (MiB)',
  max_concurrent_calls: 'Script concurrent calls',
} as const;

export const settings = {
  /** spec 7.1 (verbatim): the fixed hint beside an `http://` base URL. */
  https_required_hint:
    "atlas-duck requires https; if your server uses an internal CA, add it as the instance's custom CA",
  /** spec 7.2 (verbatim, Header lost): the admin hint of the identity-header states. */
  identity_header_hint:
    'X-AUSERNAME not received, possibly stripped by a reverse proxy in front of Jira; ask the Jira administrator',
  /** spec 7.2 (verbatim, L42): the hint when the OS proxy setting is a PAC script. */
  pac_hint:
    "your system uses a proxy auto-config script, which atlas-duck does not evaluate: set this instance's proxy (host:port or direct) in Settings",
  /** plan text (PD-181, §8.7): what the windows say after a restore answered `committed_incomplete`. */
  committed_incomplete: 'Restore will be completed at the next start',
  loading: 'Loading the settings',
  load_failed: 'Could not load the settings',
  retry: 'Try again',
  /** spec 7.1 (verbatim up to the alias). */
  url_change: 'config.toml requests a URL change for',
  url_change_requested: 'Requested URL:',
  url_change_accept: 'Accept the URL change',
  /** Plan text (T25): the label before Rust's §7.7 banner text (PD-76), which follows it verbatim. */
  read_only_prefix: 'Settings are read-only:',
  instances: 'Instances',
  no_instances: 'No instances are configured',
  col_alias: 'Alias',
  col_product: 'Product',
  col_origin: 'Origin',
  col_state: 'State',
  col_executes_as: 'Executes as',
  col_expiry: 'Token expiry',
  col_proxy: 'Proxy',
  col_actions: 'Actions',
  product: { jira: 'Jira', confluence: 'Confluence' },
  no_origin: '(not confirmed)',
  none: '(none)',
  proxy_os: 'OS setting or none',
  states: {
    ok: 'ok',
    needs_token: 'needs token',
    identity_header_missing: 'identity header missing',
    identity_header_mismatch: 'identity header mismatch',
    insecure_scheme: 'insecure scheme (http)',
    instance_unconfirmed: 'unconfirmed',
  },
  confirm_hint: 'Confirm this instance: Rust shows its alias and origin in a native dialog.',
  confirm: 'Confirm instance',
  retest: 'Re-test stored token',
  replace_token: 'Replace token',
  add_token: 'Add token',
  retest_connected: 'Connected as',
  retest_failed: 'The re-test failed:',
  retest_classes: {
    http_401: 'the server refused the token',
    other_user: 'the token now belongs to another user',
    network: 'the server could not be reached',
    tls: 'the TLS certificate was not accepted',
    proxy: 'the proxy refused or could not be reached',
    unavailable: 'the server did not answer with an identity',
    identity_header_missing: 'the identity header was not received: see the note on this instance',
    identity_header_mismatch: 'the identity header did not match: see the note on this instance',
    version_below_floor: 'the server version is below the supported minimum',
    not_known_user: 'the token belongs to a user that atlas-duck does not know',
  },
  /** An unrecognized class is never echoed: the wire name is not shown. */
  retest_class_unknown: 'the server answered in a way atlas-duck does not recognize',
  retest_warnings: 'Warnings:',
  change_url: 'Change URL',
  change_url_label: 'New base URL',
  change_url_apply: 'Apply URL change',
  proxy_label: 'Proxy (host:port, direct, or empty for the OS setting)',
  proxy_apply: 'Apply proxy',
  expires_on: 'Expires',
  /** plan text (PD-84): "expires in N days" / "expires today" / "expired on <date>". */
  expiry_in: (n: number) => `Token expires in ${n} ${n === 1 ? 'day' : 'days'}`,
  expiry_today: 'Token expires today',
  expiry_past: (date: string) => `Token expired on ${date}`,
  expiry_soon: 'Token expiry is close',
  expiry_note: 'A warning only: the server decides whether a token works.',
  add_heading: 'Add an instance',
  add_alias: 'Alias',
  add_product: 'Product',
  add_url: 'Base URL (https, with the context path)',
  add_proxy: 'Proxy (host:port, direct, or empty for the OS setting)',
  add_ca: 'Use a custom CA certificate (Rust asks for the file)',
  add_default: 'Default instance for its product',
  add_submit: 'Add instance',
  add_done: 'The instance was added.',
  /** dd confirms the origin in its own native dialog, so the next step is the token. */
  add_done_token: 'The instance was added. Add its token next.',
  limits: 'Limits',
  limit_labels: {
    jira_comments_cap: 'Jira comments cap',
    candidate_cache_mb: 'Candidate cache (MB)',
    max_pending_bytes_mb: 'Pending bytes cap (MB, empty = off)',
    expiry_hours: 'Request expiry (hours)',
    ...SCRIPT_LIMIT_LABELS,
  },
  script_limits: 'Script limits',
  script_limit_labels: SCRIPT_LIMIT_LABELS,
  /** The spec default (§9.4) beside a script limit's input. */
  script_default: (n: number) => `default ${n}`,
  script_limits_note: 'A change applies to scripts submitted afterwards. Raising a limit is confirmed in a native dialog.',
  /** plan text (PD-76). */
  restart_marker: 'applies after restart',
  restart_waiting: 'a changed value is waiting for the next start',
  retention: 'Retention and legal hold',
  retention_days: 'Audit retention (days)',
  legal_hold: 'Legal hold (pruning stops)',
  attention: 'Attention mode',
  attention_modes: {
    show_without_activating: 'Show the window without taking focus',
    badge_only: 'Badge only',
    show_and_focus: 'Show the window and take focus',
  },
  presentation_note: 'Presentation mode is a toggle in the tray menu and is not saved here.',
  apply: 'Apply',
  applied: 'Applied',
  not_a_number: 'Enter a whole number',
  prune: 'Pruning',
  prune_button: 'Prune backlog now',
  prune_failed_last: 'The last prune failed.',
  pruned: (n: number, cutoff: string) => `Pruned ${n} record(s) older than ${cutoff}`,
  pruned_clamped: 'The cutoff was limited by the retention minimum.',
  prune_skipped: 'Pruning was skipped',
  prune_reasons: {
    legal_hold: 'legal hold is on',
    not_corroborated: 'no server date has confirmed the current date yet',
    head_epoch_null: 'the newest audit record has no date yet',
    already_ran_this_epoch: 'pruning already ran for the current date',
    clock_before_head: 'the system clock is before the newest audit record',
    clock_before_last_prune: 'the system clock is before the last prune',
    nothing_to_advance: 'there is nothing older to prune',
    config_not_reconciled: 'config.toml has not been read yet in this run',
    clock_behind: 'the system clock is behind the server date',
  },
  confinement: 'Script confinement',
  confinement_met: 'met: scripts may run',
  confinement_not_met: 'not met: scripts are off',
  /** The unmet floor while the user's opt-in lets scripts run anyway: never "scripts are off". */
  confinement_not_met_degraded: 'not met: scripts run only because degraded confinement is allowed',
  confinement_pending: 'the startup probe has not finished',
  confinement_mode: 'Mode',
  confinement_failed: 'Failed probes',
  confinement_layers: 'Extra layers',
  /** M8 T23 (Δ8): whether scripts run, by `confinement.scripts`. */
  scripts_states: {
    enabled: 'Scripts are enabled',
    disabled: 'Scripts are disabled',
    degraded: 'Scripts are enabled with degraded confinement',
  },
  degraded_toggle: 'Allow scripts with degraded confinement',
  /** plan text (PD-141): the persistent caution while scripts run degraded. */
  scripts_degraded_caution: 'scripts run with degraded confinement',
  degraded_inactive: 'Allowed, but not in use: the confinement floor is met.',
  degraded_note: 'Turning this on is confirmed in a native dialog. A compromised script worker could then act as your user.',
  layer_on: 'on',
  layer_off: 'off',
  cli: 'Command line',
  cli_installed: 'The atlas-duck command is on your PATH.',
  cli_not_installed: 'The atlas-duck command is not on your PATH.',
  /**
   * Installed, but the folder is not on the PATH this app runs with (a GUI-launched macOS app has
   * a minimal one): the text does not claim what the terminals have.
   */
  cli_installed_dir_not_on_path:
    'The atlas-duck command is installed, but its folder is not on the PATH this app was started with. A terminal you open may still find it; if it does not, add that folder to the PATH of your shell.',
  /** Not installed (or not recorded), yet the folder is on the PATH already: the user's own entry. */
  cli_not_installed_dir_on_path:
    'The folder for the atlas-duck command is already on your PATH, but the install is not complete yet. Use the button to finish it.',
  cli_install: 'Install CLI to PATH',
  cli_uninstall: 'Remove CLI from PATH',
  /** What `cli_install` / `cli_uninstall` did (spec 12.3), by the answer's fixed word. */
  cli_outcomes: {
    installed:
      'Installed. Open a new terminal, and restart your MCP clients, so they find the atlas-duck command.',
    installed_local_bin:
      'Installed to ~/.local/bin, which might not be on the PATH of the terminals you open. If a new terminal does not find the atlas-duck command, add ~/.local/bin to the PATH of your shell (on Ubuntu, log out and in again), and restart your MCP clients afterwards.',
    installed_local_bin_on_path:
      'Installed to ~/.local/bin, which is on the PATH this app was started with. Open a new terminal, and restart your MCP clients, so they find the atlas-duck command.',
    replaced_stale_entry:
      'Installed. The PATH entry of an earlier atlas-duck folder that no longer exists was removed. Open a new terminal, and restart your MCP clients, so they find the atlas-duck command.',
    already_installed: 'The atlas-duck command was already installed.',
    removed: 'Removed. New terminals no longer find the atlas-duck command.',
    already_on_path:
      'The atlas-duck command comes with the package and is already on your PATH: there is nothing to install or remove.',
  },
  /** Why the install or its removal failed, by core-of-the-app error kind (`cli_install` errors). */
  cli_errors: {
    no_stable_path:
      'atlas-duck cannot tell which file to put on your PATH: start it from the installed app (or the AppImage file itself) and try again',
    unsafe_path:
      'The install location has a character that cannot be put on the PATH safely (for example a semicolon or a quote): move the app to another folder',
    occupied:
      'A file or link named atlas-duck is already in the way and was left alone: remove it and try again',
    unsupported: 'Installing to the PATH is not supported on this system',
    registry: 'Your user PATH could not be read or changed',
    path_too_long: 'Your user PATH is too long to add the atlas-duck folder: shorten it and try again',
    io: 'The command file could not be written or removed',
    cli_toml: 'The file that records where the app is could not be written',
    newer_version:
      'The command file was installed by a newer atlas-duck and was left alone: use that version, or remove the file and try again',
    other: 'The command line could not be installed or removed',
  },
  removal: 'Prepare for removal',
  removal_intro:
    'Before you uninstall atlas-duck: make a backup if you want one, delete the stored tokens, revoke each token on its server, and remove the command line and the login item. The audit log, its keys and its anchors are kept, so the log stays verifiable until its retention period has passed.',
  /**
   * spec 12.5 step 1 with the retention setting: the fallback while the newest record's remaining
   * days are not known (`retention_left_days` is `null` without a legal hold: the head is unreadable).
   */
  removal_retention: (days: number, hold: boolean) =>
    `The newest audit record is kept ${hold ? 'until the legal hold is lifted, then for' : 'for'} at least ${days} more ${days === 1 ? 'day' : 'days'}.`,
  /** spec 12.5 step 1 (M10 T16, PD-176): the newest record's remaining retention in days. */
  removal_retention_left: (days: number) =>
    `The newest audit record is kept for at least ${days} more ${days === 1 ? 'day' : 'days'}.`,
  removal_retention_hold: 'The newest audit record is kept indefinitely: a legal hold is on.',
  /** spec 12.5 step 1: the compliance export offered next to the backup (PD-176). */
  removal_export: 'Export the audit log…',
  removal_export_note:
    'Exports the whole audit log with its decrypted payloads into a new folder. atlas-duck shows a warning and asks for the folder in its own dialogs.',
  removal_export_running: 'An export is running',
  removal_export_starting: 'Starting the export',
  removal_export_cancel: 'Cancel export',
  removal_export_cancel_requested: "Cancel requested. The export's own result follows.",
  removal_export_cancel_none: 'No export was running.',
  /** PD-176 (L130): answers recorded in the log are final and a resumed procedure ends only with Finish. */
  removal_recorded:
    'Your answers are recorded in the audit log and are final. If atlas-duck was restarted meanwhile, this procedure continues here. It ends only with "Finish removal".',
  removal_backup: 'Create a full backup',
  removal_backup_note: 'A backup never contains a token. You choose the folder in the next dialog.',
  removal_backup_saved: 'The backup was saved.',
  removal_backup_cancelled: 'No backup was made.',
  removal_backup_made: 'A backup was made in this procedure.',
  removal_begin: 'Delete the stored tokens',
  removal_retry: 'Delete the remaining tokens',
  /** spec 12.5 step 2 (verbatim). */
  removal_revoke_step: 'Revoke this token in Jira/Confluence (Profile → Personal Access Tokens)',
  removal_checklist: 'Revoke the tokens',
  removal_alias: 'Instance',
  removal_identity: 'Token identity',
  removal_identity_unknown: 'not known (no token identity is on record for this instance)',
  removal_not_deleted: 'The token is still stored: it could not be deleted.',
  /** A token is stored again for the instance (no delete failed): it has to be deleted again. */
  removal_token_back: 'A token is stored again for this instance: delete it again.',
  removal_done: 'I revoked it',
  removal_skip: 'Skip',
  removal_choice_done: 'Marked as revoked.',
  removal_choice_skipped: 'Skipped: the token stays valid on the server until it is revoked there.',
  removal_choice_pending: 'Not answered yet.',
  removal_undo: 'Answer again',
  removal_finish: 'Finish removal',
  removal_finish_hint:
    'Finishing needs every instance to be ticked or skipped. It removes the login item and the command line (the PATH entry, link or wrapper, launcher and cli.toml), and keeps the audit log, its keys and its anchors.',
  removal_cli: {
    removed: 'The command line was removed.',
    already_on_path: 'The command line comes with the package: remove the package to remove it.',
    not_found: 'No command line of atlas-duck was found.',
    not_removed: 'The command line was not removed.',
  },
  /** Why the command line step could not look at everything, by error kind (`cli_reason`). */
  removal_cli_reasons: {
    no_stable_path:
      'atlas-duck cannot tell where it is installed from this location, so the command line may still be on your PATH',
    unsafe_path:
      'The install location has a character that cannot be handled safely (for example a semicolon or a quote), so the command line may still be on your PATH',
    unsupported: 'Removing the command line is not supported on this system',
    io: 'The files of this computer could not be read',
    registry: 'Your user PATH could not be read or changed',
    cli_toml: 'The file that records where the app is could not be removed',
    newer_version:
      'The command file was installed by a newer atlas-duck and was left alone: use that version to remove it, or remove the file yourself',
    other: 'The command line could not be removed',
  },
  /** Shown only when every step succeeded. */
  removal_autostart: {
    removed: 'atlas-duck no longer starts at login.',
    was_off: 'atlas-duck did not start at login.',
  },
  removal_complete:
    'Done. You can uninstall atlas-duck now. The audit log, its keys and its anchors stay on this computer; the documentation lists where, for deletion after the retention period.',
  /** Shown when a step could not be completed: never "Done". */
  removal_incomplete:
    'Not done: the command line may still be installed. Remove the atlas-duck command and the cli.toml file by hand, or start atlas-duck from where it is installed and run this procedure again. The tokens are deleted and your answers are recorded; the audit log, its keys and its anchors stay on this computer.',
  /** Why a removal step was refused, by error kind (`removal` errors). */
  removal_errors: {
    no_procedure: 'Delete the stored tokens first',
    unticked: 'Tick or skip every instance first',
    token_stored: 'A token is stored again for an instance: delete it again, then finish',
    autostart: 'The login item could not be read or removed',
    recorded: 'The answers are already recorded: finish the removal',
    running: 'Another removal step or a backup is running: wait for it to end, then try again',
  },
  working: 'Working',
  /** Fixed answers for a refused or failed command, by error kind. */
  errors: {
    busy: 'The credential window is open, or another task is running (an export, a backup, a restore or a removal step): close the window or wait, then try again',
    not_found: 'That instance no longer exists',
    not_ready: 'The app is still starting: try again in a moment',
    internal: 'The command failed',
    refused: 'The command was refused',
    cancelled: 'Cancelled: nothing was changed',
    backup: 'The backup failed. If an unfinished backup folder is left in the folder you chose, delete it.',
    /**
     * Plan text (T25) for a refused change. The §7.7 banner ("config written by vX; settings
     * read-only until you upgrade", PD-76) is Rust's text, shown by the page from `config_read_only`.
     */
    config_read_only: 'config.toml was written by a newer version: settings are read-only',
    no_config_file: 'There is no config.toml to change',
    conflict: 'config.toml changed meanwhile: reload and try again',
    config_write_failed: 'config.toml could not be written',
    /** The neutral text of core's `audit` kind (a record or a file write failed); never a duplicate alias, a second default or a CA file (own kinds below). */
    audit: 'The change was refused',
    /** Plan text (M10 T36, L217): `AdminError::DuplicateAlias`. */
    duplicate_alias: 'Another instance already uses that alias: choose another alias',
    /** Plan text (M10 T36, L217): `AdminError::SecondDefault`; Rust also sends the product, the page does not need it. */
    second_default: 'That product already has a default instance: it can have only one',
    /** Plan text (M10 T36, L217): `AdminError::UnusableCaBundle`; the closed `reason` is `no_certificate`. */
    unusable_ca_bundle: 'That file holds no usable CA certificate: choose a PEM file with the certificate',
    invalid_url: 'That is not a valid URL',
    keychain: 'The token store is not available, or it holds no token for this instance',
    shutting_down: 'The app is shutting down',
    unconfirmed: 'Confirm the instance first',
    connection_failed: 'The connection test failed',
    other: 'The change was refused',
  },
  invalid_field: (what: string) => `Check the value of ${what}`,
  /** The names of an argument or a setting Rust reported that has no label; the wire name is never shown. */
  invalid_field_unknown: 'a field',
  invalid_setting_unknown: 'a setting',
  /** Labels for the argument names Rust reports; any other name is not shown. */
  invalid_arguments: {
    alias: 'the alias',
    product: 'the product',
    base_url: 'the base URL',
    proxy: 'the proxy',
    use_custom_ca: 'the CA file: choose another file',
  },
  /** M10 T21: Settings' "Recovery and backup" and anchor-directory sections. */
  recovery: {
    recovery: 'Recovery and backup',
    /** L27 (plan text). */
    backup_tokens: 'Backups never contain stored tokens; after a restore every instance needs its token again.',
    backup_retention: 'Backups and exports are outside retention and crypto-shredding: keeping and deleting them is up to you.',
    /** §8.13 (plan text): there is no automatic pre-upgrade snapshot. */
    upgrade_backup: 'Make a full backup before every upgrade.',
    backup_start: 'Back up now…',
    backup_running: 'A backup is running',
    backup_saved: 'The backup was saved.',
    backup_not_saved: 'No backup was made.',
    backup_cancelled: 'Cancelled: no backup was made.',
    restore_note:
      'Restoring replaces this audit log with the log of a backup. atlas-duck asks you to confirm in its own dialogs and to enter the recovery passphrase of the backup.',
    restore_start: 'Restore backup…',
    restore_running: 'A restore is running',
    restore_starting: 'Starting the restore',
    /** PD-181 (plan text): shown from the `started` event of the restore job. */
    restore_wait: 'Requests wait while the restore runs',
    restore_cancel: 'Cancel restore',
    restore_cancel_requested: 'Cancel requested.',
    restore_cancel_none: 'No restore is running.',
    restore_cancel_too_late: 'The restore is already writing and cannot be cancelled.',
    restore_done: 'The restore is complete.',
    restore_records_lost: (n: number) =>
      n === 0
        ? 'No records were lost.'
        : `${n} ${n === 1 ? 'record' : 'records'} written after the backup ${n === 1 ? 'is' : 'are'} no longer in the log.`,
    restore_tokens: (n: number) =>
      `Stored tokens are never restored: ${n === 0 ? 'no token was deleted' : `${n} stored ${n === 1 ? 'token was' : 'tokens were'} deleted`}, and every instance needs its token again.`,
    restore_follow_up_failed:
      'The restore is complete, but its follow-up step failed. Quit atlas-duck and start it again to finish it.',
    restore_restart: 'Quit atlas-duck and start it again. Until then new requests cannot be recorded.',
    restore_passphrase_offer:
      "The backup's recovery passphrase is now the recovery passphrase of this log. You can change it now with \"Change recovery passphrase…\".",
    restore_errors: {
      wrong_passphrase: 'That recovery passphrase does not open the backup. Nothing was changed.',
      not_a_backup: 'That folder is not a backup of atlas-duck. Nothing was changed.',
      newer: 'The backup was written by a newer atlas-duck: install that version or newer. Nothing was changed.',
      broken: 'The backup does not verify. Nothing was changed.',
      anchor_dir_mismatch: 'The backup does not match the anchor directory. Nothing was changed.',
      keychain: 'The keychain could not be used. Nothing was changed.',
      failed: 'The restore failed. Nothing was changed.',
    },
    passphrase_change: 'Change recovery passphrase…',
    passphrase_note:
      'The recovery passphrase unlocks the audit log after a keychain loss, from a backup or on a new machine. Changing it opens the credential window.',
    passphrase_opened: 'The credential window is open: enter the new passphrase there.',
  
    reanchor_heading: 'Anchors',
    anchors_missing: {
      head: 'The head anchor entry is missing from the keychain.',
      first_retained: 'The first-retained anchor entry is missing from the keychain.',
      both: 'The head anchor and the first-retained anchor entries are missing from the keychain.',
    },
    reanchor: 'Re-anchor…',
    reanchor_note:
      'Re-anchoring writes both the head anchor and the first-retained anchor again from the audit log as it is now. It is recorded as an integrity incident, which you acknowledge in the Audit window.',
    reanchor_done: 'Re-anchored. An integrity incident was recorded: acknowledge it in the Audit window.',
    reanchor_errors: {
      nothing_missing: 'No anchor entry is missing: nothing was changed.',
      held: 'The anchors are held while another step runs: try again later.',
      does_not_verify: 'The log does not verify, so nothing was re-anchored. An integrity incident was recorded: see Audit.',
      restored: 'A restore changed the anchors meanwhile: nothing was changed.',
      keychain: 'The keychain could not be written. An integrity incident was recorded: see Audit.',
      failed: 'Re-anchoring failed. Nothing was changed.',
    },
  
    orphans: 'Old installs',
    orphans_intro:
      'These installs left an archived audit log or keychain entries on this computer. Forgetting one deletes its keychain entries after native confirmations; the keys that open its archived log are deleted only if you confirm that too.',
    orphans_none: 'No old installs were found.',
    orphans_load_failed: 'Could not list the old installs.',
    orphan_install: 'Install',
    orphan_files: 'Archived logs',
    orphan_entries: 'Keychain entries',
    orphan_forget: 'Forget',
    orphan_forget_label: (installId: string) => `Forget the install ${installId}`,
    forgotten: (keysDeleted: boolean) =>
      keysDeleted
        ? 'Forgotten: its keychain entries and the keys of its archived log were deleted.'
        : 'Forgotten: its token entries were deleted; the keys of its archived log were kept.',
    forget_errors: {
      unreadable: 'The keychain entries of the old installs could not be read: nothing was deleted.',
      keychain: 'Some entries could not be deleted. Forget the install again to delete the rest.',
      failed: 'Forgetting the install failed.',
    },
    forget_deleted: 'Deleted',
    forget_not_deleted: 'Not deleted',
  
    anchor_dir: 'External anchor directory',
    anchor_dir_none: '(not set)',
    anchor_dir_note:
      'Copies of the log head are written to this folder. It protects against rolling history back only if you cannot rewrite the folder yourself, for example a share administered by someone else. atlas-duck asks for a folder and confirms every change in its own dialogs.',
    anchor_dir_set: 'Set anchor directory…',
    anchor_dir_change: 'Change anchor directory…',
    anchor_dir_remove: 'Remove anchor directory…',
    anchor_dir_changed: 'The anchor directory was changed.',
    anchor_dir_removed: 'The anchor directory was removed.',
    anchor_dir_pending: (n: number) =>
      `${n} ${n === 1 ? 'line waits' : 'lines wait'} to be written to the anchor directory.`,
    anchor_dir_errors: {
      not_writable: 'This folder cannot be written',
      writer_busy: 'The audit log is busy: try again in a moment.',
      unchanged: 'That is the anchor directory already in use: nothing was changed.',
      not_set: 'No anchor directory is set: nothing was changed.',
      failed: 'That folder cannot be used as an anchor directory: nothing was changed.',
    },
  },
} as const;
