import { formatNumber } from '../format';
import type { Dict } from '../index';

export const admin: Dict['admin'] = {
  instances: {
    title: 'Instanzen',
    admins_only: 'Nur für Administratoren.',
    intro: 'Jeder Benutzer sieht diese Instanzen und gibt für jede sein eigenes Token ein.',
    load_failed: 'Die Instanzen konnten nicht geladen werden.',
    loading: 'Wird geladen…',
    none: 'Es ist keine Instanz eingerichtet.',
    add_title: 'Instanz hinzufügen',
    alias: 'Alias',
    product: 'Produkt',
    base_url: 'Basis-URL',
    proxy: 'Proxy (optional: direct, system oder eine Proxy-URL)',
    org_ca: 'CA-Bundle der Organisation verwenden',
    is_default: 'Standardinstanz für dieses Produkt',
    add: 'Instanz hinzufügen',
    added: (alias) => `Instanz ${alias} hinzugefügt.`,
    remove: 'Entfernen',
    remove_confirm: (alias) =>
      `Die Instanz ${alias} entfernen? Die Tokens aller Benutzer für diese Instanz werden gelöscht.`,
    removed: (alias) => `Instanz ${alias} entfernt.`,
    col_url: 'URL',
    col_proxy: 'Proxy',
    col_org_ca: 'Organisations-CA',
    col_default: 'Standard',
    col_actions: 'Aktionen',
    none_value: '—',
    yes: 'ja',
    no: 'nein',
    errors: {
      invalid:
        'Die Instanz ist nicht gültig: Prüfen Sie den Alias (Buchstaben, Ziffern, - und _), das Produkt, eine Basis-URL mit https:// und den Proxy. Außerdem darf ein Produkt nur eine Standardinstanz haben.',
      exists: 'Eine Instanz mit diesem Alias gibt es bereits.',
      unknown: 'Diese Instanz gibt es nicht mehr.',
      role: 'Nur für Administratoren.',
      failed: 'Die Änderung ist fehlgeschlagen. Versuchen Sie es erneut.',
    },
  },
  auditor: {
    title: 'Auditor',
    only: 'Nur für Auditoren.',
    intro:
      'Wählen Sie einen Benutzer, um seine Audit-Kette zu lesen. Jede Ansicht wird in Ihrer eigenen Audit-Kette festgehalten.',
    search: 'Nach Benutzername suchen',
    state: 'Status',
    state_all: 'Alle',
    state_active: 'Aktiv',
    state_deactivated: 'Deaktiviert',
    loading: 'Wird geladen…',
    load_failed: 'Die Benutzer konnten nicht geladen werden.',
    none: 'Kein Benutzer passt.',
    back: 'Zurück zu den Benutzern',
    users: 'Benutzer',
    recorded_view: 'Festgehaltene Ansicht',
    banner: (username) =>
      `Sie sehen die Audit-Kette von ${username}. Jede Ansicht wird in Ihrer eigenen Audit-Kette festgehalten.`,
  },
  export: {
    title: 'Export',
    intro:
      'Exportiert die Audit-Kette als tar-Archiv, das jeder offline mit atlas-duck verify-export prüfen kann.',
    range_all: 'Alle Datensätze',
    range_from: 'Ab Datum (UTC)',
    start: 'Export starten',
    starting: 'Wird gestartet…',
    running: (done, total) =>
      total > 0
        ? `Export läuft… ${formatNumber('de', done)} von ${formatNumber('de', total)} Datensätzen`
        : 'Export läuft…',
    done: 'Der Export ist bereit. Er lässt sich einmal herunterladen.',
    download: 'Herunterladen',
    manifest: 'SHA-256 des Manifests',
    anchor: 'Kopf-Anker',
    verify: 'Prüfen mit',
    copy: 'Kopieren',
    copy_label: (what) => `${what} kopieren`,
    copied: 'Kopiert.',
    copy_failed: 'Das Kopieren ist fehlgeschlagen; markieren Sie stattdessen den Text.',
    out_of_band:
      'Geben Sie dem Empfänger das SHA-256 des Manifests und den Kopf-Anker über einen anderen Kanal als das Archiv.',
    busy: 'Ein Export läuft bereits. Starten Sie erneut, wenn er beendet ist.',
    expired: 'Dieser Export ist nicht mehr verfügbar. Starten Sie einen neuen.',
    failed: 'Der Export ist fehlgeschlagen. Starten Sie einen neuen.',
    start_failed: 'Der Export konnte nicht gestartet werden. Versuchen Sie es erneut.',
    bad_date: 'Geben Sie ein Datum ein oder wählen Sie alle Datensätze.',
  },
};