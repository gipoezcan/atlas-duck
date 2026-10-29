import type { Dict } from '../index';

export const running: Dict['running'] = {
  loading: 'Laufende Skripte werden geladen',
  load_failed: 'Die laufenden Skripte konnten nicht geladen werden',
  retry: 'Erneut versuchen',
  empty: 'Es laufen keine Skripte.',
  list_label: 'Laufende Skripte',
  col_request: 'Anfrage',
  col_agent: 'Agent',
  col_instances: 'Instanzen',
  col_started: 'Gestartet',
  col_elapsed: 'Dauer',
  col_calls: 'Host-Aufrufe',
  col_bytes: 'Abgerufene Bytes',
  col_actions: 'Aktionen',
  kill: 'Beenden',
  killing: 'Wird beendet…',
  kill_label: (requestId) => `Skript ${requestId} beenden`,
  kill_answer: {
    killed: 'Beenden angefordert',
    not_running: 'Dieses Skript läuft nicht mehr.',
    already_stopping: 'Dieses Skript wird bereits beendet.',
  },
  kill_failed: 'Das Skript konnte nicht beendet werden.',
  no_agent: 'kein Agent-Name',
  no_instances: 'noch keine',
  elapsed: {
    seconds: (s) => `${s} s`,
    minutes: (m, s) => `${m} min ${s} s`,
    hours: (h, m) => `${h} h ${m} min`,
  },
};
