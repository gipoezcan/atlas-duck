/** plan text (PD-81, T30): the Running scripts window shell. */
export const running = {
  loading: 'Loading the running scripts',
  load_failed: 'Could not load the running scripts',
  retry: 'Try again',
  empty: 'No scripts are running.',
  list_label: 'Running scripts',
  col_request: 'Request',
  col_agent: 'Agent',
  col_instances: 'Instances',
  col_started: 'Started',
  col_elapsed: 'Elapsed',
  col_calls: 'Host calls',
  col_bytes: 'Bytes fetched',
  col_actions: 'Actions',
  kill: 'Kill',
  killing: 'Stopping\u2026',
  /** The accessible name of a row's kill button (the request id names the row). */
  kill_label: (requestId: string) => `Kill the script ${requestId}`,
  /** The three `running_kill` answers (PD-143), keyed by Rust's `answer` tag. */
  kill_answer: {
    killed: 'Kill requested',
    not_running: 'That script is no longer running.',
    already_stopping: 'That script is already stopping.',
  },
  kill_failed: 'Could not stop the script.',
  no_agent: 'no agent name',
  no_instances: 'none yet',
  /** Elapsed time from Rust's whole milliseconds (formatting only). */
  elapsed: {
    seconds: (s: number) => `${s} s`,
    minutes: (m: number, s: number) => `${m} min ${s} s`,
    hours: (h: number, m: number) => `${h} h ${m} min`,
  },
} as const;
