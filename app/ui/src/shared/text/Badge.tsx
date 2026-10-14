interface BadgeProps {
  label: string;
  count?: number;
  /** Extra class for styling; the text and accessible name never depend on it. */
  tone?: 'caution' | 'neutral';
}

/** A text-labelled flag: the text is the signal and the accessible name, never colour alone. */
export function Badge({ label, count, tone = 'neutral' }: BadgeProps) {
  const text = count === undefined ? label : `${label} (${count})`;
  return (
    <span className={`badge badge-${tone}`} role="note" aria-label={text}>
      {text}
    </span>
  );
}