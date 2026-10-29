import { Badge } from './Badge';
import { useText } from '../i18n/context';

interface AgentTextProps {
  value: string;
  /** The classifier flagged the text (spec 3.3). */
  unusual?: boolean;
}

/**
 * The only way agent-supplied text reaches the DOM (spec 5.6): a fixed-width "unverified" badge,
 * then the text quoted in a bidi-isolated element, then the "unusual characters" flag when set.
 * The value is a React text node, never markup.
 */
export function AgentText({ value, unusual = false }: AgentTextProps) {
  const t = useText();
  return (
    <span className="agent-text">
      <span className="badge-fixed">
        <Badge label={t.approvals.unverified} />
      </span>
      <bdi className="agent-text-value">{`\u201C${value}\u201D`}</bdi>
      {unusual ? <Badge label={t.approvals.unusual_characters} tone="caution" /> : null}
    </span>
  );
}