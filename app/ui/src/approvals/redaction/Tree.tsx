import { Windowed } from '../../shared/list/Windowed';
import { REDACTION_TEXT } from '../../shared/strings';
import { AgentText } from '../../shared/text/AgentText';
import { Badge } from '../../shared/text/Badge';
import { unusual } from '../../shared/text/unusual';
import { members, scalarText, stringOf, type Candidate, type Span } from './json';
import { IDENT_KEYS, selectorSafe, type Ident, type Loc, type Step } from './paths';

/** One value of the candidate as the tree shows it. `id` (its offset in the text) is unique. */
export interface TreeNode {
  id: number;
  loc: Loc;
  span: Span;
  depth: number;
}

/** A row's text is cut here (code points); the selected-node pane shows more. */
export const ROW_TEXT_MAX = 200;
export const TREE_ROW_PX = 28;

export const cut = (s: string, max: number): string => {
  const points = Array.from(s);
  return points.length > max ? `${points.slice(0, max).join('')}…` : s;
};

/**
 * The identity of each element of an array (paths.ts `Ident`): the first of `IDENT_KEYS` whose
 * value is a selector-safe string that no other element spells the same way (Rust's `[k=v]` also
 * matches a number or boolean spelled `v`, so those count against uniqueness).
 */
function identities(text: string, elements: readonly Span[]): (Ident | null)[] {
  const fieldsOf = elements.map((e) => {
    const out = new Map<string, { spelled: string; string: boolean }>();
    if (e.kind !== 'object') return out;
    for (const m of members(text, e)) {
      if (typeof m.key !== 'string' || !(IDENT_KEYS as readonly string[]).includes(m.key)) continue;
      if (m.span.kind === 'string') out.set(m.key, { spelled: stringOf(text, m.span), string: true });
      else if (m.span.kind === 'number' || m.span.kind === 'literal') {
        out.set(m.key, { spelled: scalarText(text, m.span), string: false });
      }
    }
    return out;
  });
  const counts = new Map<string, Map<string, number>>();
  for (const f of fieldsOf) {
    for (const [k, v] of f) {
      const byValue = counts.get(k) ?? new Map<string, number>();
      byValue.set(v.spelled, (byValue.get(v.spelled) ?? 0) + 1);
      counts.set(k, byValue);
    }
  }
  return fieldsOf.map((f) => {
    for (const key of IDENT_KEYS) {
      const v = f.get(key);
      if (v !== undefined && v.string && selectorSafe(v.spelled) && counts.get(key)?.get(v.spelled) === 1) {
        return { key, value: v.spelled };
      }
    }
    return null;
  });
}

/** The candidate read lazily: a container's members are read when it is first expanded. */
export class TreeModel {
  readonly root: TreeNode;
  private readonly cache = new Map<number, TreeNode[]>();

  constructor(readonly candidate: Candidate) {
    this.root = { id: candidate.root.start, loc: [], span: candidate.root, depth: 0 };
  }

  get text(): string {
    return this.candidate.text;
  }

  children(node: TreeNode): TreeNode[] {
    const known = this.cache.get(node.id);
    if (known !== undefined) return known;
    const list = members(this.text, node.span);
    const idents = node.span.kind === 'array' ? identities(this.text, list.map((m) => m.span)) : [];
    const out = list.map((m, i): TreeNode => {
      const step: Step =
        typeof m.key === 'string' ? { key: m.key } : { index: m.key, ident: idents[i] ?? null };
      return { id: m.span.start, loc: [...node.loc, step], span: m.span, depth: node.depth + 1 };
    });
    this.cache.set(node.id, out);
    return out;
  }

  /**
   * The node a plain `name[3]` path names (the form Rust reports locations in), or null where the
   * path is not in the tree or cannot be told apart (a key with `.`, `[` or `]`).
   */
  find(path: string): TreeNode | null {
    const step = /\.?([^.[\]]+)|\[(\d+)\]/y;
    let node: TreeNode = this.root;
    for (let at = 0; at < path.length; ) {
      step.lastIndex = at;
      const m = step.exec(path);
      if (m === null) return null;
      at = step.lastIndex;
      const next: TreeNode | undefined = this.children(node).find((c) => {
        const last = c.loc[c.loc.length - 1];
        if (last === undefined) return false;
        return m[1] !== undefined ? 'key' in last && last.key === m[1] : 'index' in last && last.index === Number(m[2]);
      });
      if (next === undefined) return null;
      node = next;
    }
    return node;
  }

  /** Whether `node`'s members were read (its count is known). */
  read(node: TreeNode): boolean {
    return this.cache.has(node.id);
  }

  /** The visible rows: the root and the members of every expanded container, in order. */
  rows(expanded: ReadonlySet<number>): TreeNode[] {
    const out: TreeNode[] = [];
    const visit = (n: TreeNode) => {
      out.push(n);
      if (expanded.has(n.id)) for (const c of this.children(n)) visit(c);
    };
    visit(this.root);
    return out;
  }
}

const isContainer = (s: Span): boolean => s.kind === 'object' || s.kind === 'array';

function Label({ node }: { node: TreeNode }) {
  const last = node.loc[node.loc.length - 1];
  if (last === undefined) return <span className="tree-key">{REDACTION_TEXT.root}</span>;
  if ('index' in last) return <span className="tree-key">{`[${last.index}]`}</span>;
  return (
    <span className="tree-key">
      <AgentText value={last.key} unusual={unusual(last.key)} />
    </span>
  );
}

function Summary({ model, node, open }: { model: TreeModel; node: TreeNode; open: boolean }) {
  const { span } = node;
  if (span.kind === 'string') {
    const value = stringOf(model.text, span);
    return <AgentText value={cut(value, ROW_TEXT_MAX)} unusual={unusual(value)} />;
  }
  if (span.kind === 'number' || span.kind === 'literal') {
    return <span className="tree-scalar">{scalarText(model.text, span)}</span>;
  }
  const [l, r] = span.kind === 'object' ? ['{', '}'] : ['[', ']'];
  const n = open || model.read(node) ? String(model.children(node).length) : '…';
  return <span className="tree-count">{`${l}${n}${r}`}</span>;
}

interface TreeProps {
  model: TreeModel;
  expanded: ReadonlySet<number>;
  onToggle: (node: TreeNode) => void;
  selectedId: number | null;
  onSelect: (node: TreeNode) => void;
  /** Text marks of a row (a link field, dropped in the unsent round). */
  marks: (node: TreeNode) => { link: boolean; dropped: boolean };
}

/**
 * The candidate as a windowed tree of text nodes (spec 6.1, PD-67): only the visible slice is in
 * the DOM, so a 16 MiB candidate with every array open costs a screenful. Keys and strings are
 * agent or upstream text: `AgentText` only.
 */
export function Tree({ model, expanded, onToggle, selectedId, onSelect, marks }: TreeProps) {
  const rows = model.rows(expanded);
  return (
    <Windowed
      rows={rows}
      rowHeight={TREE_ROW_PX}
      height={360}
      label={REDACTION_TEXT.tree_label}
      rowKey={(n) => n.id}
      render={(node) => {
        const open = expanded.has(node.id);
        const m = marks(node);
        return (
          <div className="tree-row" style={{ paddingLeft: `${node.depth}rem` }}>
            {isContainer(node.span) ? (
              <button
                type="button"
                className="tree-toggle"
                aria-expanded={open}
                aria-label={open ? REDACTION_TEXT.collapse : REDACTION_TEXT.expand}
                onClick={() => onToggle(node)}
              >
                {open ? '▾' : '▸'}
              </button>
            ) : (
              <span className="tree-leaf" aria-hidden="true">
                ·
              </span>
            )}
            <button
              type="button"
              className="tree-select"
              aria-pressed={selectedId === node.id}
              onClick={() => onSelect(node)}
            >
              <Label node={node} /> <Summary model={model} node={node} open={open} />
            </button>
            {m.link ? <Badge label={REDACTION_TEXT.link_field} /> : null}
            {m.dropped ? <Badge label={REDACTION_TEXT.dropped} tone="caution" /> : null}
          </div>
        );
      }}
    />
  );
}
