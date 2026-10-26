import { useState } from 'react';

import { instanceAdd } from '../shared/ipc/invoke';
import { SETTINGS_TEXT as T } from '../shared/strings';
import { Guard } from './Guard';
import { useAction } from './useAction';

interface InstanceFormProps {
  /** Called after Rust added the instance (its native confirmation was answered Ok). */
  onAdded: () => void;
  /** config.toml is read-only: the form is off. */
  readOnly: boolean;
  /**
   * The heading level: 2 in Settings, 3 where the form sits inside a panel that has its own h2 (the
   * setup wizard).
   */
  headingLevel?: 2 | 3;
  /**
   * What is said after an add that leaves the instance without a token. Settings: "Add its token
   * next" (it has the control); the setup window has none and names Settings instead.
   */
  addedNeedsToken?: string;
}

/**
 * The add-instance form (spec 7.1). Every value goes to Rust as typed: it normalizes the URL,
 * refuses `http://` (with the fixed hint) and draws the confirmation. A custom CA is never read
 * here: the checkbox only asks Rust to open its own file dialog (spec 10.3).
 */
export function InstanceForm({
  onAdded,
  readOnly,
  headingLevel = 2,
  addedNeedsToken = T.add_done_token,
}: InstanceFormProps) {
  const Heading = headingLevel === 3 ? 'h3' : 'h2';
  const [alias, setAlias] = useState('');
  const [product, setProduct] = useState<'jira' | 'confluence'>('jira');
  const [baseUrl, setBaseUrl] = useState('');
  const [proxy, setProxy] = useState('');
  const [ca, setCa] = useState(false);
  const [isDefault, setIsDefault] = useState(false);
  const [added, setAdded] = useState<string | null>(null);
  const action = useAction();

  const submit = () => {
    setAdded(null);
    void action
      .run(() =>
        instanceAdd({
          alias,
          product,
          base_url: baseUrl,
          proxy,
          use_custom_ca: ca,
          is_default: isDefault,
        }),
      )
      .then((v) => {
        if (v === undefined) return;
        // dd confirmed the origin in its own dialog: an instance without a token is next.
        setAdded(v.state === 'needs_token' ? addedNeedsToken : T.add_done);
        setAlias('');
        setBaseUrl('');
        setProxy('');
        setCa(false);
        setIsDefault(false);
        onAdded();
      });
  };

  return (
    <section aria-label={T.add_heading}>
      <Heading>{T.add_heading}</Heading>
      <Guard disabled={readOnly}>
      <label>
        {T.add_alias}
        <input type="text" value={alias} onChange={(e) => setAlias(e.target.value)} />
      </label>
      <label>
        {T.add_product}
        <select value={product} onChange={(e) => setProduct(e.target.value === 'confluence' ? 'confluence' : 'jira')}>
          <option value="jira">{T.product.jira}</option>
          <option value="confluence">{T.product.confluence}</option>
        </select>
      </label>
      <label>
        {T.add_url}
        <input type="text" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} />
      </label>
      <label>
        {T.add_proxy}
        <input type="text" value={proxy} onChange={(e) => setProxy(e.target.value)} />
      </label>
      <label>
        <input type="checkbox" checked={ca} onChange={(e) => setCa(e.target.checked)} />
        {T.add_ca}
      </label>
      <label>
        <input type="checkbox" checked={isDefault} onChange={(e) => setIsDefault(e.target.checked)} />
        {T.add_default}
      </label>
      <button type="button" className="primary" disabled={action.pending} onClick={submit}>
        {T.add_submit}
      </button>
      </Guard>
      {action.error === null ? null : <p role="alert">{action.error}</p>}
      {added === null ? null : <p role="status">{added}</p>}
    </section>
  );
}
