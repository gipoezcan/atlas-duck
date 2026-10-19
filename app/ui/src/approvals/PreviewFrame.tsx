import { DETAIL_TEXT } from '../shared/strings';

interface PreviewFrameProps {
  /** The document Rust built and sanitized (spec 6.4); it carries its own CSP `<meta>`. */
  srcdoc: string;
  /** The frame's accessible name; the preview's by default (the Audit window names its record). */
  title?: string;
}

/**
 * The only place preview HTML reaches the DOM (spec 6.4): an iframe with an empty `sandbox` (no
 * scripts, no same-origin, no forms, no popups), no `src`, and nothing that loosens it. The
 * document's CSP lives in its own `<meta>` and in the window's inherited policy, so no `csp`,
 * `allow`, `referrerpolicy` or `credentialless` attribute is set here. The Audit window's decrypted
 * payload pages (`audit_payload`, M10 T20) are shown through this frame too.
 */
export function PreviewFrame({ srcdoc, title = DETAIL_TEXT.preview_title }: PreviewFrameProps) {
  return <iframe sandbox="" srcDoc={srcdoc} title={title} />;
}
