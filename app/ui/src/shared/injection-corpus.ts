// The S-06 payload corpus (spec 13, Security Frontend row): every string a window shows may hold
// any of these. Used by src/approvals/injection.test.tsx; nothing in a bundle imports it.
//
// A payload that only works when it is parsed as markup, a URL, a style or a template names what
// it carries in `needs`; the test treats a payload that reaches the DOM as an element, an `on*`
// attribute or a `href`/`src` as a failure whatever its `needs` says. `__pwned` is the marker
// every script payload sets: the page never runs one, so `window.__pwned` stays undefined.

export interface Payload {
  readonly id: string;
  readonly value: string;
}

const P = 'window.__pwned=1';

const p = (id: string, value: string): Payload => ({ id, value });

const MARKUP: readonly Payload[] = [
  p('script_tag', `<script>${P}</script>`),
  p('script_src', '<script src="//evil.example/x.js"></script>'),
  p('script_upper', `<SCRIPT>${P}</SCRIPT>`),
  p('img_onerror', `<img src=x onerror="${P}">`),
  p('svg_onload', `<svg/onload=${P}>`),
  p('body_onload', `<body onload=${P}>`),
  p('iframe_srcdoc', `<iframe srcdoc="<script>parent.${P}</script>"></iframe>`),
  p('iframe_src', '<iframe src="https://evil.example/"></iframe>'),
  p('details_ontoggle', `<details open ontoggle=${P}>x</details>`),
  p('input_onfocus', `<input autofocus onfocus=${P}>`),
  p('a_href_js', `<a href="javascript:${P}">x</a>`),
  p('form_action', `<form action="https://evil.example/"><button formaction="javascript:${P}">x</button></form>`),
  p('object_data', '<object data="https://evil.example/x.swf"></object><embed src="https://evil.example/x">'),
  p('meta_refresh', '<meta http-equiv="refresh" content="0;url=https://evil.example/">'),
  p('base_href', '<base href="https://evil.example/">'),
  p('link_stylesheet', '<link rel="stylesheet" href="https://evil.example/x.css">'),
  p('style_import', '<style>@import url(//evil.example/x.css);</style>'),
  p('math_xlink', `<math><mtext><a xlink:href="javascript:${P}">x</a></mtext></math>`),
  p('video_poster', `<video poster="https://evil.example/x" onerror=${P}><source src=x></video>`),
  p('attr_breakout_dq', `" onmouseover="${P}" x="`),
  p('attr_breakout_sq', `' autofocus onfocus='${P}`),
  p('tag_breakout', `"><script>${P}</script>`),
  p('textarea_breakout', `</textarea><script>${P}</script>`),
  p('pre_breakout', `</pre><img src=x onerror=${P}>`),
  p('cdata_breakout', `]]><script>${P}</script>`),
  p('comment_breakout', `--><script>${P}</script>`),
  p('nested_broken', `<scr<script>ipt>${P}</scr</script>ipt>`),
  p('unclosed_tag', '<img src="x'),
];

const URLS: readonly Payload[] = [
  p('url_javascript', `javascript:${P}`),
  p('url_javascript_mixed', `JaVaScRiPt:${P}`),
  p('url_javascript_tab', `java\tscript:${P}`),
  p('url_data_html', `data:text/html,<script>${P}</script>`),
  p('url_data_b64', 'data:text/html;base64,PHNjcmlwdD53aW5kb3cuX19wd25lZD0xPC9zY3JpcHQ+'),
  p('url_vbscript', 'vbscript:msgbox(1)'),
  p('url_protocol_relative', '//evil.example/x'),
  p('url_https', 'https://evil.example/?x=<script>'),
  p('url_file', 'file:///C:/Windows/win.ini'),
  p('url_unc', '\\\\evil.example\\share\\x'),
  p('url_userinfo', 'https://jira.example@evil.example/'),
];

const INVISIBLE: readonly Payload[] = [
  p('bidi_rlo', '\u202Eexe.txt'),
  p('bidi_all', '\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069 x'),
  p('zero_width', 'a\u200B\u200C\u200D\u2060\uFEFFb'),
  p('tag_chars', '\u{E0041}\u{E0042}\u{E007F}'),
  p('control_c0', '\u0001\u0002\u0007\u0008\u001B[31mred\u001B[0m\u001F'),
  p('control_c1', '\u0080\u0085\u008D\u009B31m'),
  p('del', '\u007F'),
  p('line_separators', 'a\u2028b\u2029c\u0085d\r\ne\rf'),
  p('combining', `Z${'\u0301\u0316\u0489'.repeat(50)}`),
  p('lone_surrogate', 'a\uD800b\uDC00c'),
  p('noncharacters', '\uFFFE\uFFFF\uFDD0'),
  p('replacement', '\uFFFD\uFFFD'),
  p('nbsp_variants', '\u00A0\u1680\u2000\u2007\u202F\u205F\u3000'),
  p('homoglyph', 'p\u0430yp\u0430l.com \u0455cript'),
];

const ENTITIES: readonly Payload[] = [
  p('entity_named', `&lt;script&gt;${P}&lt;/script&gt;`),
  p('entity_hex', `&#x3C;script&#x3E;${P}&#x3C;/script&#x3E;`),
  p('entity_decimal', `&#60;img src=x onerror=${P}&#62;`),
  p('entity_double', '&amp;lt;script&amp;gt;'),
  p('entity_null', '&#0;&#x0;&NewLine;&Tab;'),
  p('entity_no_semicolon', '&ltscript&gt'),
];

const TEMPLATES: readonly Payload[] = [
  p('tpl_mustache', "{{constructor.constructor('window.__pwned=1')()}}"),
  p('tpl_dollar', `\${${P}}`),
  p('tpl_erb', `<%= ${P} %>`),
  p('tpl_ruby', `#{${P}}`),
  p('tpl_arith', '{{7*7}} ${7*7} #{7*7}'),
  p('tpl_printf', '%s%n%x%d {0} {} {name}'),
  p('tpl_shell', '$(touch pwned) `id` ; rm -rf / && x | y > z'),
  p('tpl_sql', "'; DROP TABLE audit; --"),
  p('tpl_path', '../../../etc/passwd C:\\Windows\\System32\\config\\SAM'),
  p('tpl_angular', '{{$on.constructor("window.__pwned=1")()}}'),
];

const MARKDOWN: readonly Payload[] = [
  p('md_link_js', `[click](javascript:${P})`),
  p('md_image_attr', `![x](x" onerror="${P})`),
  p('md_heading', '# heading\n## sub\n---\n===='),
  p('md_emphasis', '**bold** _it_ ~~strike~~ `code`'),
  p('md_reference', `[x][1]\n\n[1]: javascript:${P}`),
  p('md_autolink', `<javascript:${P}>`),
  p('md_table', '| a | b |\n|---|---|\n| <img src=x onerror=1> | y |'),
  p('md_code_fence', `\`\`\`html\n<script>${P}</script>\n\`\`\``),
  p('md_html_block', `<div onclick="${P}">x</div>`),
  p('bare_urls', 'www.evil.example evil.example/x user@evil.example https://evil.example'),
];

const CSS: readonly Payload[] = [
  p('css_style_close', `</style><style>*{display:none}</style>`),
  p('css_expression', `expression(${P})`),
  p('css_url_js', `url(javascript:${P})`),
  p('css_declaration', 'red;background:url(//evil.example/x);position:fixed;inset:0'),
  p('css_attr_breakout', '" style="background:url(//evil.example/x)" x="'),
  p('css_import', '@import "//evil.example/x.css";'),
  p('css_escape', '\\3c script\\3e'),
];

const LONG: readonly Payload[] = [
  p('long_a', 'A'.repeat(10_000)),
  p('long_no_break_markup', '<b>'.repeat(3_000)),
  p('long_unicode', '\u{1F986}'.repeat(4_000)),
  p('long_spaces', ' '.repeat(10_000)),
  p('long_newlines', 'x\n'.repeat(3_000)),
  p('long_quotes', '"\''.repeat(5_000)),
];

// Names a lookup table of the page might index with a wire string, and members every object has.
const PROTOTYPE: readonly Payload[] = [
  p('proto', '__proto__'),
  p('constructor', 'constructor'),
  p('prototype', 'prototype'),
  p('to_string', 'toString'),
  p('has_own', 'hasOwnProperty'),
  p('value_of', 'valueOf'),
  p('define_getter', '__defineGetter__'),
  p('proto_dotted', 'constructor.prototype.polluted'),
  p('proto_path', '__proto__.polluted'),
];

const NULLS: readonly Payload[] = [
  p('null_byte', 'a\u0000b'),
  p('null_only', '\u0000'),
  p('null_percent', 'a%00b'),
  p('null_script', `\u0000<script>${P}</script>`),
  p('empty', ''),
];

/**
 * The corpus by kind. Markup, URL, invisible-character, entity, template, Markdown and CSS payloads
 * do their harm whatever field they sit in, so a run may give a field all of a kind at once;
 * `EXACT` kinds only matter as the whole value (a name looked up in a table, a missing or odd
 * string) and `LONG` ones are heavy: those are run one payload at a time.
 */
export const KINDS = {
  markup: MARKUP,
  url: URLS,
  invisible: INVISIBLE,
  entity: ENTITIES,
  template: TEMPLATES,
  markdown: MARKDOWN,
  css: CSS,
  prototype: PROTOTYPE,
  null: NULLS,
  long: LONG,
} as const;

export type Kind = keyof typeof KINDS;

export const COMBINABLE: readonly Kind[] = ['markup', 'url', 'invisible', 'entity', 'template', 'markdown', 'css'];

export const CORPUS: readonly Payload[] = Object.values(KINDS).flat();

/** One value holding every payload of `kind`, for a run that gives each field all of them. */
export function combined(kind: Kind): string {
  return KINDS[kind].map((p) => p.value).join(' ');
}
/** Object keys a record may carry on the wire: own properties that shadow what every object has. */
export const PROTOTYPE_KEYS: readonly string[] = ['__proto__', 'constructor', 'prototype', 'toString'];
