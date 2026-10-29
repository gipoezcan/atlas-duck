// node --test ci/check-user-guide.test.mjs  (node:test, no npm dependencies)
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";
import { checkUserGuide, errAnchor, loadInputs, main, parseServerPages } from "./check-user-guide.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");

// ---------- fixture ----------

const page = (id, anchors) => ({ id, title: id, file: `${id}.html`, anchors });

function manifest(set) {
  const errs = ["err-usage", "err-internal", ...(set === "server" ? ["err-auth-no-session"] : [])];
  return { pages: [page("index", ["intro"]), page("error-reference", ["errors-all", ...errs])] };
}

function pages(set, lang) {
  const other = lang === "en" ? "de" : "en";
  const link = (path) => `<a href="${path}">x</a>`;
  const [idx, err, sw] =
    set === "desktop"
      ? ["index.html", "error-reference.html#err-usage", `../${other}/index.html`]
      : [`/docs/${lang}/`, `/docs/${lang}/error-reference#err-usage`, `/docs/${other}/`];
  return {
    index: `<link rel="stylesheet" href="assets/help.css">${link(idx)}${link("#intro")}${link(err)}${link(sw)}${link("https://example.org/")}`,
    "error-reference": link(idx),
  };
}

function base() {
  const manifests = {};
  const html = {};
  for (const set of ["desktop", "server"]) {
    manifests[set] = { en: manifest(set), de: manifest(set) };
    html[set] = { en: pages(set, "en"), de: pages(set, "de") };
  }
  return {
    manifests,
    html,
    uiLinks: { desktop: { approvals: "index#intro" }, server: { "/": "index#intro" } },
    labels: ["approvals", "credential", "help"],
    serverPaths: ["/", "/oauth/consent"],
    codes: { envelope: ["usage", "internal"], decision: [], batch: [], cmd: [], server: ["auth/no_session", "internal"] },
    sources: [{ path: "docs/user-guide/en/index.md", text: "## Intro {#intro}\n\nText.\n" }],
  };
}

const run = (mutate, opts) => {
  const inp = base();
  mutate(inp);
  return checkUserGuide(inp, opts);
};
const has = (errors, text) => errors.some((e) => e.includes(text));

test("the baseline fixture has no findings", () => {
  assert.deepEqual(checkUserGuide(base()), []);
});

// ---------- parity (PD-321) ----------

test("missing_page_in_de_fails", () => {
  const e = run((i) => {
    i.manifests.server.de.pages = i.manifests.server.de.pages.filter((p) => p.id !== "index");
  });
  assert.ok(has(e, "server: page index exists in en but not in de"), e.join("\n"));
  const f = run((i) => {
    i.manifests.desktop.en.pages = i.manifests.desktop.en.pages.filter((p) => p.id !== "index");
  });
  assert.ok(has(f, "desktop: page index exists in de but not in en"), f.join("\n"));
});

test("anchor_set_differs_fails", () => {
  const e = run((i) => {
    i.manifests.desktop.de.pages[0].anchors = ["einleitung"];
  });
  assert.ok(has(e, "desktop/index: anchors differ between en and de (only en: intro; only de: einleitung)"), e.join("\n"));
});

// ---------- error reference ----------

test("errAnchor maps _ and / to -", () => {
  assert.equal(errAnchor("auth/invalid_credentials"), "err-auth-invalid-credentials");
  assert.equal(errAnchor("usage"), "err-usage");
});

test("error_code_without_entry_fails", () => {
  const e = run((i) => {
    i.codes.decision = ["not_decidable"];
  });
  assert.ok(has(e, "desktop/en: error code without an entry: err-not-decidable"), e.join("\n"));
  assert.ok(has(e, "server/de: error code without an entry: err-not-decidable"), e.join("\n"));
  // A server-only code needs an entry in the server set only.
  const f = run((i) => {
    i.codes.cmd = ["release_blocked"];
    for (const l of ["en", "de"]) i.manifests.server[l].pages[1].anchors.push("err-release-blocked");
  });
  assert.deepEqual(f, []);
  const g = run((i) => {
    i.codes.cmd = ["release_blocked"];
  });
  assert.ok(has(g, "server/en: error code without an entry: err-release-blocked"));
  assert.ok(!has(g, "desktop"), g.join("\n"));
});

test("a code in several sets needs one entry", () => {
  // `internal` is an envelope and a server code; err-internal serves both.
  assert.deepEqual(checkUserGuide(base()), []);
});

test("entry_without_error_code_fails", () => {
  const e = run((i) => {
    i.manifests.desktop.en.pages[1].anchors.push("err-made-up");
  });
  assert.ok(has(e, "desktop/en: entry without an error code: err-made-up"), e.join("\n"));
  // A server-only entry in the desktop set is an entry without a code there.
  const f = run((i) => {
    i.manifests.desktop.de.pages[1].anchors.push("err-auth-no-session");
  });
  assert.ok(has(f, "desktop/de: entry without an error code: err-auth-no-session"), f.join("\n"));
  // Group anchors (errors-...) are not entries.
  assert.deepEqual(checkUserGuide(base()), []);
});

// ---------- ui-links (PD-327) ----------

test("ui_link_target_missing_fails", () => {
  const e = run((i) => {
    i.uiLinks.desktop.approvals = "index#nope";
    i.uiLinks.server["/"] = "ghost#intro";
  });
  assert.ok(has(e, "ui-links desktop: approvals -> index#nope: no anchor nope"), e.join("\n"));
  assert.ok(has(e, "ui-links server: / -> ghost#intro: no page ghost in the server set"), e.join("\n"));
  const f = run((i) => {
    i.uiLinks.desktop.approvals = "index";
  });
  assert.ok(has(f, "is not page#anchor"), f.join("\n"));
  // A desktop target must exist in the desktop set.
  const g = run((i) => {
    for (const l of ["en", "de"]) i.manifests.desktop[l].pages = i.manifests.desktop[l].pages.filter((p) => p.id !== "index");
    i.uiLinks.desktop = {};
    i.labels = [];
  });
  assert.ok(!has(g, "ui-links"), g.join("\n"));
});

test("ui_page_without_link_fails", () => {
  const e = run((i) => {
    i.labels.push("settings");
    i.serverPaths.push("/audit");
  });
  assert.ok(has(e, "ui-links desktop: settings has no help link"), e.join("\n"));
  assert.ok(has(e, "ui-links server: /audit has no help link"), e.join("\n"));
  // help, credential and /oauth/consent need no entry; a key that is no page is an error.
  const f = run((i) => {
    i.uiLinks.server["/nowhere"] = "index#intro";
  });
  assert.ok(has(f, "ui-links server: /nowhere is not a server page"), f.join("\n"));
});

// M16 T7: per-section "?" links of the desktop windows (`desktop_sections`, key `<label>/<section>`).
test("ui_section_links_validated", () => {
  const ok = run((i) => {
    i.uiLinks.desktop_sections = { "approvals/queue": "index#intro" };
  });
  assert.deepEqual(ok, []);
  const bad = run((i) => {
    i.uiLinks.desktop_sections = {
      "approvals/queue": "index#nope",
      "approvals/other": "ghost#intro",
      "nowhere/section": "index#intro",
      approvals: "index#intro",
      "approvals/x": "index",
    };
  });
  assert.ok(has(bad, "ui-links desktop_sections: approvals/queue -> index#nope: no anchor nope"), bad.join("\n"));
  assert.ok(has(bad, "ui-links desktop_sections: approvals/other -> ghost#intro: no page ghost in the desktop set"), bad.join("\n"));
  assert.ok(has(bad, "ui-links desktop_sections: nowhere/section is not <window label>/<section>"), bad.join("\n"));
  assert.ok(has(bad, "ui-links desktop_sections: approvals is not <window label>/<section>"), bad.join("\n"));
  assert.ok(has(bad, "ui-links desktop_sections: approvals/x -> index is not page#anchor"), bad.join("\n"));
});

// ---------- links and placeholders ----------

test("broken_internal_link_fails", () => {
  const e = run((i) => {
    i.html.desktop.en.index += '<a href="ghost.html">x</a><a href="index.html#nope">y</a><a href="#nope">z</a>';
    i.html.server.de.index += '<a href="/docs/de/ghost">x</a><a href="/docs/fr/index">y</a><a href="/admin">z</a>';
  });
  assert.ok(has(e, "desktop/en/index: link ghost.html points at a missing page"), e.join("\n"));
  assert.ok(has(e, "desktop/en/index: link index.html#nope points at a missing anchor"), e.join("\n"));
  assert.ok(has(e, "desktop/en/index: link #nope points at a missing anchor"), e.join("\n"));
  assert.ok(has(e, "server/de/index: link /docs/de/ghost points at a missing page"), e.join("\n"));
  assert.ok(has(e, "server/de/index: link /docs/fr/index is not a guide link"), e.join("\n"));
  assert.ok(has(e, "server/de/index: link /admin is not a guide link"), e.join("\n"));
});

test("todo_placeholder_fails", () => {
  const todo = (i) => {
    i.sources.push({ path: "docs/user-guide/de/audit.md", text: "## A {#a}\n\nTODO\n" });
  };
  const e = run(todo);
  assert.deepEqual(e, ["docs/user-guide/de/audit.md:3: TODO placeholder"]);
  assert.deepEqual(run(todo, { allowTodo: true }), []);
});

// ---------- the real tree ----------

test("parseServerPages reads PAGES", () => {
  const pagesList = parseServerPages(readFileSync(join(REPO, "crates/server/src/static_files.rs"), "utf8"));
  assert.ok(pagesList.includes("/login") && pagesList.includes("/oauth/consent") && pagesList.includes("/"));
  assert.ok(pagesList.length >= 10);
});

test("the committed guide passes (TODO placeholders allowed until the content tasks land)", () => {
  // T12 removes --allow-todo from CI; flip `allowTodo` here with it.
  assert.deepEqual(checkUserGuide(loadInputs(REPO), { allowTodo: true }), []);
});

test("main exits 0 on the committed guide with --allow-todo", () => {
  const log = console.log;
  console.log = () => {};
  try {
    assert.equal(main(["--allow-todo"], REPO), 0);
  } finally {
    console.log = log;
  }
});

// ---------- help.js ----------

const helpJs = readFileSync(join(REPO, "docs/user-guide/assets/help.js"), "utf8");

test("help.js stays within 8 KB (PD-324)", () => {
  assert.ok(Buffer.byteLength(helpJs) <= 8192, `${Buffer.byteLength(helpJs)} bytes`);
});

test("help.js does not throw on a malformed URL hash and still wires the search", () => {
  const listeners = {};
  const node = () => ({ hidden: true, addEventListener: (t, f) => (listeners[t] = f), getAttribute: () => "", setAttribute() {}, contains: () => false });
  const input = node();
  const els = { ".search": node(), ".lang-switch": node(), "help-search": input, "help-results": node() };
  const context = {
    window: { ATLAS_HELP_INDEX: [], addEventListener() {} },
    document: {
      querySelector: (s) => els[s] ?? null,
      getElementById: (id) => els[id] ?? null,
      addEventListener() {},
    },
    location: { hash: "#%E0%A4%A", href: "" },
  };
  context.window.location = context.location;
  runInNewContext(helpJs, context);
  assert.equal(typeof listeners.input, "function", "search was not wired");
  assert.equal(els[".search"].hidden, false);
});
