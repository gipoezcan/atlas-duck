use atlas_duck_preview::{
    JsonNode, Platform, app_origin, iframe_document, json_tree, sanitize_html,
};
use serde_json::json;

const PNG: &str = "data:image/png;base64,iVBORw0KGgo=";

#[test]
fn sanitize_strips_script_style_class_remote_images() {
    let input = format!(
        "<p class=\"x\" style=\"color:red\" id=\"i\" onclick=\"e()\">hi<script>alert(1)</script></p>\
         <style>p{{color:red}}</style>\
         <img src=\"https://evil\" onerror=\"alert(1)\">\
         <a href=\"javascript:alert(1)\">link text</a>\
         <img src=\"{PNG}\" alt=\"ok\">"
    );
    let out = sanitize_html(&input);
    for bad in [
        "<script",
        "onerror",
        "onclick",
        "style",
        "class=",
        "id=",
        "https://evil",
        "<a",
        "href",
    ] {
        assert!(!out.contains(bad), "{bad} in {out}");
    }
    assert!(out.contains("hi"));
    assert!(
        out.contains("link text (javascript:alert(1))"),
        "link text and URL as text: {out}"
    );
    assert!(out.contains(PNG), "data image kept: {out}");
}

#[test]
fn sanitize_hostile_inputs() {
    let cases = [
        "<img src=//evil.example/x.png>",
        "<img src=\"/relative.png\">",
        "<img src=\"relative.png\">",
        "<img src=\"data:text/html;base64,PHNjcmlwdD4=\">",
        "<img src=\"data:image/svg+xml;base64,PHN2Zz4=\">",
        "<img src=\"  javascript:alert(1)\">",
        "<img srcset=\"https://evil 1x\" src=x>",
        "<svg><script>alert(1)</script></svg>",
        "<math><mi xlink:href=\"javascript:alert(1)\">x</mi></math>",
        "<iframe src=\"https://evil\"></iframe>",
        "<object data=\"https://evil\"></object><embed src=\"https://evil\">",
        "<form action=\"https://evil\"><input name=a></form>",
        "<link rel=stylesheet href=\"https://evil/x.css\">",
        "<meta http-equiv=refresh content=\"0;url=https://evil\">",
        "<base href=\"https://evil/\">",
        "<div style=\"position:fixed\" CLASS=\"y\" ID=\"z\" TITLE=\"t\" LANG=\"x\" DIR=\"rtl\">d</div>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<!-- <script>alert(1)</script> -->x",
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
        "<table background=\"https://evil\"><tr><td>c</td></tr></table>",
        "<p onmouseover=alert(1)>x</p>",
        "<button formaction=\"https://evil\">b</button>",
    ];
    for c in cases {
        let out = sanitize_html(c).to_ascii_lowercase();
        for bad in [
            "evil",
            "script",
            "javascript",
            "style",
            "class",
            "onerror",
            "onmouse",
            "<iframe",
            "<svg",
            "<object",
            "<embed",
            "<form",
            "<link",
            "<meta",
            "<base",
            "href",
            "srcset",
            "formaction",
            "background",
            "<math",
        ] {
            assert!(!out.contains(bad), "{bad} survived {c:?} -> {out}");
        }
        // Any surviving img must carry a data: raster, nothing else.
        if let Some(i) = out.find("<img") {
            assert!(
                out[i..].contains("src=\"data:image/") || !out[i..].contains("src="),
                "{c:?} -> {out}"
            );
        }
    }
}

#[test]
fn sanitize_exact_outputs_for_hiding_and_sizing_markup() {
    let cases = [
        ("<bdo dir=\"rtl\">x</bdo>", "x"),
        (
            "<p dir=\"rtl\" lang=\"x\" title=\"t\" id=\"i\">x</p>",
            "<p>x</p>",
        ),
        ("<details><summary>s</summary>h</details>", "sh"),
        ("<ruby>a<rp>h</rp><rt>b</rt></ruby>", "ahb"),
        (
            "<img src=\"data:image/png;base64,AAAA\" width=\"1\" height=\"1\" align=\"left\" alt=\"a\">",
            "<img src=\"data:image/png;base64,AAAA\" alt=\"a\">",
        ),
        ("<hr size=\"1\" width=\"1\" align=\"left\">", "<hr>"),
        (
            "<table align=\"right\"><tr><td align=\"left\" colspan=\"2\" width=\"1\">c</td></tr></table>",
            "<table><tbody><tr><td colspan=\"2\">c</td></tr></tbody></table>",
        ),
        ("<small><sub><sup><small>t</small></sup></sub></small>", "t"),
        (
            "<blockquote cite=\"https://evil\">q</blockquote>",
            "<blockquote>q</blockquote>",
        ),
        (
            "<q cite=\"https://evil\">q</q><del cite=\"https://evil\">d</del>",
            "q<del>d</del>",
        ),
        (
            "<center><font size=\"1\" color=\"red\">c</font></center>",
            "c",
        ),
        (
            "<ol start=\"3\" type=\"a\"><li>x</li></ol>",
            "<ol start=\"3\"><li>x</li></ol>",
        ),
        ("<bdi>x</bdi>", "<bdi>x</bdi>"),
        (
            "<img src=\"DATA:image/PNG;base64,AAAA\">",
            "<img src=\"DATA:image/PNG;base64,AAAA\">",
        ),
        ("<img src=\"&#100;ata:image/svg+xml;base64,AAAA\">", "<img>"),
    ];
    for (input, expected) in cases {
        assert_eq!(sanitize_html(input), expected, "{input}");
    }
}

#[test]
fn links_become_text_with_visible_url() {
    let cases = [
        (
            "<a href=\"http://example.com/x\">t</a>",
            "t (http://example.com/x)",
        ),
        (
            "<a href=\"https://example.com/x?a=1&b=2\">t</a>",
            "t (https://example.com/x?a=1&amp;b=2)",
        ),
        ("<a href=\"/rel/path\">t</a>", "t (/rel/path)"),
        (
            "<a href=\"javascript:alert(1)\">t</a>",
            "t (javascript:alert(1))",
        ),
        ("<a href=\"mailto:a@b.c\">t</a>", "t (mailto:a@b.c)"),
        ("<a href=\"\">t</a>", "t"),
        ("<a>t</a>", "t"),
        ("<a href=\"https://x/\">https://x/</a>", "https://x/"),
        (
            "<a href=\"https://x/\">a <b>bold</b> <i>it</i></a>",
            "a <b>bold</b> <i>it</i> (https://x/)",
        ),
        (
            "<a href=\"data:text/html,&lt;script&gt;alert(1)&lt;/script&gt;\">d</a>",
            "d (data:text/html,&lt;script&gt;alert(1)&lt;/script&gt;)",
        ),
        (
            "<a href=\"x&quot;&gt;&lt;img src=y\">t</a>",
            "t (x\"&gt;&lt;img src=y)",
        ),
        (
            "<abbr>a</abbr><a href=\"u\">1</a><a href=\"v\">2</a>",
            "a1 (u)2 (v)",
        ),
    ];
    for (input, expected) in cases {
        let out = sanitize_html(input);
        assert_eq!(out, expected, "{input}");
        assert_eq!(sanitize_html(&out), out, "idempotent: {input}");
        assert!(!out.contains("<a"), "{out}");
    }
}

#[test]
fn sanitize_is_idempotent() {
    let once = sanitize_html("<p>a <b>b</b><img src=\"data:image/png;base64,AAAA\"></p>");
    assert_eq!(sanitize_html(&once), once);
}

#[test]
fn iframe_document_meta_csp_first() {
    let w = iframe_document("<p>x</p>", Platform::Windows);
    assert!(w.starts_with(
        "<!doctype html><html><head><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src http://tauri.localhost/preview.css; img-src data:\">"
    ));
    let m = iframe_document("<p>x</p>", Platform::MacOsLinux);
    assert!(m.starts_with(
        "<!doctype html><html><head><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src tauri://localhost/preview.css; img-src data:\">"
    ));
    for (doc, origin) in [(&w, "http://tauri.localhost"), (&m, "tauri://localhost")] {
        assert!(doc.contains(&format!(
            "><link rel=\"stylesheet\" href=\"{origin}/preview.css\"></head><body><p>x</p></body></html>"
        )));
        assert!(!doc.contains("<style"));
        assert!(!doc.contains("style="));
    }
    assert_eq!(app_origin(Platform::Windows), "http://tauri.localhost");
    assert_eq!(app_origin(Platform::MacOsLinux), "tauri://localhost");
}

#[test]
fn iframe_document_sanitizes_hostile_body() {
    let d = iframe_document(
        "<style>*{}</style><script>x</script><img src=https://evil onerror=x>t",
        Platform::Windows,
    );
    assert!(!d.contains("<script"));
    assert!(!d.contains("evil"));
    assert!(!d.contains("<style"));
    assert!(d.contains("</head><body>"));
    assert_eq!(d.matches("<meta").count(), 1);
}

#[test]
fn json_tree_hidden_bytes() {
    let big = "x".repeat(10 * 1024);
    let node =
        json_tree(&json!({"a": big, "b": ["short", {"c": "y".repeat(4096)}, "z".repeat(4097)]}));
    assert_eq!(node.hidden_bytes(), 10240 + 4097);
    match json_tree(&json!("x".repeat(10240))) {
        JsonNode::Collapsed {
            byte_len,
            hidden_bytes,
        } => {
            assert_eq!(byte_len, 10240);
            assert_eq!(hidden_bytes, 10240);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn json_tree_sizes_match_compact_json() -> Result<(), Box<dyn std::error::Error>> {
    let v = json!({"a": [1, true, null, "é\"x"], "b": {}, "c": []});
    match json_tree(&v) {
        JsonNode::Object { size, .. } => assert_eq!(size, serde_json::to_string(&v)?.len() as u64),
        other => panic!("{other:?}"),
    }
    Ok(())
}
