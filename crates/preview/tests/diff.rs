use atlas_duck_preview::diff::{
    DIFF_MAX_LINES, DIFF_MAX_MIDDLE_BYTES, DiffLine, DiffOp, hunks, line_diff, line_diff_lines,
};

fn d(op: DiffOp, t: &str) -> DiffLine {
    DiffLine {
        op,
        text: t.to_owned(),
    }
}

/// Checks that an untruncated edit script turns `old` into `new` byte for byte (lines split
/// like `line_diff` does, keeping the terminator); returns the number of non-Same lines.
fn check_script(old: &str, new: &str, script: &[DiffLine]) -> usize {
    let kept_old: String = script
        .iter()
        .filter(|l| l.op != DiffOp::Add)
        .map(|l| l.text.as_str())
        .collect();
    let kept_new: String = script
        .iter()
        .filter(|l| l.op != DiffOp::Del)
        .map(|l| l.text.as_str())
        .collect();
    assert_eq!(kept_old, old, "Same+Del must reproduce old");
    assert_eq!(kept_new, new, "Same+Add must reproduce new");
    script.iter().filter(|l| l.op != DiffOp::Same).count()
}

/// Terminates every line, so cases read as lists of lines.
fn nl(s: &str) -> String {
    if s.is_empty() {
        String::new()
    } else {
        format!("{s}\n")
    }
}

#[test]
fn line_diff_identity_is_all_same() {
    let s = "a\nb\nc";
    let out = line_diff(s, s);
    assert!(!out.truncated);
    assert_eq!(
        out.lines,
        vec![
            d(DiffOp::Same, "a\n"),
            d(DiffOp::Same, "b\n"),
            d(DiffOp::Same, "c")
        ]
    );
    assert!(line_diff("", "").lines.is_empty());
}

#[test]
fn line_diff_insert_delete_replace() {
    assert_eq!(
        line_diff("a\nc\n", "a\nb\nc\n").lines,
        vec![
            d(DiffOp::Same, "a\n"),
            d(DiffOp::Add, "b\n"),
            d(DiffOp::Same, "c\n")
        ]
    );
    assert_eq!(
        line_diff("a\nb\nc\n", "a\nc\n").lines,
        vec![
            d(DiffOp::Same, "a\n"),
            d(DiffOp::Del, "b\n"),
            d(DiffOp::Same, "c\n")
        ]
    );
    assert_eq!(
        line_diff("a\nb\nc\n", "a\nx\nc\n").lines,
        vec![
            d(DiffOp::Same, "a\n"),
            d(DiffOp::Del, "b\n"),
            d(DiffOp::Add, "x\n"),
            d(DiffOp::Same, "c\n")
        ]
    );
    assert_eq!(line_diff("", "x").lines, vec![d(DiffOp::Add, "x")]);
    assert_eq!(line_diff("x", "").lines, vec![d(DiffOp::Del, "x")]);
}

#[test]
fn line_diff_myers_minimal_on_small_cases() {
    // (old, new, minimal number of Add + Del lines)
    let table: [(&str, &str, usize); 10] = [
        ("a\nb\nc\na\nb\nb\na", "c\nb\na\nb\na\nc", 5), // the Myers paper example
        ("a\nb\nc", "c\nb\na", 4),
        ("a\nb\nc\nd", "b\nd", 2),
        ("a", "b", 2),
        ("a\na\na", "a", 2),
        ("x\ny", "y\nx", 2),
        ("1\n2\n3\n4\n5", "1\n3\n5", 2),
        ("", "a\nb", 2),
        ("a\nb\nc\nd\ne\nf", "a\nb\nc\nd\ne\nf\ng", 1),
        ("k\nl\nm", "l\nm\nn", 2),
    ];
    for (old, new, min) in table {
        let (old, new) = (nl(old), nl(new));
        let out = line_diff(&old, &new);
        assert!(!out.truncated);
        assert_eq!(
            check_script(&old, &new, &out.lines),
            min,
            "{old:?} -> {new:?}"
        );
    }
}

/// I-1: every byte difference shows as a non-Same line.
#[test]
fn line_diff_is_byte_faithful() {
    let pairs = [
        ("a", "a\n"),
        ("a\n", "a"),
        ("a\r\n", "a\n"),
        ("a", "a "),
        ("a\r", "a"),
        ("a\r", "a\n"),
        ("a\u{2028}b", "a b"),
        ("a\u{2028}b\n", "a\u{2028}b"),
        ("", "\n"),
        ("a\r\r\n", "a\r\n"),
        ("a\nb", "a\nb\n"),
    ];
    for (old, new) in pairs {
        let out = line_diff(old, new);
        assert!(!out.truncated);
        assert!(
            out.lines.iter().any(|l| l.op != DiffOp::Same),
            "{old:?} vs {new:?} diffed as all-Same"
        );
        check_script(old, new, &out.lines);
        let out = line_diff(new, old);
        assert!(out.lines.iter().any(|l| l.op != DiffOp::Same));
        check_script(new, old, &out.lines);
    }
    assert_eq!(
        line_diff("a", "a\n").lines,
        vec![d(DiffOp::Del, "a"), d(DiffOp::Add, "a\n")]
    );
    assert_eq!(
        line_diff("a\r\nb\n", "a\nb\n").lines,
        vec![
            d(DiffOp::Del, "a\r\n"),
            d(DiffOp::Add, "a\n"),
            d(DiffOp::Same, "b\n")
        ]
    );
}

#[test]
fn line_diff_equal_inputs_are_all_same() {
    for s in ["a", "a\n", "a\r\n", "a\r", "a\u{2028}", "a \n b", "\n\n"] {
        let out = line_diff(s, s);
        assert!(out.lines.iter().all(|l| l.op == DiffOp::Same), "{s:?}");
        check_script(s, s, &out.lines);
    }
}

#[test]
fn line_diff_cap_applies_to_the_middle_only() {
    // 20 001 old lines against 2 new ones: nothing in common, the middle exceeds the cap.
    let old: String = (0..=DIFF_MAX_LINES).map(|i| format!("o{i}\n")).collect();
    let new = "same\nsame2\n";
    let out = line_diff(&old, new);
    assert!(out.truncated);
    let dels = out.lines.iter().filter(|l| l.op == DiffOp::Del).count();
    let adds = out.lines.iter().filter(|l| l.op == DiffOp::Add).count();
    assert_eq!(dels, DIFF_MAX_LINES);
    assert_eq!(adds, 2);
    assert!(out.lines.iter().all(|l| l.op != DiffOp::Same));
    // one Del block, then one Add block: a single hunk
    assert_eq!(hunks(&out.lines), 1);
    assert_eq!(
        out.lines.iter().position(|l| l.op == DiffOp::Add),
        Some(DIFF_MAX_LINES)
    );
    // identical texts at the cap and past it diff as all Same
    for n in [DIFF_MAX_LINES, DIFF_MAX_LINES + 1] {
        let t: String = (0..n).map(|i| format!("l{i}\n")).collect();
        let out = line_diff(&t, &t);
        assert!(!out.truncated);
        assert_eq!(out.lines.len(), n);
        assert!(out.lines.iter().all(|l| l.op == DiffOp::Same));
    }
}

/// I-2: a one-line change in a text past the cap still shows as one changed line.
#[test]
fn line_diff_huge_but_nearly_identical_keeps_prefix_and_suffix() {
    let n = DIFF_MAX_LINES + 1;
    let build = |mid: &str| -> String {
        (0..n)
            .map(|i| {
                if i == n / 2 {
                    format!("{mid}\n")
                } else {
                    format!("l{i}\n")
                }
            })
            .collect()
    };
    let (old, new) = (build("old"), build("new"));
    let out = line_diff(&old, &new);
    assert!(!out.truncated);
    assert_eq!(out.lines.len(), n + 1);
    assert_eq!(hunks(&out.lines), 1);
    assert_eq!(out.lines.iter().filter(|l| l.op == DiffOp::Del).count(), 1);
    assert_eq!(out.lines.iter().filter(|l| l.op == DiffOp::Add).count(), 1);
    assert_eq!(check_script(&old, &new, &out.lines), 2);
    assert_eq!(out.lines.first(), Some(&d(DiffOp::Same, "l0\n")));
    assert_eq!(
        out.lines.last(),
        Some(&d(DiffOp::Same, &format!("l{}\n", n - 1)))
    );
}

#[test]
fn line_diff_truncates_a_huge_middle_visibly() {
    // shared head and tail, two 30 000-line dissimilar middles
    let mk = |tag: &str| -> String {
        let mid: String = (0..30_000).map(|i| format!("{tag}{i}\n")).collect();
        format!("head\n{mid}tail\n")
    };
    let out = line_diff(&mk("a"), &mk("b"));
    assert!(out.truncated);
    assert_eq!(out.lines.first(), Some(&d(DiffOp::Same, "head\n")));
    assert_eq!(out.lines.last(), Some(&d(DiffOp::Same, "tail\n")));
    let dels = out.lines.iter().filter(|l| l.op == DiffOp::Del).count();
    let adds = out.lines.iter().filter(|l| l.op == DiffOp::Add).count();
    assert_eq!((dels, adds), (DIFF_MAX_LINES, DIFF_MAX_LINES));
}

#[test]
fn line_diff_bounds_the_bytes_of_a_huge_middle() {
    let big = "x".repeat(DIFF_MAX_MIDDLE_BYTES + 1000);
    let out = line_diff(&format!("h\n{big}\nt\n"), "h\ny\nt\n");
    assert!(out.truncated);
    let del_bytes: usize = out
        .lines
        .iter()
        .filter(|l| l.op == DiffOp::Del)
        .map(|l| l.text.len())
        .sum();
    assert_eq!(del_bytes, DIFF_MAX_MIDDLE_BYTES);
    assert_eq!(out.lines.first(), Some(&d(DiffOp::Same, "h\n")));
    assert_eq!(out.lines.last(), Some(&d(DiffOp::Same, "t\n")));
    assert!(out.lines.contains(&d(DiffOp::Add, "y\n")));
}

#[test]
fn line_diff_bounded_work_on_dissimilar_inputs() {
    let old: String = (0..5000).map(|i| format!("a{i}\n")).collect();
    let new: String = (0..5000).map(|i| format!("b{i}\n")).collect();
    let out = line_diff(&old, &new);
    assert!(!out.truncated);
    check_script(&old, &new, &out.lines);
    // past the distance bound: one Del block, then one Add block, no Same
    assert_eq!(out.lines.len(), 10_000);
    assert!(out.lines[..5000].iter().all(|l| l.op == DiffOp::Del));
    assert!(out.lines[5000..].iter().all(|l| l.op == DiffOp::Add));
    assert_eq!(hunks(&out.lines), 1);

    // the same with a shared prefix and suffix: they stay Same around the replaced middle
    let (old, new) = (format!("p\n{old}s\n"), format!("p\n{new}s\n"));
    let out = line_diff(&old, &new);
    assert!(!out.truncated);
    check_script(&old, &new, &out.lines);
    assert_eq!(out.lines.len(), 10_002);
    assert_eq!(out.lines.first(), Some(&d(DiffOp::Same, "p\n")));
    assert_eq!(out.lines.last(), Some(&d(DiffOp::Same, "s\n")));
    assert!(out.lines[1..5001].iter().all(|l| l.op == DiffOp::Del));
    assert!(out.lines[5001..10_001].iter().all(|l| l.op == DiffOp::Add));
}

/// M7 Task 15 (T7 review I-2): a diff over a caller's own line projection (the raw storage
/// lines, which end at block tags, not only at `\n`) keeps every line as given: no line is
/// re-split, nothing is added, and `line_diff` is the slice diff of its `\n` split.
#[test]
fn line_diff_lines_keeps_the_projection() {
    let old = ["<p>a</p>", "<p>b</p>", "<p>c</p>"];
    let new = ["<p>a</p>", "<p>B</p>", "<p>c</p>", "<hr/>"];
    let out = line_diff_lines(&old, &new);
    assert!(!out.truncated);
    assert_eq!(
        out.lines,
        vec![
            d(DiffOp::Same, "<p>a</p>"),
            d(DiffOp::Del, "<p>b</p>"),
            d(DiffOp::Add, "<p>B</p>"),
            d(DiffOp::Same, "<p>c</p>"),
            d(DiffOp::Add, "<hr/>"),
        ]
    );
    check_script(&old.concat(), &new.concat(), &out.lines);
    // A line holding a `\n` inside is not split again.
    let out = line_diff_lines(&["x\ny"], &["x\nz"]);
    assert_eq!(
        out.lines,
        vec![d(DiffOp::Del, "x\ny"), d(DiffOp::Add, "x\nz")]
    );
    for (old, new) in [("a\nb\nc", "a\nx\nc\n"), ("", "q\n"), ("p\nq", "p\nq")] {
        let a: Vec<&str> = old.split_inclusive('\n').collect();
        let b: Vec<&str> = new.split_inclusive('\n').collect();
        assert_eq!(
            line_diff(old, new),
            line_diff_lines(&a, &b),
            "{old:?} {new:?}"
        );
    }
}

/// M7 T15 review m-4: storage-sized middles (4 MiB a side) of long lines that share all but
/// their last bytes. The search compares interned line ids, not the line text, so its cost does
/// not grow with the line length (measured on the dev profile: the text comparisons took about
/// 170 ms for the first case, the ids about 30 ms); the script is still the minimal,
/// byte-faithful one.
/// - 1 000 lines a side, each differing from every line of the other side only after a common
///   4 000-byte run: an edit distance of exactly the search bound, every step of the search a
///   mismatch over the whole run.
/// - long equal lines, one side 1 990 lines shorter and both framed by a line the other lacks
///   (neither the prefix nor the suffix cut takes them): a snake over almost the whole middle.
#[test]
fn line_diff_long_equal_lines_stay_fast() {
    let run = "x".repeat(4_000);
    let old: String = (0..1_000).map(|i| format!("{run}a{i}\n")).collect();
    let new: String = (0..1_000).map(|i| format!("{run}b{i}\n")).collect();
    let started = std::time::Instant::now();
    let out = line_diff(&old, &new);
    let took = started.elapsed();
    assert!(!out.truncated);
    assert_eq!(check_script(&old, &new, &out.lines), 2_000);
    assert!(took < std::time::Duration::from_millis(500), "{took:?}");

    let line = format!("{}\n", "x".repeat(199));
    let side = |head: &str, n: usize, tail: &str| format!("{head}\n{}{tail}\n", line.repeat(n));
    let (old, new) = (
        side("old", 19_990, "end old"),
        side("new", 18_000, "end new"),
    );
    let started = std::time::Instant::now();
    let out = line_diff(&old, &new);
    let took = started.elapsed();
    assert!(!out.truncated);
    assert_eq!(check_script(&old, &new, &out.lines), 1_994);
    assert!(took < std::time::Duration::from_secs(1), "{took:?}");
}

#[test]
fn hunks_counts_runs() {
    assert_eq!(hunks(&[]), 0);
    assert_eq!(hunks(&[d(DiffOp::Same, "a")]), 0);
    let s = [
        d(DiffOp::Del, "a"),
        d(DiffOp::Add, "b"),
        d(DiffOp::Same, "c"),
        d(DiffOp::Add, "d"),
        d(DiffOp::Same, "e"),
        d(DiffOp::Del, "f"),
    ];
    assert_eq!(hunks(&s), 3);
}

/// T13: a `Field` line heads a field's section of a multi-field diff; it is neither text nor a
/// change, so it is no hunk and ends the run before it.
#[test]
fn field_lines_head_sections_and_are_not_hunks() -> Result<(), serde_json::Error> {
    assert_eq!(hunks(&[d(DiffOp::Field, "fields.summary")]), 0);
    let s = [
        d(DiffOp::Field, "fields.description"),
        d(DiffOp::Del, "a"),
        d(DiffOp::Field, "fields.summary"),
        d(DiffOp::Add, "b"),
    ];
    assert_eq!(hunks(&s), 2);
    assert_eq!(serde_json::to_value(DiffOp::Field)?, "field");
    Ok(())
}
