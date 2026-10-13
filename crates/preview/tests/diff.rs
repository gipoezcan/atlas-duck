use atlas_duck_preview::diff::{DIFF_MAX_LINES, DiffLine, DiffOp, hunks, line_diff};

fn d(op: DiffOp, t: &str) -> DiffLine {
    DiffLine {
        op,
        text: t.to_owned(),
    }
}

/// Checks that an edit script turns `old` into `new`; returns the number of non-Same lines.
fn check_script(old: &str, new: &str, script: &[DiffLine]) -> usize {
    let o: Vec<&str> = old.lines().collect();
    let n: Vec<&str> = new.lines().collect();
    let kept_old: Vec<&str> = script
        .iter()
        .filter(|l| l.op != DiffOp::Add)
        .map(|l| l.text.as_str())
        .collect();
    let kept_new: Vec<&str> = script
        .iter()
        .filter(|l| l.op != DiffOp::Del)
        .map(|l| l.text.as_str())
        .collect();
    assert_eq!(kept_old, o, "Same+Del must reproduce old");
    assert_eq!(kept_new, n, "Same+Add must reproduce new");
    script.iter().filter(|l| l.op != DiffOp::Same).count()
}

#[test]
fn line_diff_identity_is_all_same() {
    let s = "a\nb\nc";
    let out = line_diff(s, s);
    assert_eq!(
        out,
        vec![
            d(DiffOp::Same, "a"),
            d(DiffOp::Same, "b"),
            d(DiffOp::Same, "c")
        ]
    );
    assert!(line_diff("", "").is_empty());
}

#[test]
fn line_diff_insert_delete_replace() {
    assert_eq!(
        line_diff("a\nc", "a\nb\nc"),
        vec![
            d(DiffOp::Same, "a"),
            d(DiffOp::Add, "b"),
            d(DiffOp::Same, "c")
        ]
    );
    assert_eq!(
        line_diff("a\nb\nc", "a\nc"),
        vec![
            d(DiffOp::Same, "a"),
            d(DiffOp::Del, "b"),
            d(DiffOp::Same, "c")
        ]
    );
    assert_eq!(
        line_diff("a\nb\nc", "a\nx\nc"),
        vec![
            d(DiffOp::Same, "a"),
            d(DiffOp::Del, "b"),
            d(DiffOp::Add, "x"),
            d(DiffOp::Same, "c")
        ]
    );
    assert_eq!(line_diff("", "x"), vec![d(DiffOp::Add, "x")]);
    assert_eq!(line_diff("x", ""), vec![d(DiffOp::Del, "x")]);
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
        let script = line_diff(old, new);
        assert_eq!(check_script(old, new, &script), min, "{old:?} -> {new:?}");
    }
}

#[test]
fn line_diff_cap_falls_back_to_whole_replace() {
    let old: String = (0..=DIFF_MAX_LINES).map(|i| format!("o{i}\n")).collect();
    let new = "same\nsame2\n";
    let out = line_diff(&old, new);
    let dels = out.iter().filter(|l| l.op == DiffOp::Del).count();
    let adds = out.iter().filter(|l| l.op == DiffOp::Add).count();
    assert_eq!(dels, DIFF_MAX_LINES + 1);
    assert_eq!(adds, 2);
    assert!(out.iter().all(|l| l.op != DiffOp::Same));
    // one Del block, then one Add block: a single hunk
    assert_eq!(hunks(&out), 1);
    assert_eq!(
        out.iter().position(|l| l.op == DiffOp::Add),
        Some(DIFF_MAX_LINES + 1)
    );
    // exactly at the cap still diffs normally
    let at_cap: String = (0..DIFF_MAX_LINES).map(|i| format!("l{i}\n")).collect();
    let out = line_diff(&at_cap, &at_cap);
    assert!(out.iter().all(|l| l.op == DiffOp::Same));
}

#[test]
fn line_diff_bounded_work_on_dissimilar_inputs() {
    let old: String = (0..5000).map(|i| format!("a{i}\n")).collect();
    let new: String = (0..5000).map(|i| format!("b{i}\n")).collect();
    let out = line_diff(&old, &new);
    check_script(&old, &new, &out);
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
