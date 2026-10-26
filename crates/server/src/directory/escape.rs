//! RFC 4515 filter-value escaping: `*`, `(`, `)`, `\`, NUL and every non-ASCII byte become
//! `\xx` (two lowercase hex digits of the UTF-8 byte). Usernames are already restricted to
//! `[A-Za-z0-9._-]` (PD-199); this is the second line of defence for the search filter.

pub fn filter_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'*' | b'(' | b')' | b'\\' | 0 | 0x80..=0xff => {
                out.push('\\');
                out.push_str(&format!("{b:02x}"));
            }
            _ => out.push(char::from(b)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::filter_value;

    #[test]
    fn escape_table() {
        for (input, want) in [
            ("alice", "alice"),
            ("a*b", "a\\2ab"),
            ("(x)", "\\28x\\29"),
            ("back\\slash", "back\\5cslash"),
            ("nul\0", "nul\\00"),
            (
                "*)(uid=*))(|(uid=*",
                "\\2a\\29\\28uid=\\2a\\29\\29\\28|\\28uid=\\2a",
            ),
            ("jürgen", "j\\c3\\bcrgen"),
            ("日", "\\e6\\97\\a5"),
            ("a.b-c_d@x.local", "a.b-c_d@x.local"),
            ("", ""),
        ] {
            assert_eq!(filter_value(input), want, "{input:?}");
        }
    }
}
