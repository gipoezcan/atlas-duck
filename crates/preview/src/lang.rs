//! M15 T10b: the language of the preview's own text (labels, notes, warnings). The rendered
//! Jira/Confluence content and every agent-supplied string are never translated. The desktop
//! passes the app's resolved language, the server the user's (`lang_pref`, `auto` resolved from
//! the request's `Accept-Language`). English is byte for byte what the preview always wrote.

/// A language of the preview's own text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    #[default]
    En,
    De,
}

impl Lang {
    /// `en` or `de` by the language.
    pub const fn pick(self, en: &'static str, de: &'static str) -> &'static str {
        match self {
            Lang::En => en,
            Lang::De => de,
        }
    }

    /// A count as the language writes it: English digits as they are, German grouped by `.`.
    pub fn count(self, n: u64) -> String {
        let digits = n.to_string();
        if self == Lang::En || digits.len() <= 3 {
            return digits;
        }
        let mut out = String::with_capacity(digits.len() + digits.len() / 3);
        for (i, c) in digits.chars().enumerate() {
            if i > 0 && (digits.len() - i).is_multiple_of(3) {
                out.push('.');
            }
            out.push(c);
        }
        out
    }

    /// The German word of a count unit the preview names ("bytes", "rows", ...); English as is.
    pub fn unit(self, unit: &str) -> String {
        if self == Lang::En {
            return unit.to_owned();
        }
        match unit {
            "bytes" => "Bytes",
            "rows" | "lines" => "Zeilen",
            "entries" | "items" => "Einträge",
            "calls" => "Aufrufe",
            "keys" => "Schlüssel",
            "comments" => "Kommentare",
            "results" => "Ergebnisse",
            "requests" => "Anfragen",
            "fields" => "Felder",
            "attachments" => "Anhänge",
            other => other,
        }
        .to_owned()
    }
}
