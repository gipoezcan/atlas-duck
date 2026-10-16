//! The U-24 converter fault (PD-64): `TestHooks::converter_fault` makes the engine's executor
//! contexts carry one, and `ops::jira_body` / `ops::confluence_body` append it to the Markdown
//! converter's output before the hard check, so a test can prove that an escaping failure is
//! rejected at validation. `convert` itself has no fault API; production builds have neither the
//! hook nor the field.

use atlas_duck_registry::Product;

/// One unrecorded construct appended to converted text: the first three to Jira wiki text, the
/// last three to Confluence storage (M7 Δ3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConverterFault {
    /// `{include:…}`: an unrecorded include.
    Include,
    /// `[~…]`: an unrecorded mention.
    Mention,
    /// `{html}…{html}`: an unrecorded macro (one paired span on its own line).
    Html,
    /// `<ri:user …/>`: an unrecorded mention.
    RiUser,
    /// `<ac:structured-macro ac:name="include"/>`: an unrecorded include.
    IncludeMacro,
    /// `<ac:link><ri:page …/></ac:link>`: an unrecorded link.
    AcLink,
}

impl ConverterFault {
    /// The appended text; each one is the T4 (wiki) or T6 (storage) fuzz's fault string, so on
    /// any converter output of its product it is exactly one unrecorded construct of its kind.
    pub fn text(self) -> &'static str {
        match self {
            ConverterFault::Include => "{include:Injected}",
            ConverterFault::Mention => "[~injected]",
            ConverterFault::Html => "{html}<b>x</b>{html}",
            ConverterFault::RiUser => "<ri:user ri:userkey=\"injected\"/>",
            ConverterFault::IncludeMacro => "<ac:structured-macro ac:name=\"include\"/>",
            ConverterFault::AcLink => "<ac:link><ri:page ri:content-title=\"Injected\"/></ac:link>",
        }
    }

    /// The product whose converter output the fault belongs to.
    pub fn product(self) -> Product {
        match self {
            ConverterFault::Include | ConverterFault::Mention | ConverterFault::Html => {
                Product::Jira
            }
            ConverterFault::RiUser | ConverterFault::IncludeMacro | ConverterFault::AcLink => {
                Product::Confluence
            }
        }
    }

    /// `out` (converted text of `product`) with the fault appended, or `out` unchanged when the
    /// fault belongs to the other product, so a test of one product's check can never pass on the
    /// other's fault (plan review I-15). Wiki text ends in `\n` and gets the fault on a line of
    /// its own; storage ends without a newline and gets the element after its last block. The
    /// converter's record of its containers stays valid either way, since nothing before the end
    /// moves.
    pub fn apply(self, product: Product, out: &str) -> String {
        if self.product() != product {
            return out.to_owned();
        }
        match product {
            Product::Jira => format!("{out}{}\n", self.text()),
            Product::Confluence => format!("{out}{}", self.text()),
        }
    }
}
