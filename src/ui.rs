//! Terminal UI rendering via termimad.

use termimad::MadSkin;

/// Create the default terminal skin for rendering markdown content.
pub fn default_skin() -> MadSkin {
    MadSkin::default()
}

/// Render markdown text to the terminal.
pub fn render_md(text: &str) {
    let skin = default_skin();
    skin.print_text(text);
}
