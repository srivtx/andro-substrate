fn main() {
    for s in ["\u{202A}1\u{202A}", "\u{202A}a\u{202A}", "\u{202A} \u{202A}", "\u{202B}1\u{202B}", "\u{202A}1\u{202C}", "\u{202A}1"] {
        let chars: Vec<(usize, char)> = s.char_indices().collect();
        let r = substrate_text::shaper::resolve(&chars, 0);
        println!("{:?}", s.chars().map(|c| format!("{:04X}", c as u32)).collect::<Vec<_>>());
        println!("  levels={:?} removed={:?} order={:?}", r.levels, r.removed, r.order(&chars));
    }
}
