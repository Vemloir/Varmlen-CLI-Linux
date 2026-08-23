//! Terminal formatting helpers.

use std::io::IsTerminal;

/// Whether to emit ANSI styling: never when piped, and never when the user has
/// asked for plain output through the NO_COLOR convention.
pub fn styled() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

/// Secondary text — metadata that should not compete with the names above it.
pub fn dim(text: &str) -> String {
    if styled() {
        format!("\x1b[2m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

pub fn bold(text: &str) -> String {
    if styled() {
        format!("\x1b[1m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

/// Binary units, matching how providers quote quotas.
pub fn bytes(value: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut size = value as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit + 1 < UNITS.len() {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value} B")
    } else if size >= 100.0 {
        format!("{size:.0} {}", UNITS[unit])
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

/// `YYYY-MM-DD` in UTC from a unix timestamp.
///
/// Written out rather than pulled from a date crate: this is the only date
/// arithmetic in the client, and a VPN client is a poor place to grow the
/// dependency surface for it.
pub fn date(unix_seconds: i64) -> String {
    let days = unix_seconds.div_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Howard Hinnant's days-to-civil algorithm, shifted to a March-based year so
/// the leap day falls at the end.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 { shifted } else { shifted - 146_096 } / 146_097;
    let day_of_era = (shifted - era * 146_097) as i64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_position = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_position + 2) / 5 + 1) as u32;
    let month = if month_position < 10 {
        month_position + 3
    } else {
        month_position - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_dates_round_trip() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(1_767_225_600), "2026-01-01");
        // 2024 was a leap year: the day after 2024-02-28 is the 29th.
        assert_eq!(date(1_709_164_800), "2024-02-29");
        assert_eq!(date(-86_400), "1969-12-31");
    }

    #[test]
    fn byte_sizes_stay_readable() {
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(1024), "1.0 KiB");
        assert_eq!(bytes(1024 * 1024 * 1024), "1.0 GiB");
        assert_eq!(bytes(150 * 1024 * 1024 * 1024), "150 GiB");
    }
}

/// Render a provider label for a terminal that cannot draw emoji.
///
/// VTE-based terminals (Ptyxis, GNOME Terminal) do not compose regional
/// indicator pairs into flags no matter which fonts are installed, so a label
/// like "\u{1F1EB}\u{1F1EE} Finland" arrives as blanks or boxes. A flag is not
/// decoration though — it names the country — so the pair is turned back into
/// its ISO letters rather than dropped, and only the genuinely decorative
/// pictographs are removed.
pub fn label(text: &str, emoji: bool) -> String {
    if emoji {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        let cp = ch as u32;
        match cp {
            // Regional indicators A-Z: recover the country code.
            0x1F1E6..=0x1F1FF => {
                out.push((b'A' + (cp - 0x1F1E6) as u8) as char);
            }
            // Variation selectors and ZWJ: joiners with nothing left to join.
            0x200D | 0xFE00..=0xFE0F => {}
            // Pictographs, symbols, dingbats.
            0x1F000..=0x1FAFF | 0x2600..=0x27BF | 0x2B00..=0x2BFF => {}
            _ => out.push(ch),
        }
    }
    // Removing a pictograph leaves the space that separated it behind.
    let mut collapsed = String::with_capacity(out.len());
    let mut previous_space = false;
    for ch in out.trim().chars() {
        let space = ch.is_whitespace();
        if !(space && previous_space) {
            collapsed.push(ch);
        }
        previous_space = space;
    }
    collapsed
}

#[cfg(test)]
mod label_tests {
    use super::label;

    #[test]
    fn flags_become_country_codes() {
        assert_eq!(
            label("\u{1F1EB}\u{1F1EE} Finland | Helsinki", false),
            "FI Finland | Helsinki"
        );
        assert_eq!(
            label("\u{1F1F7}\u{1F1FA} \u{0411}\u{0435}\u{043B}\u{044B}\u{0439} \u{1F4C4}", false),
            "RU \u{0411}\u{0435}\u{043B}\u{044B}\u{0439}"
        );
    }

    #[test]
    fn enabling_emoji_leaves_the_label_alone() {
        let original = "\u{1F1EB}\u{1F1EE} Finland";
        assert_eq!(label(original, true), original);
    }

    #[test]
    fn plain_labels_are_untouched() {
        assert_eq!(label("Frankfurt 01", false), "Frankfurt 01");
    }
}

/// A subscription URL with its credential removed.
///
/// The path of a subscription URL *is* the account token — anyone holding it
/// can pull the account's servers. Terminals get screenshotted, scrollback gets
/// pasted into support chats, and `list` output ends up in bug reports, so the
/// path never leaves the config file unless it is asked for explicitly.
pub fn redacted_url(raw: &str) -> String {
    match url::Url::parse(raw) {
        Ok(url) => match url.host_str() {
            Some(host) => format!("{}://{host}/\u{2026}", url.scheme()),
            None => "\u{2026}".to_string(),
        },
        Err(_) => "\u{2026}".to_string(),
    }
}

#[cfg(test)]
mod redaction_tests {
    use super::redacted_url;

    #[test]
    fn the_token_never_survives() {
        let secret = "EXAMPLE-TOKEN-0000000000000000000";
        let masked = redacted_url(&format!("https://example.org/sub/{secret}"));
        assert_eq!(masked, "https://example.org/\u{2026}");
        assert!(!masked.contains(secret));
    }

    #[test]
    fn a_url_that_does_not_parse_reveals_nothing() {
        assert_eq!(redacted_url("not a url at all"), "\u{2026}");
    }
}
