use std::{borrow::Cow, sync::LazyLock};

use regex::{Regex, RegexSet};

use super::ip_filtering::filter_ips;

// A macro to allow for &'static str returns
macro_rules! censor {
    ($kind:literal) => {
        concat!("-censored(", $kind, ")-")
    };
}

#[tracing::instrument(skip_all)]
pub fn parse_line<'a>(line: &'a str) -> Cow<'a, str> {
    let line = line.trim();

    if line.is_empty() {
        return censor!("empty_line").into();
    }

    if !line.starts_with('[') {
        return censor!("no_ts_start").into();
    }

    let Some((timestamp, contents)) = line.split_once(']') else {
        return censor!("no_category_colon").into(); // Matching PHP
    };

    static TIMESTAMP_REGEX: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"^([0-9]{2}:[0-9]{2}:[0-9]{2}|[0-9]{2,4}-[0-9]{2,4}-[0-9]{2,4} [0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,3})+)$",
        ).unwrap()
    });
    if !TIMESTAMP_REGEX.is_match(&timestamp[1..]) {
        return censor!("no_ts_regex_match").into();
    }

    if contents.starts_with(" Starting up round ID ") {
        return Cow::Borrowed(line);
    }

    let mut words = contents.split(' ');
    if words.next() != Some("") {
        return censor!("no_space_after_timestamp").into();
    }

    let log_type = {
        let next_word = words.next().expect("out of words");
        if !next_word.ends_with(':') {
            return censor!("no_category_colon").into();
        }

        if next_word == "GAME-COMPAT:" {
            match words.next() {
                Some(next_word) => next_word,
                None => return censor!("game_compat_no_followup").into(),
            }
        } else {
            next_word
        }
    };

    match log_type[0..(log_type.len() - 1)].trim_start_matches("GAME-") {
        "ACCESS" => match words.next() {
            Some("Login:") => {
                let mut words_vec = words.collect::<Vec<_>>();

                if words_vec.len() < 4 {
                    return censor!("malformed access login").into();
                }

                let ip_cid_index = words_vec.len() - 4;
                words_vec[ip_cid_index] = censor!("ip/cid");

                Cow::Owned(format!(
                    "{timestamp}] {log_type} Login: {}",
                    words_vec.join(" ")
                ))
            }

            // Logout lines carry only a ckey, safe to keep verbatim.
            Some("Logout:") => Cow::Borrowed(line),

            // Anything else under ACCESS gets censored. Variants like
            //   "Failed Login: ckey CID IP - reason"
            //   "Forced disconnect: ckey CID IP - CID randomizer check"
            //   "Notice: ckey has the same IP (X) / ID (Y) as other_ckey"
            //   "AFK: ckey"
            // either leak IP and CID in non-trivial positions or are noisy
            // enough that default-censoring unknown subcategories is the
            // safer choice for codebases that diverge from upstream tg.
            _ => censor!("access detail").into(),
        },

        "ADMIN" => {
            let remaining = words.collect::<Vec<_>>().join(" ");

            static REGEX_SET: LazyLock<RegexSet> = LazyLock::new(|| {
                RegexSet::new([
                    r"^HELP:",
                    r"^PM:",
                    r"^ASAY:",
                    r"^<a",
                    r"^.*/\(.*\) : ",
                    r"^.*/\(.*\) added note ",
                    r"^.*/\(.*\) removed a note ",
                    r"^.*/\(.*\) has added ",
                    r"^.*/\(.*\) has edited ",
                    r#"^[^:]*/\(.*\) ".*""#,
                ])
                .unwrap()
            });

            if REGEX_SET.is_match(&remaining) {
                return censor!("asay/apm/ahelp/notes/etc").into();
            }

            Cow::Borrowed(line)
        }

        "ADMINPRIVATE" => censor!("private logtype").into(),

        "TOPIC" => censor!("world_topic logs").into(),

        "SQL" => censor!("sql logs").into(),

        _ => Cow::Borrowed(line),
    }
}

pub fn process_game_log(contents: String) -> String {
    filter_ips(&contents)
        .lines()
        .map(parse_line)
        .fold(String::new(), |a, b| a + &b + "\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    // The IP regex runs at the file-level filter_ips() pass before parse_line()
    // sees any line, so for these per-line tests we feed already-IP-filtered
    // input (the IP literal substituted with the global "-censored-" token).

    #[test]
    fn access_login_strips_ip_cid_token() {
        // Real format from client_procs.dm:229
        // [ts] ACCESS: Login: ckey from <ip>-<cid> || BYOND v<v>
        let line = "[2026-04-30 16:20:42.301] ACCESS: Login: SomeUser from -censored--2548808841 || BYOND v516.1681";
        let out = parse_line(line);
        assert!(!out.contains("2548808841"), "CID survived: {out}");
        assert!(out.contains("ip/cid"), "expected ip/cid censor token: {out}");
        assert!(out.contains("SomeUser"), "ckey should remain: {out}");
    }

    #[test]
    fn access_logout_kept_verbatim() {
        let line = "[2026-04-30 16:20:42.301] ACCESS: Logout: SomeUser";
        let out = parse_line(line);
        assert_eq!(out, line);
    }

    #[test]
    fn access_failed_login_censored() {
        // [ts] ACCESS: Failed Login: key CID IP - reason
        let line = "[2026-04-30 16:20:42.301] ACCESS: Failed Login: someone 1234567890 -censored- - blacklisted byond version";
        let out = parse_line(line);
        assert!(!out.contains("1234567890"), "CID survived in Failed Login: {out}");
        assert!(out.contains("censored"), "expected censor token: {out}");
    }

    #[test]
    fn access_forced_disconnect_censored() {
        // [ts] ACCESS: Forced disconnect: ckey CID IP - CID randomizer check
        let line = "[2026-04-30 16:20:42.301] ACCESS: Forced disconnect: foo 1234567890 -censored- - CID randomizer check";
        let out = parse_line(line);
        assert!(!out.contains("1234567890"), "CID survived in Forced disconnect: {out}");
        assert!(out.contains("censored"), "expected censor token: {out}");
    }

    #[test]
    fn access_notice_same_ip_id_censored() {
        // [ts] ACCESS: Notice: ckey has the same IP (X) / ID (Y) as other_ckey
        let line = "[2026-04-30 16:20:42.301] ACCESS: Notice: foo has the same ID (1234567890) as bar";
        let out = parse_line(line);
        assert!(!out.contains("1234567890"), "CID survived in Notice: {out}");
        assert!(out.contains("censored"), "expected censor token: {out}");
    }

    #[test]
    fn access_afk_censored() {
        // server_maint.dm:66
        let line = "[2026-04-30 16:20:42.301] ACCESS: AFK: someuser";
        let out = parse_line(line);
        // AFK lines aren't strictly sensitive but default-censor for unknown
        // ACCESS subcategories is the contract.
        assert!(out.contains("censored"), "expected censor token: {out}");
    }

    #[test]
    fn adminprivate_censored() {
        let line = "[2026-04-30 16:20:42.301] ADMINPRIVATE: ASAY: SomeAdmin/(real) ban deliberation";
        let out = parse_line(line);
        assert!(out.contains("private logtype"));
        assert!(!out.contains("real"));
    }
}
