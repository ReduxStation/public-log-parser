use std::{borrow::Cow, sync::LazyLock};

use regex::{Regex, RegexSet};

use super::ip_filtering::filter_ips;

#[tracing::instrument(skip_all)]
pub fn parse_line<'a>(line: &'a str) -> Option<Cow<'a, str>> {
    let line = line.trim();

    if line.is_empty() {
        return None;
    }

    if !line.starts_with('[') {
        return None;
    }

    let Some((timestamp, contents)) = line.split_once(']') else {
        return None;
    };

    static TIMESTAMP_REGEX: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"^([0-9]{2}:[0-9]{2}:[0-9]{2}|[0-9]{2,4}-[0-9]{2,4}-[0-9]{2,4} [0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,3})+)$",
        ).unwrap()
    });
    if !TIMESTAMP_REGEX.is_match(&timestamp[1..]) {
        return None;
    }

    if contents.starts_with(" Starting up round ID ") {
        return Some(Cow::Borrowed(line));
    }

    let mut words = contents.split(' ');
    if words.next() != Some("") {
        return None;
    }

    let log_type = {
        let next_word = words.next().expect("out of words");
        if !next_word.ends_with(':') {
            return None;
        }

        if next_word == "GAME-COMPAT:" {
            match words.next() {
                Some(next_word) => next_word,
                None => return None,
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
                    return None;
                }

                // Drop the IP/CID token entirely. Format from client_procs.dm:
                //   "Login: ckey from <ip>-<cid> || BYOND v<v>"
                // After filter_ips empties the IP, the token at len-4 is "-<cid>";
                // remove it so the rendered line becomes
                //   "Login: ckey from || BYOND v<v>"
                // No "-censored-" placeholder shown.
                let ip_cid_index = words_vec.len() - 4;
                words_vec.remove(ip_cid_index);

                Some(Cow::Owned(format!(
                    "{timestamp}] {log_type} Login: {}",
                    words_vec.join(" ")
                )))
            }

            // Logout lines carry only a ckey, safe to keep verbatim.
            Some("Logout:") => Some(Cow::Borrowed(line)),

            // Anything else under ACCESS is dropped. Variants like
            //   "Failed Login: ckey CID IP - reason"
            //   "Forced disconnect: ckey CID IP - CID randomizer check"
            //   "Notice: ckey has the same IP (X) / ID (Y) as other_ckey"
            //   "AFK: ckey"
            // leak IP and CID in positions we don't have a structured parser
            // for, so they don't appear in public output at all.
            _ => None,
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
                return None;
            }

            Some(Cow::Borrowed(line))
        }

        "ADMINPRIVATE" => None,

        "TOPIC" => None,

        "SQL" => None,

        _ => Some(Cow::Borrowed(line)),
    }
}

pub fn process_game_log(contents: String) -> String {
    filter_ips(&contents)
        .lines()
        .filter_map(parse_line)
        .fold(String::new(), |a, b| a + &b + "\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    // The IP regex runs at the file-level filter_ips() pass before parse_line()
    // sees any line, so for these per-line tests we feed already-IP-filtered
    // input (the IP literal substituted with the empty string).

    #[test]
    fn access_login_strips_ip_cid_token() {
        // Real format from client_procs.dm:229
        // [ts] ACCESS: Login: ckey from <ip>-<cid> || BYOND v<v>
        // After filter_ips empties the IP, what reaches parse_line is:
        let line = "[2026-04-30 16:20:42.301] ACCESS: Login: SomeUser from -2548808841 || BYOND v516.1681";
        let out = parse_line(line).expect("Login lines are kept, with IP/CID dropped");
        assert!(!out.contains("2548808841"), "CID survived: {out}");
        assert!(!out.contains("censored"), "no censor placeholder should appear: {out}");
        assert!(out.contains("SomeUser"), "ckey should remain: {out}");
        assert!(out.contains("BYOND v516.1681"), "BYOND version should remain: {out}");
    }

    #[test]
    fn access_logout_kept_verbatim() {
        let line = "[2026-04-30 16:20:42.301] ACCESS: Logout: SomeUser";
        let out = parse_line(line).expect("Logout lines are kept verbatim");
        assert_eq!(out, line);
    }

    #[test]
    fn access_failed_login_dropped() {
        // [ts] ACCESS: Failed Login: key CID IP - reason
        // Dropped entirely from output.
        let line = "[2026-04-30 16:20:42.301] ACCESS: Failed Login: someone 1234567890 - blacklisted byond version";
        assert!(parse_line(line).is_none(), "Failed Login should be dropped");
    }

    #[test]
    fn access_forced_disconnect_dropped() {
        // [ts] ACCESS: Forced disconnect: ckey CID IP - CID randomizer check
        let line = "[2026-04-30 16:20:42.301] ACCESS: Forced disconnect: foo 1234567890 - CID randomizer check";
        assert!(parse_line(line).is_none(), "Forced disconnect should be dropped");
    }

    #[test]
    fn access_notice_same_ip_id_dropped() {
        // [ts] ACCESS: Notice: ckey has the same IP (X) / ID (Y) as other_ckey
        let line = "[2026-04-30 16:20:42.301] ACCESS: Notice: foo has the same ID (1234567890) as bar";
        assert!(parse_line(line).is_none(), "Notice lines should be dropped");
    }

    #[test]
    fn access_afk_dropped() {
        // server_maint.dm:66
        let line = "[2026-04-30 16:20:42.301] ACCESS: AFK: someuser";
        assert!(parse_line(line).is_none(), "AFK lines should be dropped");
    }

    #[test]
    fn admin_private_dropped() {
        let line = "[2026-04-30 16:20:42.301] ADMINPRIVATE: sensitive admin chatter";
        assert!(parse_line(line).is_none(), "ADMINPRIVATE should be dropped");
    }

    #[test]
    fn topic_dropped() {
        let line = "[2026-04-30 16:20:42.301] TOPIC: world.Topic query?key=value";
        assert!(parse_line(line).is_none(), "TOPIC lines should be dropped");
    }

    #[test]
    fn sql_dropped() {
        let line = "[2026-04-30 16:20:42.301] SQL: SELECT * FROM users WHERE id = 1";
        assert!(parse_line(line).is_none(), "SQL lines should be dropped");
    }

    #[test]
    fn empty_line_dropped() {
        assert!(parse_line("").is_none(), "empty lines are dropped");
        assert!(parse_line("   ").is_none(), "whitespace-only lines are dropped");
    }

    #[test]
    fn malformed_dropped() {
        assert!(parse_line("no leading bracket").is_none());
        assert!(parse_line("[no closing bracket").is_none());
        assert!(parse_line("[bad-timestamp] GAME: something").is_none());
    }

    #[test]
    fn admin_pm_dropped() {
        let line = "[2026-04-30 16:20:42.301] ADMIN: PM: from admin to player: contents";
        assert!(parse_line(line).is_none(), "Admin PM should be dropped");
    }

    #[test]
    fn process_game_log_drops_filtered_lines() {
        let input = concat!(
            "[2026-04-30 16:20:42.301] ACCESS: Login: alice from 1.2.3.4-100 || BYOND v516.1681\n",
            "[2026-04-30 16:20:43.301] ADMINPRIVATE: secret\n",
            "[2026-04-30 16:20:44.301] SQL: SELECT 1\n",
            "[2026-04-30 16:20:45.301] ACCESS: Logout: alice\n",
        );
        let out = process_game_log(input.to_string());
        assert!(out.contains("Login: alice"), "Login should be kept: {out}");
        assert!(out.contains("Logout: alice"), "Logout should be kept: {out}");
        assert!(!out.contains("ADMINPRIVATE"), "ADMINPRIVATE dropped: {out}");
        assert!(!out.contains("SELECT"), "SQL dropped: {out}");
        assert!(!out.contains("1.2.3.4"), "IP filtered: {out}");
        assert!(!out.contains("censored"), "no censor placeholder: {out}");
    }
}
