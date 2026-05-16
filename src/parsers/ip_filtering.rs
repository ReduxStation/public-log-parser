use std::{borrow::Cow, sync::LazyLock};

use regex::Regex;

static IP_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]?|[0-9])").unwrap()
});

pub fn filter_ips<'a>(contents: &'a str) -> Cow<'a, str> {
    IP_REGEX.replace_all(contents, "")
}
