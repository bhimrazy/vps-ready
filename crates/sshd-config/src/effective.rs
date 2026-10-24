//! The output of `sshd -T`.

use std::collections::BTreeMap;

use serde::Serialize;

/// The output of `sshd -T`: lowercase keywords mapped to their values.
/// Keywords that can repeat (`listenaddress`, `hostkey`, ...) keep every value
/// in order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct SshdConfig(BTreeMap<String, Vec<String>>);

impl SshdConfig {
    /// Parses `sshd -T` output. Lines are `keyword value...`; blank lines are
    /// skipped.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let (key, value) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
            map.entry(key.to_ascii_lowercase())
                .or_default()
                .push(value.trim().to_owned());
        }
        Self(map)
    }

    /// The first value of `key` (lowercase), e.g. `get("passwordauthentication")`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key)?.first().map(String::as_str)
    }

    /// Every value of a repeatable `key`, in order.
    #[must_use]
    pub fn get_all(&self, key: &str) -> &[String] {
        self.0.get(key).map_or(&[], Vec::as_slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_repeated_keys() {
        let config = SshdConfig::parse(
            "port 22\nlistenaddress [::]:22\nlistenaddress 0.0.0.0:22\n\nbanner none\nflagonly\n",
        );
        assert_eq!(config.get("port"), Some("22"));
        assert_eq!(config.get_all("listenaddress"), ["[::]:22", "0.0.0.0:22"]);
        assert_eq!(config.get("flagonly"), Some(""));
        assert_eq!(config.get("missing"), None);
        assert!(config.get_all("missing").is_empty());
    }

    proptest::proptest! {
        #[test]
        fn never_panics(s in "\\PC*") {
            let _ = SshdConfig::parse(&s);
        }
    }
}
