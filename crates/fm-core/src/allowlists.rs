//! Package allowlist for --pseudo-third-party-packages.

use std::collections::HashSet;
use std::sync::OnceLock;

pub fn known_packages() -> &'static HashSet<String> {
    static SET: OnceLock<HashSet<String>> = OnceLock::new();
    SET.get_or_init(|| {
        include_str!("../../../policy/allowlists/packages.txt")
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|s| s.to_string())
            .collect()
    })
}

pub fn should_keep_package(name: &str) -> bool {
    known_packages().contains(name)
        || name.starts_with("com.android.")
        || name.starts_with("com.google.android.")
        || name.starts_with("android.")
        || name.starts_with("com.anon.pkg")
}

pub fn known_domains() -> &'static HashSet<String> {
    static SET: OnceLock<HashSet<String>> = OnceLock::new();
    SET.get_or_init(|| {
        include_str!("../../../policy/allowlists/domains.txt")
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|s| s.to_string())
            .collect()
    })
}

pub fn should_keep_domain(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    known_domains().iter().any(|d| host == *d || host.ends_with(&format!(".{d}")))
}
