use fm_core::EntityKind;
use once_cell::sync::Lazy;
use regex::Regex;

pub fn luhn_valid(digits: &str) -> bool {
    let ds: Vec<u32> = digits.chars().filter_map(|c| c.to_digit(10)).collect();
    if ds.len() != 15 {
        return false;
    }
    let mut sum = 0u32;
    for (i, &d) in ds.iter().rev().enumerate() {
        let mut v = d;
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum % 10 == 0
}

pub fn valid_ipv4(s: &str) -> bool {
    let parts: Vec<_> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| {
        p.parse::<u8>().is_ok() && !(p.len() > 1 && p.starts_with('0'))
            || p.parse::<u8>().is_ok()
    })
}

pub fn is_private_ipv4(s: &str) -> bool {
    let parts: Vec<u8> = match s.split('.').map(|p| p.parse()).collect::<Result<Vec<_>, _>>() {
        Ok(p) if p.len() == 4 => p,
        _ => return false,
    };
    matches!(parts[0], 10)
        || (parts[0] == 172 && (16..=31).contains(&parts[1]))
        || (parts[0] == 192 && parts[1] == 168)
        || (parts[0] == 100 && (64..=127).contains(&parts[1])) // CGNAT
        || (parts[0] == 169 && parts[1] == 254)
        || parts[0] == 127
}

pub fn valid_mac(s: &str) -> bool {
    static RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?i)^([0-9a-f]{2}:){5}[0-9a-f]{2}$").unwrap());
    if !RE.is_match(s) {
        return false;
    }
    if is_nonsensical_mac(s) {
        return false;
    }
    // Reject pure time-like if no hex letters — require hex letter a-f or synthetic 02:
    let lower = s.to_ascii_lowercase();
    let has_hex_letter = lower.chars().any(|c| matches!(c, 'a'..='f'));
    has_hex_letter || lower.starts_with("02:")
}

/// All-zero / broadcast — never treat as a device MAC/BSSID.
pub fn is_nonsensical_mac(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower == "00:00:00:00:00:00" || lower == "ff:ff:ff:ff:ff:ff"
}

pub fn valid_gps_pair(lat: f64, lon: f64) -> bool {
    (-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon)
}

pub fn looks_like_version_context(line: &str, ip_start: usize) -> bool {
    let prefix = &line[..ip_start.min(line.len())];
    let lower = prefix.to_ascii_lowercase();
    lower.contains("version") || lower.ends_with('v') || lower.ends_with("v=")
}

pub fn entity_already_pseudo(kind: EntityKind, value: &str) -> bool {
    fm_core::generators::is_pseudonym(kind, value)
}
