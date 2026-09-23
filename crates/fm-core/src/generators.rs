//! Format-preserving pseudonym generators.

use crate::entity::EntityKind;
use hex::encode as hex_encode;

pub fn generate(kind: EntityKind, tag: &[u8; 32], original: &str) -> String {
    match kind {
        EntityKind::Email => email(tag, original),
        EntityKind::DomainName => domain(tag, original),
        EntityKind::PhoneNumber => phone(tag, original),
        EntityKind::Imei => imei(tag),
        EntityKind::Imsi | EntityKind::Iccid => digits_preserve_len(tag, original),
        EntityKind::MacAddress | EntityKind::Bssid => mac(tag),
        EntityKind::Ssid => ssid(tag, original),
        EntityKind::Uuid | EntityKind::ContainerUuid | EntityKind::AndroidId => {
            uuid_like(tag, original)
        }
        EntityKind::Udid => udid(tag, original),
        EntityKind::IpV4Public => ipv4_docs(tag),
        EntityKind::IpV6 => ipv6_docs(tag),
        EntityKind::SerialNumber => serial(tag, original),
        EntityKind::PersonName | EntityKind::UserName => format!("User-{}", hex8(tag)),
        EntityKind::OrganizationName => format!("Org-{}", hex8(tag)),
        EntityKind::BluetoothName => bt_name(tag, original),
        EntityKind::FilePathLeaf => path_leaf(tag, original),
        EntityKind::PackageName => format!("com.anon.pkg{}", hex8(tag)),
        EntityKind::Url => url(tag, original),
        EntityKind::GpsCoordinate => "<redacted>".to_string(),
        EntityKind::CellId => "0".to_string(),
        EntityKind::IpV4Private => original.to_string(), // keep — topology
        EntityKind::Timestamp | EntityKind::Carrier | EntityKind::Other => original.to_string(),
    }
}

/// `--generalize-carrier`: keep the country (MCC) and drop the operator.
/// Named brands have no reliable country table here, so they become `carrier`.
pub fn generalize_carrier(value: &str) -> String {
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    let numeric = value
        .chars()
        .all(|c| c.is_ascii_digit() || c == '-' || c == ' ');
    if numeric && (5..=6).contains(&digits.len()) {
        return format!("mcc-{}", &digits[..3]);
    }
    "carrier".to_string()
}

fn hex8(tag: &[u8; 32]) -> String {
    hex_encode(&tag[..4])
}

fn hex4(tag: &[u8; 32]) -> String {
    hex_encode(&tag[..2])
}

fn hex_n(tag: &[u8; 32], n: usize) -> String {
    hex_encode(&tag[..n.min(16)])
}

/// Email → user-<8hex>@<domainpseudo>. Domain mapped separately via DomainName kind when split.
pub fn email(tag: &[u8; 32], original: &str) -> String {
    let (local_tag, domain_part) = if let Some((local, domain)) = original.split_once('@') {
        let _ = local;
        let domain_pseudo = domain_from_original(tag, domain);
        (tag, domain_pseudo)
    } else {
        (tag, format!("corp-{}.invalid", hex4(tag)))
    };
    // Idempotence: already a fakemustache email
    if original.ends_with("@example.invalid") || original.contains("@corp-") && original.ends_with(".invalid") {
        if original.starts_with("user-") {
            return original.to_string();
        }
    }
    format!("user-{}@{}", hex8(local_tag), domain_part)
}

fn domain_from_original(tag: &[u8; 32], domain: &str) -> String {
    if domain == "example.invalid" || domain.ends_with(".invalid") {
        return domain.to_string();
    }
    // Preserve registrable-domain / subdomain split depth
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() <= 1 {
        return format!("host-{}.invalid", hex8(tag));
    }
    // Map parent consistently: use tag bytes 8..12 for parent, 0..4 for host
    let parent = format!("corp-{}.invalid", hex_encode(&tag[8..10]));
    if labels.len() == 2 {
        parent
    } else {
        // Keep extra label count as host-<hex>.corp-xxxx.invalid
        format!("host-{}.{}", hex8(tag), parent)
    }
}

pub fn domain(tag: &[u8; 32], original: &str) -> String {
    if original.ends_with(".invalid") && (original.starts_with("host-") || original.starts_with("corp-"))
    {
        return original.to_string();
    }
    domain_from_original(tag, original)
}

pub fn phone(tag: &[u8; 32], original: &str) -> String {
    let has_plus = original.starts_with('+');
    let digits: String = original.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return format!("+15550{}", &hex8(tag)[..7]);
    }
    // Preserve country-code length heuristically: 1–3 digits after +
    let (cc, rest_len) = if has_plus {
        if digits.len() > 10 {
            let cc_len = digits.len() - 10;
            let cc_len = cc_len.clamp(1, 3);
            (&digits[..cc_len], digits.len() - cc_len)
        } else {
            ("1", digits.len().saturating_sub(1))
        }
    } else {
        ("", digits.len())
    };
    let mut out_digits = String::new();
    // Reserved 555 prefix
    let material = hex_encode(tag);
    let digit_material: String = material
        .chars()
        .filter_map(|c| c.to_digit(16).map(|d| char::from_digit(d % 10, 10).unwrap()))
        .collect();
    if !cc.is_empty() {
        out_digits.push_str(cc);
    }
    // Insert 555 after country code when length allows
    let need = if cc.is_empty() { rest_len } else { rest_len };
    let mut body = String::from("555");
    for (i, ch) in digit_material.chars().enumerate() {
        if body.len() >= need {
            break;
        }
        if i == 0 {
            continue;
        }
        body.push(ch);
    }
    while body.len() < need {
        body.push('0');
    }
    body.truncate(need);
    out_digits.push_str(&body);
    if has_plus {
        format!("+{out_digits}")
    } else {
        out_digits
    }
}

fn luhn_check_digit(digits14: &[u8]) -> u8 {
    let mut sum = 0u32;
    for (i, &d) in digits14.iter().rev().enumerate() {
        let mut v = d as u32;
        if i % 2 == 0 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    ((10 - (sum % 10)) % 10) as u8
}

pub fn imei(tag: &[u8; 32]) -> String {
    let material = hex_encode(tag);
    let mut digits = Vec::with_capacity(14);
    for c in material.chars() {
        if digits.len() == 14 {
            break;
        }
        if let Some(d) = c.to_digit(16) {
            digits.push((d % 10) as u8);
        }
    }
    while digits.len() < 14 {
        digits.push(0);
    }
    let check = luhn_check_digit(&digits);
    digits.push(check);
    digits.into_iter().map(|d| char::from_digit(d as u32, 10).unwrap()).collect()
}

pub fn digits_preserve_len(tag: &[u8; 32], original: &str) -> String {
    let len = original.chars().filter(|c| c.is_ascii_digit()).count().max(1);
    let material = hex_encode(tag);
    let mut out = String::new();
    for c in material.chars().cycle() {
        if out.len() >= len {
            break;
        }
        if let Some(d) = c.to_digit(16) {
            out.push(char::from_digit(d % 10, 10).unwrap());
        }
    }
    out
}

/// Locally-administered unicast MAC: 02:xx:xx:xx:xx:xx
pub fn mac(tag: &[u8; 32]) -> String {
    format!(
        "02:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        tag[0], tag[1], tag[2], tag[3], tag[4]
    )
}

pub fn ssid(tag: &[u8; 32], original: &str) -> String {
    if original.starts_with("SSID-") {
        return original.to_string();
    }
    let base = format!("SSID-{}", hex4(tag));
    let orig_len = original.len();
    if base.len() == orig_len {
        base
    } else if base.len() < orig_len {
        format!("{base}{}", "X".repeat(orig_len - base.len()))
    } else {
        // Truncate carefully — keep SSID- prefix
        let mut s = base;
        s.truncate(orig_len.max(7));
        s
    }
}

pub fn uuid_like(tag: &[u8; 32], original: &str) -> String {
    // Preserve version nibble if UUID-shaped
    let version = original
        .as_bytes()
        .get(14)
        .copied()
        .filter(|&c| (b'1'..=b'5').contains(&c))
        .unwrap_or(b'4');
    let h = hex_encode(tag);
    // 8-4-4-4-12
    format!(
        "{}-{}-{}{}-{}-{}",
        &h[0..8],
        &h[8..12],
        version as char,
        &h[13..16],
        &h[16..20],
        &h[20..32]
    )
}

pub fn udid(tag: &[u8; 32], original: &str) -> String {
    if original.len() == 40 && original.chars().all(|c| c.is_ascii_hexdigit()) {
        return hex_encode(tag)[..40.min(hex_encode(tag).len())].to_string()
            + &hex_n(tag, 4).repeat(2)[..(40usize.saturating_sub(32))];
    }
    // Simpler: 40 hex from tag repeated
    let h = hex_encode(tag);
    format!("{h}{h}")[..40].to_string()
}

pub fn ipv4_docs(tag: &[u8; 32]) -> String {
    // RFC 5737: 198.51.100.0/24 or 203.0.113.0/24
    let which = tag[0] % 2;
    let host = tag[1];
    if which == 0 {
        format!("198.51.100.{host}")
    } else {
        format!("203.0.113.{host}")
    }
}

pub fn ipv6_docs(tag: &[u8; 32]) -> String {
    // RFC 3849: 2001:db8::/32
    format!(
        "2001:db8::{:x}:{:x}",
        u16::from_be_bytes([tag[0], tag[1]]),
        u16::from_be_bytes([tag[2], tag[3]])
    )
}

pub fn serial(tag: &[u8; 32], original: &str) -> String {
    let h = hex_encode(tag);
    let mut out = String::with_capacity(original.len());
    let mut hi = 0usize;
    for c in original.chars() {
        let replacement = if c.is_ascii_digit() {
            let d = h.as_bytes().get(hi % h.len()).copied().unwrap_or(b'0');
            hi += 1;
            char::from_digit((d as u32 - if d.is_ascii_digit() { b'0' as u32 } else { b'a' as u32 - 10 }) % 10, 10)
                .unwrap_or('0')
        } else if c.is_ascii_uppercase() {
            let d = h.as_bytes().get(hi % h.len()).copied().unwrap_or(b'a');
            hi += 1;
            let v = if d.is_ascii_digit() { d - b'0' } else { 10 + d - b'a' };
            (b'A' + v % 26) as char
        } else if c.is_ascii_lowercase() {
            let d = h.as_bytes().get(hi % h.len()).copied().unwrap_or(b'a');
            hi += 1;
            let v = if d.is_ascii_digit() { d - b'0' } else { 10 + d - b'a' };
            (b'a' + v % 26) as char
        } else {
            c
        };
        out.push(replacement);
    }
    if out.is_empty() {
        hex8(tag)
    } else {
        out
    }
}

fn bt_name(tag: &[u8; 32], original: &str) -> String {
    // Preserve known product type hints
    const PRODUCTS: &[&str] = &[
        "AirPods",
        "AirPods Pro",
        "AirPods Max",
        "Galaxy Buds",
        "Tesla Model 3",
        "Tesla Model Y",
        "Apple Watch",
        "Beats",
    ];
    let hint = PRODUCTS.iter().find(|p| original.contains(*p)).copied();
    match hint {
        Some(p) => format!("BT-Device-{} ({p})", hex4(tag)),
        None => format!("BT-Device-{}", hex4(tag)),
    }
}

fn path_leaf(tag: &[u8; 32], original: &str) -> String {
    let ext = std::path::Path::new(original)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{e}"))
        .unwrap_or_default();
    format!("file-{}{ext}", hex8(tag))
}

fn url(tag: &[u8; 32], original: &str) -> String {
    // Pseudo host, drop path/query
    if let Ok(parsed) = extract_host(original) {
        let host = domain(tag, &parsed);
        if let Some(scheme) = original.split("://").next() {
            if original.contains("://") {
                return format!("{scheme}://{host}/");
            }
        }
        return format!("https://{host}/");
    }
    format!("https://host-{}.invalid/", hex8(tag))
}

fn extract_host(url: &str) -> std::result::Result<String, ()> {
    let rest = url
        .split("://")
        .nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or("");
    let host = rest.split('@').next_back().unwrap_or(rest);
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() {
        Err(())
    } else {
        Ok(host.to_string())
    }
}

/// Returns true if `value` looks like an already-emitted pseudonym for `kind`.
pub fn is_pseudonym(kind: EntityKind, value: &str) -> bool {
    match kind {
        EntityKind::Email => {
            value.ends_with("@example.invalid")
                || (value.starts_with("user-") && value.ends_with(".invalid"))
        }
        EntityKind::DomainName => {
            value.ends_with(".invalid")
                && (value.starts_with("host-") || value.starts_with("corp-") || value.contains(".corp-"))
        }
        EntityKind::Ssid => value.starts_with("SSID-"),
        EntityKind::MacAddress | EntityKind::Bssid => {
            value.starts_with("02:") && value.len() == 17
        }
        EntityKind::UserName | EntityKind::PersonName => value.starts_with("User-"),
        EntityKind::BluetoothName => value.starts_with("BT-Device-"),
        EntityKind::OrganizationName => value.starts_with("Org-"),
        EntityKind::PackageName => value.starts_with("com.anon.pkg"),
        EntityKind::FilePathLeaf => value.starts_with("file-"),
        EntityKind::IpV4Public => {
            value.starts_with("198.51.100.") || value.starts_with("203.0.113.")
        }
        EntityKind::IpV6 => value.starts_with("2001:db8:"),
        EntityKind::GpsCoordinate => value.contains("<redacted>") || value == "<redacted>",
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag_from(seed: u8) -> [u8; 32] {
        let mut t = [seed; 32];
        for (i, b) in t.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        t
    }

    #[test]
    fn imei_is_15_and_luhn() {
        let s = imei(&tag_from(7));
        assert_eq!(s.len(), 15);
        let digits: Vec<u8> = s.chars().map(|c| c.to_digit(10).unwrap() as u8).collect();
        assert_eq!(luhn_check_digit(&digits[..14]), digits[14]);
    }

    #[test]
    fn mac_is_locally_administered() {
        let m = mac(&tag_from(1));
        assert!(m.starts_with("02:"));
        assert_eq!(m.len(), 17);
    }

    #[test]
    fn email_uses_invalid_tld() {
        let e = email(&tag_from(2), "alice@corp.example.com");
        assert!(e.ends_with(".invalid"));
        assert!(e.starts_with("user-"));
    }

    #[test]
    fn generators_deterministic() {
        let t = tag_from(9);
        assert_eq!(imei(&t), imei(&t));
        assert_eq!(mac(&t), mac(&t));
        assert_eq!(email(&t, "a@b.com"), email(&t, "a@b.com"));
    }

    #[test]
    fn serial_preserves_length_and_class() {
        let s = serial(&tag_from(3), "AB12-cd34");
        assert_eq!(s.len(), "AB12-cd34".len());
        assert!(s.chars().next().unwrap().is_ascii_uppercase());
    }
}
