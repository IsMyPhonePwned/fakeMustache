//! Generator format / determinism / injectivity / idempotence (spec §8, §13).

use fm_core::generators::{self, is_pseudonym};
use fm_core::{EntityKind, Key, Pseudonymizer};
use std::collections::HashSet;

fn tag(seed: u8) -> [u8; 32] {
    let mut t = [0u8; 32];
    for (i, b) in t.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8).wrapping_mul(17);
    }
    t
}

fn luhn_ok(digits: &str) -> bool {
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

#[test]
fn all_kinds_deterministic_and_idempotent_where_marked() {
    let kinds = [
        EntityKind::Email,
        EntityKind::DomainName,
        EntityKind::PhoneNumber,
        EntityKind::Imei,
        EntityKind::MacAddress,
        EntityKind::Bssid,
        EntityKind::Ssid,
        EntityKind::Uuid,
        EntityKind::IpV4Public,
        EntityKind::IpV6,
        EntityKind::SerialNumber,
        EntityKind::UserName,
        EntityKind::BluetoothName,
        EntityKind::FilePathLeaf,
        EntityKind::PackageName,
        EntityKind::Url,
    ];
    let originals = [
        "alice@Corp.Example.COM",
        "a.b.evil.com",
        "+14155552671",
        "490154203237518",
        "aa:bb:cc:dd:ee:ff",
        "11:22:33:44:55:66",
        "Home Network",
        "550e8400-e29b-41d4-a716-446655440000",
        "8.8.8.8",
        "2001:4860:4860::8888",
        "AB12-cd34",
        "Alice",
        "Anthony's AirPods",
        "IMG_Amsterdam.jpg",
        "com.evil.app",
        "https://evil.example/path?x=1",
    ];
    for (kind, orig) in kinds.iter().zip(originals.iter()) {
        let t = tag(42);
        let a = generators::generate(*kind, &t, orig);
        let b = generators::generate(*kind, &t, orig);
        assert_eq!(a, b, "{kind:?} not deterministic");
        // Idempotence for kinds with is_pseudonym recognition
        if is_pseudonym(*kind, &a) {
            let again = generators::generate(*kind, &t, &a);
            assert_eq!(a, again, "{kind:?} not idempotent on its own output: {a} → {again}");
        }
    }
}

#[test]
fn imei_mac_ipv4_uuid_phone_shapes() {
    for seed in 0..32u8 {
        let t = tag(seed);
        let imei = generators::imei(&t);
        assert_eq!(imei.len(), 15);
        assert!(luhn_ok(&imei), "bad luhn {imei}");

        let mac = generators::mac(&t);
        assert!(mac.starts_with("02:"));
        assert_eq!(mac.len(), 17);

        let ip = generators::ipv4_docs(&t);
        assert!(
            ip.starts_with("198.51.100.") || ip.starts_with("203.0.113."),
            "{ip}"
        );

        let uuid = generators::uuid_like(&t, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(uuid.as_bytes()[14], b'4'); // version preserved from original when valid
        assert_eq!(uuid.len(), 36);
    }
}

#[test]
fn email_never_resolvable_tld_and_domain_depth() {
    let e = generators::email(&tag(1), "x@a.b.evil.com");
    assert!(e.ends_with(".invalid"));
    assert!(e.starts_with("user-"));
    let d = generators::domain(&tag(1), "a.b.evil.com");
    assert!(d.ends_with(".invalid"));
    // depth preserved roughly via host- prefix for >2 labels
    assert!(d.starts_with("host-") || d.starts_with("corp-"));
}

#[test]
fn phone_preserves_plus_and_length_band() {
    let orig = "+33123456789";
    let p = generators::phone(&tag(3), orig);
    assert!(p.starts_with('+'));
    let od: String = orig.chars().filter(|c| c.is_ascii_digit()).collect();
    let pd: String = p.chars().filter(|c| c.is_ascii_digit()).collect();
    assert_eq!(od.len(), pd.len());
}

#[test]
fn ssid_length_soft_preserve() {
    let orig = "Victim Family WiFi!!";
    let s = generators::ssid(&tag(4), orig);
    assert!(s.starts_with("SSID-"));
    assert_eq!(s.len(), orig.len());
}

#[test]
fn serial_preserves_class_per_position() {
    let orig = "ZYw9-12AB";
    let s = generators::serial(&tag(5), orig);
    assert_eq!(s.len(), orig.len());
    for (a, b) in orig.chars().zip(s.chars()) {
        if a.is_ascii_digit() {
            assert!(b.is_ascii_digit(), "{a}→{b}");
        } else if a.is_ascii_uppercase() {
            assert!(b.is_ascii_uppercase());
        } else if a.is_ascii_lowercase() {
            assert!(b.is_ascii_lowercase());
        } else {
            assert_eq!(a, b);
        }
    }
}

#[test]
fn path_leaf_keeps_extension() {
    let s = generators::generate(EntityKind::FilePathLeaf, &tag(6), "secret_photo.apk");
    assert!(s.ends_with(".apk"));
    assert!(s.starts_with("file-"));
}

#[test]
fn bluetooth_preserves_product_hint() {
    let s = generators::generate(EntityKind::BluetoothName, &tag(7), "Anthony's AirPods Pro");
    assert!(s.contains("AirPods"));
    assert!(s.starts_with("BT-Device-"));
}

#[test]
fn injectivity_across_thousand_inputs_same_kind() {
    let key = Key::from_bytes([99u8; 32]);
    let p = Pseudonymizer::new(key);
    let mut seen = HashSet::new();
    for i in 0..1000 {
        let email = format!("user{i}@example.com");
        let pseudo = p.generate(EntityKind::Email, &email);
        assert!(seen.insert(pseudo), "collision at {i}");
    }
}

#[test]
fn hmac_not_keyless_hash_different_keys_diverge() {
    let a = Pseudonymizer::new(Key::from_bytes([1u8; 32]));
    let b = Pseudonymizer::new(Key::from_bytes([2u8; 32]));
    let phone = "+15551234567";
    assert_ne!(
        a.generate(EntityKind::PhoneNumber, phone),
        b.generate(EntityKind::PhoneNumber, phone)
    );
}
