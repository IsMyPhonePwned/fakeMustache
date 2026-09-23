//! Detector positive / negative fixtures (spec §7, §13).

use fm_core::{load_bundled_profile, Confidence, EntityKind, ProfileName};
use fm_detect::{
    extract_dumpsys_section, scan_text, scan_with_encodings, split_dumpstate_sections, ScanContext,
};

fn ctx<'a>(profile: &'a fm_core::Profile, section: Option<&'a str>) -> ScanContext<'a> {
    ScanContext {
        member: "test",
        section,
        key_path: None,
        profile,
    }
}

fn kinds(hits: &[fm_core::Hit]) -> Vec<EntityKind> {
    let mut v: Vec<_> = hits.iter().map(|h| h.kind).collect();
    v.sort_by_key(|k| k.as_str());
    v.dedup();
    v
}

#[test]
fn email_positive_and_rejects_retina_asset() {
    let p = load_bundled_profile(ProfileName::Balanced).unwrap();
    let c = ctx(&p, None);
    let hits = scan_text("contact alice@corp.example.com please", &c);
    assert!(hits.iter().any(|h| h.kind == EntityKind::Email && h.canonical.contains("alice@")));

    let hits = scan_text("icon foo@2x.png in assets", &c);
    assert!(
        !hits.iter().any(|h| h.kind == EntityKind::Email && h.value.contains("@2x")),
        "retina @2x must not be email"
    );
}

#[test]
fn email_already_pseudo_not_redetected_as_actionable() {
    let p = load_bundled_profile(ProfileName::Balanced).unwrap();
    let c = ctx(&p, None);
    let hits = scan_text("user-aabbccdd@example.invalid", &c);
    assert!(
        !hits.iter().any(|h| h.kind == EntityKind::Email),
        "pseudonym emails must be ignored for re-pseudonymization"
    );
}

#[test]
fn imei_requires_luhn_and_gains_confidence_in_telephony() {
    let p = load_bundled_profile(ProfileName::Balanced).unwrap();
    // Valid Luhn IMEI used in canary
    let valid = "490154203237518";
    let c_low = ctx(&p, None);
    let hits = scan_text(&format!("id={valid}"), &c_low);
    assert!(hits.iter().any(|h| h.kind == EntityKind::Imei && h.value == valid));

    let invalid = "490154203237519"; // bad check digit
    let hits = scan_text(&format!("id={invalid}"), &c_low);
    assert!(!hits.iter().any(|h| h.kind == EntityKind::Imei && h.value == invalid));

    let c_hi = ctx(&p, Some("DUMP OF SERVICE iphonesubinfo:"));
    let hits = scan_text(&format!("IMEI: {valid}"), &c_hi);
    let imei = hits.iter().find(|h| h.kind == EntityKind::Imei).unwrap();
    assert_eq!(imei.confidence, Confidence::High);
}

#[test]
fn mac_rejects_broadcast_and_all_zero() {
    let p = load_bundled_profile(ProfileName::Balanced).unwrap();
    let c = ctx(&p, Some("DUMP OF SERVICE wifi:"));
    assert!(!scan_text("BSSID ff:ff:ff:ff:ff:ff", &c)
        .iter()
        .any(|h| matches!(h.kind, EntityKind::MacAddress | EntityKind::Bssid)
            && h.canonical.contains("ff:ff")));
    assert!(!scan_text("BSSID 00:00:00:00:00:00", &c)
        .iter()
        .any(|h| matches!(h.kind, EntityKind::MacAddress | EntityKind::Bssid)));
}

#[test]
fn mac_in_wifi_section_is_bssid_high_confidence() {
    let p = load_bundled_profile(ProfileName::Balanced).unwrap();
    let c = ctx(&p, Some("wifi"));
    let hits = scan_text("BSSID aa:bb:cc:dd:ee:ff", &c);
    assert!(hits.iter().any(|h| h.kind == EntityKind::Bssid && h.confidence >= Confidence::Medium));
}

#[test]
fn ipv4_version_context_rejected_private_kept_as_private() {
    let p = load_bundled_profile(ProfileName::Balanced).unwrap();
    let c = ctx(&p, None);
    let hits = scan_text("app version 1.2.3.4 released", &c);
    assert!(
        !hits.iter().any(|h| matches!(h.kind, EntityKind::IpV4Public | EntityKind::IpV4Private)),
        "version-prefixed dotted quads must not be IPs"
    );

    let hits = scan_text("addr 192.168.1.50", &c);
    assert!(hits.iter().any(|h| h.kind == EntityKind::IpV4Private));

    let hits = scan_text("addr 8.8.8.8", &c);
    assert!(hits.iter().any(|h| h.kind == EntityKind::IpV4Public));
}

#[test]
fn gps_needs_four_decimals_and_valid_ranges() {
    let p = load_bundled_profile(ProfileName::Balanced).unwrap();
    let c = ctx(&p, Some("location"));
    assert!(scan_text("52.392128,4.902320", &c)
        .iter()
        .any(|h| h.kind == EntityKind::GpsCoordinate));
    // Too few decimals
    assert!(!scan_text("52.39,4.90", &c)
        .iter()
        .any(|h| h.kind == EntityKind::GpsCoordinate));
    // Out of range
    assert!(!scan_text("91.000000,4.902320", &c)
        .iter()
        .any(|h| h.kind == EntityKind::GpsCoordinate));
}

#[test]
fn contextual_account_user_wifi_location_bluetooth() {
    let text = r#"
DUMP OF SERVICE account:
Account {name=victim@corp.example.com, type=com.google}

DUMP OF SERVICE user:
UserInfo{0:Alice Victim:13}
Owner name: Alice Victim

DUMP OF SERVICE wifi:
SSID: "Victim Family WiFi"
BSSID aa:bb:cc:dd:ee:ff

DUMP OF SERVICE location:
{fused, 52.392128,4.902320±14.69m, Bundle}

DUMP OF SERVICE bluetooth_manager:
name: "Anthony's AirPods"

DUMP OF SERVICE package:
Package [com.evil.stalkerware]
installerPackageName=com.android.vending
"#;
    let secs = split_dumpstate_sections(text);
    assert!(secs.len() >= 5);

    let account = extract_dumpsys_section(text, "account").unwrap();
    assert!(account.contains("victim@corp.example.com"));

    let p = load_bundled_profile(ProfileName::Balanced).unwrap();
    let mut all = Vec::new();
    for sec in &secs {
        let c = ctx(&p, Some(&sec.name));
        all.extend(scan_text(&sec.body, &c));
    }
    let k = kinds(&all);
    assert!(k.contains(&EntityKind::Email));
    assert!(k.contains(&EntityKind::UserName));
    assert!(k.contains(&EntityKind::Ssid));
    assert!(k.contains(&EntityKind::Bssid));
    assert!(k.contains(&EntityKind::GpsCoordinate));
    assert!(k.contains(&EntityKind::BluetoothName));
    assert!(k.contains(&EntityKind::PackageName));
}

#[test]
fn url_encoded_and_base64_surface_forms_discovered() {
    let p = load_bundled_profile(ProfileName::Balanced).unwrap();
    let c = ctx(&p, None);

    let hits = scan_with_encodings("param=victim.user%40corp.example.com", &c);
    assert!(
        hits.iter().any(|h| h.kind == EntityKind::Email),
        "URL-encoded email must be found: {:?}",
        hits
    );

    // base64 of "mail me at leak@example.com now!!" (padded)
    let b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        b"mail me at leak@example.com now!!",
    );
    assert!(b64.len() >= 16);
    let hits = scan_with_encodings(&format!("blob={b64}"), &c);
    assert!(
        hits.iter().any(|h| h.kind == EntityKind::Email && h.canonical.contains("leak@")),
        "base64-embedded email must be found: {:?}",
        hits
    );
}

#[test]
fn section_splitter_parity_ends_at_next_dump_or_dashes() {
    let content = "DUMP OF SERVICE account:\nA\n------\nDUMP OF SERVICE wifi:\nB\n";
    let account = extract_dumpsys_section(content, "account").unwrap();
    assert!(account.contains('A'));
    assert!(!account.contains("DUMP OF SERVICE wifi"));
}
