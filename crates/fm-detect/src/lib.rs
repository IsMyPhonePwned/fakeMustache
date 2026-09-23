//! Entity detectors: structural, contextual, and lexical.

mod contextual;
mod encodings;
mod lexical;
mod validators;

use fm_core::{Confidence, EntityKind, Hit, Profile};

pub use contextual::{
    extract_dumpsys_section, scan_dumpstate_section, split_dumpstate_sections, Section,
};
pub use encodings::scan_with_encodings;
pub use lexical::LexicalDetectors;

pub struct ScanContext<'a> {
    pub member: &'a str,
    pub section: Option<&'a str>,
    pub key_path: Option<&'a str>,
    pub profile: &'a Profile,
}

pub trait Detector: Send + Sync {
    fn kind(&self) -> EntityKind;
    fn prefilter(&self, chunk: &str) -> bool {
        let _ = chunk;
        true
    }
    fn scan(&self, chunk: &str, ctx: &ScanContext<'_>, out: &mut Vec<Hit>);
}

/// Run all default detectors over a text chunk.
pub fn scan_text(chunk: &str, ctx: &ScanContext<'_>) -> Vec<Hit> {
    let mut out = Vec::new();
    // Prefer contextual when section is known
    if let Some(section) = ctx.section {
        contextual::scan_dumpstate_section(chunk, section, ctx, &mut out);
    }
    let lex = LexicalDetectors::default();
    lex.scan_all(chunk, ctx, &mut out);
    // Dedup by (kind, canonical, start)
    out.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then(a.kind.as_str().cmp(b.kind.as_str()))
            .then(a.canonical.cmp(&b.canonical))
    });
    out.dedup_by(|a, b| a.kind == b.kind && a.canonical == b.canonical && a.start == b.start);
    out
}

/// Residual-sensitive scan (all detectors, lowest confidence threshold).
pub fn scan_residual(chunk: &str, ctx: &ScanContext<'_>) -> Vec<Hit> {
    let mut hits = scan_text(chunk, ctx);
    hits.retain(|h| h.confidence >= Confidence::Medium);
    hits
}

/// Structural key_path → EntityKind map (plist/json/sqlite columns).
pub fn kind_from_key_path(key_path: &str) -> Option<EntityKind> {
    let last = key_path.split('.').next_back()?.split('[').next()?.to_ascii_lowercase();
    match last.as_str() {
        "ssid" | "wifi_network_name" => Some(EntityKind::Ssid),
        "bssid" => Some(EntityKind::Bssid),
        "mac" | "mac_address" | "hwaddr" | "hardware_address" => {
            if key_path.to_ascii_lowercase().contains("bluetooth") {
                Some(EntityKind::MacAddress)
            } else {
                Some(EntityKind::MacAddress)
            }
        }
        "address" if key_path.to_ascii_lowercase().contains("bluetooth") => {
            Some(EntityKind::MacAddress)
        }
        "email" | "account_name" | "appleid" | "apple_id" => Some(EntityKind::Email),
        "imei" => Some(EntityKind::Imei),
        "imsi" | "subscriber_id" => Some(EntityKind::Imsi),
        "iccid" => Some(EntityKind::Iccid),
        "phone" | "msisdn" | "phone_number" => Some(EntityKind::PhoneNumber),
        "serial" | "serialnumber" | "serial_number" => Some(EntityKind::SerialNumber),
        "udid" | "ecid" => Some(EntityKind::Udid),
        "latitude" | "longitude" | "lat" | "lon" => Some(EntityKind::GpsCoordinate),
        "package" | "package_name" | "pkg" | "bundleid" | "bundle_id" => {
            Some(EntityKind::PackageName)
        }
        "organization" | "organizationname" => Some(EntityKind::OrganizationName),
        "username" | "user_name" | "owner_name" => Some(EntityKind::UserName),
        _ => None,
    }
}
