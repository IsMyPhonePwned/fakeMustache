use crate::ScanContext;
use fm_core::{Confidence, EntityKind, Hit};
use once_cell::sync::Lazy;
use regex::Regex;

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub start_line: usize,
    pub body: String,
}

/// Split dumpstate text into DUMP OF SERVICE sections (BEL-compatible boundaries).
pub fn split_dumpstate_sections(content: &str) -> Vec<Section> {
    static START: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?m)^DUMP OF SERVICE ([^:]+):").unwrap());

    let mut sections = Vec::new();
    let matches: Vec<_> = START.find_iter(content).collect();
    for (i, m) in matches.iter().enumerate() {
        let name_cap = START.captures(m.as_str()).unwrap();
        let name = name_cap.get(1).unwrap().as_str().to_string();
        let body_start = m.end();
        let body_end = if i + 1 < matches.len() {
            matches[i + 1].start()
        } else {
            content.len()
        };
        // Also end early on ------ delimiter lines if present before next section
        let body = &content[body_start..body_end];
        let line_no = content[..m.start()].bytes().filter(|&b| b == b'\n').count() + 1;
        sections.push(Section {
            name,
            start_line: line_no,
            body: body.to_string(),
        });
    }
    sections
}

/// Extract a single dumpsys section by service name (parity with BEL AccountParser).
pub fn extract_dumpsys_section(content: &str, service: &str) -> Option<String> {
    let start_marker = format!("DUMP OF SERVICE {service}:");
    let start = content.find(&start_marker)?;
    let after = start + start_marker.len();
    let rest = &content[after..];
    let end_rel = rest
        .find("\nDUMP OF SERVICE ")
        .or_else(|| rest.find("\n------"))
        .unwrap_or(rest.len());
    Some(content[start..after + end_rel].to_string())
}

pub fn scan_dumpstate_section(
    body: &str,
    section_name: &str,
    ctx: &ScanContext<'_>,
    out: &mut Vec<Hit>,
) {
    let lname = section_name.to_ascii_lowercase();
    if lname.contains("account") {
        scan_account(body, out);
    }
    if lname.contains("user") && !lname.contains("usagestats") {
        scan_user(body, out);
    }
    if lname.contains("wifi") {
        scan_wifi(body, out);
    }
    if lname.contains("location") {
        scan_location(body, out);
    }
    if lname.contains("bluetooth") {
        scan_bluetooth(body, out);
    }
    if lname.contains("telephony") || lname.contains("iphonesubinfo") {
        scan_telephony(body, out);
    }
    if lname.contains("package") {
        scan_packages(body, out);
    }
    let _ = ctx;
}

fn scan_packages(body: &str, out: &mut Vec<Hit>) {
    static RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"Package \[([a-zA-Z0-9_./]+)\]").unwrap());
    static INST: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i)(installerPackageName|initiatingPackageName|originatingPackageName)=([a-zA-Z0-9_.]+)").unwrap()
    });
    for m in RE.captures_iter(body) {
        let g = m.get(1).unwrap();
        out.push(Hit {
            kind: EntityKind::PackageName,
            value: g.as_str().to_string(),
            canonical: g.as_str().to_string(),
            confidence: Confidence::High,
            start: g.start(),
            end: g.end(),
        });
    }
    for m in INST.captures_iter(body) {
        let g = m.get(2).unwrap();
        out.push(Hit {
            kind: EntityKind::PackageName,
            value: g.as_str().to_string(),
            canonical: g.as_str().to_string(),
            confidence: Confidence::High,
            start: g.start(),
            end: g.end(),
        });
    }
}

fn scan_account(body: &str, out: &mut Vec<Hit>) {
    static RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"Account \{name=([^,]+), type=([^}]+)\}").unwrap()
    });
    for m in RE.captures_iter(body) {
        let name = m.get(1).unwrap();
        let value = name.as_str().trim().to_string();
        let kind = if value.contains('@') {
            EntityKind::Email
        } else {
            EntityKind::UserName
        };
        out.push(Hit {
            kind,
            value: value.clone(),
            canonical: value.to_ascii_lowercase(),
            confidence: Confidence::High,
            start: name.start(),
            end: name.end(),
        });
    }
}

fn scan_user(body: &str, out: &mut Vec<Hit>) {
    static RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"UserInfo\{\d+:([^:]+):\d+\}").unwrap());
    static OWNER: Lazy<Regex> = Lazy::new(|| Regex::new(r"Owner name:\s*(.+)").unwrap());
    for m in RE.captures_iter(body) {
        let name = m.get(1).unwrap();
        let value = name.as_str().to_string();
        out.push(Hit {
            kind: EntityKind::UserName,
            value: value.clone(),
            canonical: value.clone(),
            confidence: Confidence::High,
            start: name.start(),
            end: name.end(),
        });
    }
    for m in OWNER.captures_iter(body) {
        let name = m.get(1).unwrap();
        let value = name.as_str().trim().to_string();
        out.push(Hit {
            kind: EntityKind::UserName,
            value: value.clone(),
            canonical: value,
            confidence: Confidence::High,
            start: name.start(),
            end: name.end(),
        });
    }
}

fn scan_wifi(body: &str, out: &mut Vec<Hit>) {
    static SSID: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"(?i)SSID:\s*"([^"]+)""#).unwrap());
    static BSSID: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i)\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b").unwrap()
    });
    for m in SSID.captures_iter(body) {
        let g = m.get(1).unwrap();
        let v = g.as_str();
        if v.starts_with("SSID-") {
            continue;
        }
        out.push(Hit {
            kind: EntityKind::Ssid,
            value: v.to_string(),
            canonical: v.to_string(), // SSIDs are case-sensitive
            confidence: Confidence::High,
            start: g.start(),
            end: g.end(),
        });
    }
    for m in BSSID.find_iter(body) {
        let v = m.as_str();
        if v.starts_with("02:")
            || v.eq_ignore_ascii_case("00:00:00:00:00:00")
            || v.eq_ignore_ascii_case("ff:ff:ff:ff:ff:ff")
        {
            continue;
        }
        out.push(Hit {
            kind: EntityKind::Bssid,
            value: v.to_string(),
            canonical: v.to_ascii_lowercase(),
            confidence: Confidence::High,
            start: m.start(),
            end: m.end(),
        });
    }
}

fn scan_location(body: &str, out: &mut Vec<Hit>) {
    // {fused, 52.392128,4.902320±14.69m, ...}
    static RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\{[^,]+,\s*(-?\d+\.\d+)\s*,\s*(-?\d+\.\d+)(±[^,]*)?").unwrap()
    });
    for m in RE.captures_iter(body) {
        let full = m.get(0).unwrap();
        let lat = m.get(1).unwrap().as_str();
        let lon = m.get(2).unwrap().as_str();
        let acc = m.get(3).map(|x| x.as_str()).unwrap_or("");
        out.push(Hit {
            kind: EntityKind::GpsCoordinate,
            value: format!("{lat},{lon}{acc}"),
            canonical: format!("{lat},{lon}"),
            confidence: Confidence::High,
            start: full.start(),
            end: full.end(),
        });
    }
}

fn scan_bluetooth(body: &str, out: &mut Vec<Hit>) {
    static NAME: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"(?i)name:\s*"([^"]+)""#).unwrap());
    for m in NAME.captures_iter(body) {
        let g = m.get(1).unwrap();
        let v = g.as_str();
        if v.starts_with("BT-Device-") {
            continue;
        }
        out.push(Hit {
            kind: EntityKind::BluetoothName,
            value: v.to_string(),
            canonical: v.to_string(),
            confidence: Confidence::High,
            start: g.start(),
            end: g.end(),
        });
    }
}

fn scan_telephony(body: &str, out: &mut Vec<Hit>) {
    static IMEI: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)IMEI[:\s]+(\d{15})").unwrap());
    for m in IMEI.captures_iter(body) {
        let g = m.get(1).unwrap();
        out.push(Hit {
            kind: EntityKind::Imei,
            value: g.as_str().to_string(),
            canonical: g.as_str().to_string(),
            confidence: Confidence::High,
            start: g.start(),
            end: g.end(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_sections_basic() {
        let text = "header\nDUMP OF SERVICE account:\nAccount {name=a@b.com, type=com.google}\nDUMP OF SERVICE wifi:\nSSID: \"Home\"\n";
        let secs = split_dumpstate_sections(text);
        assert_eq!(secs.len(), 2);
        assert_eq!(secs[0].name, "account");
        assert!(extract_dumpsys_section(text, "account").unwrap().contains("a@b.com"));
    }
}
