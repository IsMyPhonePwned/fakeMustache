use crate::validators::{
    entity_already_pseudo, is_nonsensical_mac, is_private_ipv4, looks_like_version_context,
    luhn_valid, valid_gps_pair, valid_ipv4, valid_mac,
};
use crate::ScanContext;
use fm_core::{generators, Confidence, EntityKind, Hit};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct LexicalDetectors {
    email: Regex,
    imei: Regex,
    mac: Regex,
    ipv4: Regex,
    uuid: Regex,
    gps: Regex,
    phone: Regex,
}

impl Default for LexicalDetectors {
    fn default() -> Self {
        Self {
            email: Regex::new(
                r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b",
            )
            .unwrap(),
            imei: Regex::new(r"\b\d{15}\b").unwrap(),
            mac: Regex::new(r"(?i)\b([0-9a-f]{2}:){5}[0-9a-f]{2}\b").unwrap(),
            ipv4: Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
                .unwrap(),
            uuid: Regex::new(
                r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
            )
            .unwrap(),
            gps: Regex::new(r"(-?\d{1,3}\.\d{4,})\s*,\s*(-?\d{1,3}\.\d{4,})").unwrap(),
            phone: Regex::new(r"\+\d[\d\-() ]{7,}\d").unwrap(),
        }
    }
}

impl LexicalDetectors {
    pub fn scan_all(&self, chunk: &str, ctx: &ScanContext<'_>, out: &mut Vec<Hit>) {
        self.scan_emails(chunk, ctx, out);
        self.scan_imei(chunk, ctx, out);
        self.scan_mac(chunk, ctx, out);
        self.scan_ipv4(chunk, ctx, out);
        self.scan_uuid(chunk, ctx, out);
        self.scan_gps(chunk, ctx, out);
        self.scan_phone(chunk, ctx, out);
    }

    fn conf(&self, base: Confidence, ctx: &ScanContext<'_>) -> Confidence {
        if ctx.section.is_some() || ctx.key_path.is_some() {
            std::cmp::max(Confidence::High, base)
        } else {
            base
        }
    }

    fn scan_emails(&self, chunk: &str, ctx: &ScanContext<'_>, out: &mut Vec<Hit>) {
        for m in self.email.find_iter(chunk) {
            let v = m.as_str();
            if v.contains("@2x") || v.ends_with(".invalid") {
                continue;
            }
            if entity_already_pseudo(EntityKind::Email, v) {
                continue;
            }
            // Reject retina-ish foo@2x.png handled above; reject if no real TLD-ish
            out.push(Hit {
                kind: EntityKind::Email,
                value: v.to_string(),
                canonical: v.to_ascii_lowercase(),
                confidence: self.conf(Confidence::Low, ctx),
                start: m.start(),
                end: m.end(),
            });
        }
    }

    fn scan_imei(&self, chunk: &str, ctx: &ScanContext<'_>, out: &mut Vec<Hit>) {
        for m in self.imei.find_iter(chunk) {
            let v = m.as_str();
            if !luhn_valid(v) {
                continue;
            }
            let line_start = chunk[..m.start()].rfind('\n').map(|i| i + 1).unwrap_or(0);
            let line = &chunk[line_start..m.end().min(chunk.len())];
            // Reject timestamp-ish contexts loosely
            if line.contains(':') && line.matches(':').count() >= 2 && !ctx.section.map(|s| s.contains("telephony") || s.contains("iphonesubinfo")).unwrap_or(false) {
                // still allow if section is telephony
            }
            let conf = if ctx
                .section
                .map(|s| s.contains("telephony") || s.contains("iphonesubinfo") || s.contains("radio"))
                .unwrap_or(false)
            {
                Confidence::High
            } else {
                Confidence::Low
            };
            out.push(Hit {
                kind: EntityKind::Imei,
                value: v.to_string(),
                canonical: v.to_string(),
                confidence: conf,
                start: m.start(),
                end: m.end(),
            });
        }
    }

    fn scan_mac(&self, chunk: &str, ctx: &ScanContext<'_>, out: &mut Vec<Hit>) {
        for m in self.mac.find_iter(chunk) {
            let v = m.as_str();
            if entity_already_pseudo(EntityKind::MacAddress, v) {
                continue;
            }
            if is_nonsensical_mac(v) {
                continue;
            }
            if !valid_mac(v) {
                // Allow time-like digit-only MACs only in network context — never broadcast/zero
                let net = ctx.section.map(|s| {
                    let l = s.to_ascii_lowercase();
                    l.contains("wifi") || l.contains("bluetooth") || l.contains("net")
                }).unwrap_or(false);
                if !net {
                    continue;
                }
            }
            let kind = if ctx
                .section
                .map(|s| s.to_ascii_lowercase().contains("wifi"))
                .unwrap_or(false)
            {
                EntityKind::Bssid
            } else {
                EntityKind::MacAddress
            };
            out.push(Hit {
                kind,
                value: v.to_string(),
                canonical: v.to_ascii_lowercase(),
                confidence: self.conf(Confidence::Medium, ctx),
                start: m.start(),
                end: m.end(),
            });
        }
    }

    fn scan_ipv4(&self, chunk: &str, ctx: &ScanContext<'_>, out: &mut Vec<Hit>) {
        for m in self.ipv4.find_iter(chunk) {
            let v = m.as_str();
            if !valid_ipv4(v) {
                continue;
            }
            if generators::is_pseudonym(EntityKind::IpV4Public, v) {
                continue;
            }
            let line_start = chunk[..m.start()].rfind('\n').map(|i| i + 1).unwrap_or(0);
            let line = &chunk[line_start..];
            if looks_like_version_context(line, m.start() - line_start) {
                continue;
            }
            let kind = if is_private_ipv4(v) {
                EntityKind::IpV4Private
            } else {
                EntityKind::IpV4Public
            };
            out.push(Hit {
                kind,
                value: v.to_string(),
                canonical: v.to_string(),
                confidence: self.conf(Confidence::Low, ctx),
                start: m.start(),
                end: m.end(),
            });
        }
    }

    fn scan_uuid(&self, chunk: &str, ctx: &ScanContext<'_>, out: &mut Vec<Hit>) {
        for m in self.uuid.find_iter(chunk) {
            let v = m.as_str();
            let kind = if chunk[m.start().saturating_sub(40)..m.start()]
                .to_ascii_lowercase()
                .contains("containers")
            {
                EntityKind::ContainerUuid
            } else {
                EntityKind::Uuid
            };
            out.push(Hit {
                kind,
                value: v.to_string(),
                canonical: v.to_ascii_lowercase(),
                confidence: self.conf(Confidence::Medium, ctx),
                start: m.start(),
                end: m.end(),
            });
        }
    }

    fn scan_gps(&self, chunk: &str, ctx: &ScanContext<'_>, out: &mut Vec<Hit>) {
        for m in self.gps.captures_iter(chunk) {
            let full = m.get(0).unwrap();
            let lat: f64 = m.get(1).unwrap().as_str().parse().unwrap_or(999.0);
            let lon: f64 = m.get(2).unwrap().as_str().parse().unwrap_or(999.0);
            if !valid_gps_pair(lat, lon) {
                continue;
            }
            let conf = if ctx
                .section
                .map(|s| s.contains("location"))
                .unwrap_or(false)
            {
                Confidence::High
            } else {
                Confidence::Medium
            };
            out.push(Hit {
                kind: EntityKind::GpsCoordinate,
                value: full.as_str().to_string(),
                canonical: format!("{lat},{lon}"),
                confidence: conf,
                start: full.start(),
                end: full.end(),
            });
        }
    }

    fn scan_phone(&self, chunk: &str, ctx: &ScanContext<'_>, out: &mut Vec<Hit>) {
        for m in self.phone.find_iter(chunk) {
            let v = m.as_str();
            let digits: String = v.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() < 8 || digits.len() > 15 {
                continue;
            }
            // Skip 555 already-pseudo-ish
            if digits.contains("555") && v.starts_with('+') {
                // could be ours; still ok to skip mid residual
            }
            let conf = if ctx.section.is_some() {
                Confidence::Medium
            } else {
                Confidence::Low
            };
            out.push(Hit {
                kind: EntityKind::PhoneNumber,
                value: v.to_string(),
                canonical: format!("+{digits}"),
                confidence: conf,
                start: m.start(),
                end: m.end(),
            });
        }
    }
}

// silence unused lazy if any
#[allow(dead_code)]
static _UNUSED: Lazy<()> = Lazy::new(|| ());
