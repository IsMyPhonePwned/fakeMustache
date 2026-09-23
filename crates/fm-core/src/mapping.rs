use crate::entity::{Action, Entity, EntityKind};
use crate::error::{Error, Result};
use crate::generators::{self, is_pseudonym};
use crate::key::Key;
use crate::options::RewriteMode;
use crate::pseudonym::Pseudonymizer;
use crate::seal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingEntry {
    pub kind: EntityKind,
    pub original: String,
    pub replacement: String,
    pub action: Action,
    pub surface_forms: Vec<String>,
}

/// original surface → replacement (encoding-aware replacements stored per surface in rewrite).
#[derive(Debug, Default, Clone)]
pub struct Mapping {
    /// canonical → replacement
    by_canonical: HashMap<(EntityKind, String), String>,
    /// every surface form → replacement (possibly re-encoded)
    by_surface: HashMap<String, String>,
    entries: Vec<MappingEntry>,
    ordinal_counters: HashMap<EntityKind, u32>,
}

impl Mapping {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_entities(entities: &[Entity], key: &Key, ordinal: bool) -> Result<Self> {
        Self::from_entities_mode(entities, key, ordinal, RewriteMode::Pseudonym)
    }

    pub fn from_entities_mode(
        entities: &[Entity],
        key: &Key,
        ordinal: bool,
        mode: RewriteMode,
    ) -> Result<Self> {
        let mut mapping = Self::new();
        let mut assigned: HashMap<(EntityKind, String), String> = HashMap::new();

        // Stable order for ordinal: by first_seen member/line then canonical
        let mut sorted: Vec<&Entity> = entities.iter().collect();
        sorted.sort_by(|a, b| {
            a.first_seen
                .member
                .cmp(&b.first_seen.member)
                .then(a.first_seen.line.unwrap_or(0).cmp(&b.first_seen.line.unwrap_or(0)))
                .then(a.canonical.cmp(&b.canonical))
        });

        let pseudo = Pseudonymizer::new(key.clone());

        for ent in sorted {
            match ent.action {
                Action::Keep => continue,
                Action::Drop | Action::Generalize | Action::Shift | Action::Pseudo => {}
            }

            if ent.action == Action::Keep {
                continue;
            }

            if mode == RewriteMode::Encrypt && ent.action != Action::Shift {
                let mut first = None;
                for surface in &ent.surface_forms {
                    if surface.is_empty() {
                        continue;
                    }
                    let token = seal::seal(key, surface)?;
                    if first.is_none() {
                        first = Some(token.clone());
                    }
                    mapping.by_surface.insert(surface.clone(), token);
                }
                let canonical_token = seal::seal(key, &ent.canonical)?;
                mapping
                    .by_canonical
                    .insert((ent.kind, ent.canonical.clone()), canonical_token.clone());
                mapping.entries.push(MappingEntry {
                    kind: ent.kind,
                    original: ent.canonical.clone(),
                    replacement: first.unwrap_or(canonical_token),
                    action: ent.action,
                    surface_forms: ent.surface_forms.clone(),
                });
                continue;
            }

            let replacement = if ent.action == Action::Drop {
                match ent.kind {
                    EntityKind::GpsCoordinate => {
                        // Handled by format-aware rewrite_gps_drop (preserves ±accuracy).
                        // Do not string-replace surfaces here.
                        continue;
                    }
                    EntityKind::CellId => "0".to_string(),
                    EntityKind::Url => {
                        generators::generate(ent.kind, &pseudo.tag(ent.kind, &ent.canonical), &ent.canonical)
                    }
                    _ => String::new(),
                }
            } else if ent.action == Action::Generalize && ent.kind == EntityKind::Carrier {
                generators::generalize_carrier(&ent.canonical)
            } else if ordinal
                && matches!(
                    ent.kind,
                    EntityKind::UserName
                        | EntityKind::PersonName
                        | EntityKind::Ssid
                        | EntityKind::Email
                )
            {
                let n = mapping.ordinal_counters.entry(ent.kind).or_insert(0);
                *n += 1;
                match ent.kind {
                    EntityKind::Email => format!("user-{n}@example.invalid"),
                    EntityKind::Ssid => format!("SSID-{n}"),
                    _ => format!("User-{n}"),
                }
            } else {
                let mut tag = pseudo.tag(ent.kind, &ent.canonical);
                let mut candidate = generators::generate(ent.kind, &tag, &ent.canonical);
                // Collision detection: extend tag on conflict
                let mut extend = 0u8;
                while assigned
                    .values()
                    .any(|v| v == &candidate)
                    && assigned
                        .iter()
                        .any(|((k, c), _)| *k == ent.kind && c != &ent.canonical && assigned.get(&(*k, c.clone())) == Some(&candidate))
                {
                    extend = extend.wrapping_add(1);
                    tag[31] ^= extend;
                    candidate = generators::generate(ent.kind, &tag, &ent.canonical);
                    if extend == 255 {
                        return Err(Error::Other(format!(
                            "pseudonym collision for {:?}",
                            ent.kind
                        )));
                    }
                }
                // Simpler collision check against same-kind replacements
                loop {
                    let clash = assigned.iter().any(|((k, c), v)| {
                        *k == ent.kind && *c != ent.canonical && *v == candidate
                    });
                    if !clash {
                        break;
                    }
                    extend = extend.wrapping_add(1);
                    tag[31] ^= extend;
                    candidate = generators::generate(ent.kind, &tag, &ent.canonical);
                    if extend == 255 {
                        return Err(Error::Other("pseudonym collision".into()));
                    }
                }
                candidate
            };

            assigned.insert((ent.kind, ent.canonical.clone()), replacement.clone());
            mapping
                .by_canonical
                .insert((ent.kind, ent.canonical.clone()), replacement.clone());

            for surface in &ent.surface_forms {
                let rep = reencode_surface(surface, &ent.canonical, &replacement);
                mapping.by_surface.insert(surface.clone(), rep);
            }

            mapping.entries.push(MappingEntry {
                kind: ent.kind,
                original: ent.canonical.clone(),
                replacement: replacement.clone(),
                action: ent.action,
                surface_forms: ent.surface_forms.clone(),
            });
        }

        Ok(mapping)
    }

    pub fn replace_surface(&self, surface: &str) -> Option<&str> {
        self.by_surface.get(surface).map(|s| s.as_str())
    }

    pub fn replacement_for(&self, kind: EntityKind, canonical: &str) -> Option<&str> {
        self.by_canonical
            .get(&(kind, canonical.to_string()))
            .map(|s| s.as_str())
    }

    pub fn entries(&self) -> &[MappingEntry] {
        &self.entries
    }

    pub fn apply_to_text(&self, text: &str) -> String {
        // Longest-first replacement to avoid partial overlaps
        let mut pairs: Vec<(&String, &String)> = self.by_surface.iter().collect();
        pairs.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        let mut out = text.to_string();
        for (orig, rep) in pairs {
            if orig.is_empty() {
                continue;
            }
            out = out.replace(orig.as_str(), rep.as_str());
        }
        out
    }

    /// True if value is a known replacement (for residual scan allowlist).
    pub fn is_known_pseudonym(&self, value: &str) -> bool {
        self.by_surface.values().any(|v| v == value)
            || self.by_canonical.values().any(|v| v == value)
            || seal::is_token(value)
            || is_pseudonym(EntityKind::Email, value)
            || is_pseudonym(EntityKind::MacAddress, value)
            || is_pseudonym(EntityKind::Ssid, value)
            || is_pseudonym(EntityKind::DomainName, value)
            || is_pseudonym(EntityKind::IpV4Public, value)
            || is_pseudonym(EntityKind::UserName, value)
            || is_pseudonym(EntityKind::PackageName, value)
    }
}

fn reencode_surface(surface: &str, canonical: &str, replacement: &str) -> String {
    if surface == canonical {
        return replacement.to_string();
    }
    // URL-encoded form
    if surface.contains('%') {
        return urlencoding_encode(replacement);
    }
    // Simple case fold
    if surface.eq_ignore_ascii_case(canonical) && surface != canonical {
        if surface.chars().all(|c| !c.is_ascii_alphabetic() || c.is_ascii_uppercase()) {
            return replacement.to_ascii_uppercase();
        }
        return replacement.to_ascii_lowercase();
    }
    replacement.to_string()
}

fn urlencoding_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{Confidence, Location};

    #[test]
    fn mapping_is_deterministic() {
        let key = Key::from_bytes([42u8; 32]);
        let ent = Entity {
            kind: EntityKind::Email,
            canonical: "a@b.com".into(),
            surface_forms: vec!["a@b.com".into(), "a%40b.com".into()],
            occurrences: 2,
            first_seen: Location {
                member: "x".into(),
                section: None,
                line: Some(1),
                key_path: None,
            },
            confidence: Confidence::High,
            action: Action::Pseudo,
        };
        let m1 = Mapping::from_entities(&[ent.clone()], &key, false).unwrap();
        let m2 = Mapping::from_entities(&[ent], &key, false).unwrap();
        assert_eq!(
            m1.replacement_for(EntityKind::Email, "a@b.com"),
            m2.replacement_for(EntityKind::Email, "a@b.com")
        );
    }
}
