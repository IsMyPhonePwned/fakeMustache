use crate::FormatHandler;
use fm_core::{AnonOptions, EntityTable, Error, Location, Mapping, Result};
use fm_detect::{kind_from_key_path, ScanContext};
use fm_core::{Confidence, EntityKind, Hit};

pub struct PlistHandler;

impl FormatHandler for PlistHandler {
    fn can_handle(&self, path: &str, magic: &[u8]) -> bool {
        let p = path.to_ascii_lowercase();
        p.ends_with(".plist")
            || magic.starts_with(b"bplist")
            || (magic.starts_with(b"<?xml") && p.contains("plist"))
    }

    fn discover(
        &self,
        path: &str,
        bytes: &[u8],
        table: &mut EntityTable,
        opts: &AnonOptions,
    ) -> Result<()> {
        let value: plist::Value =
            plist::from_bytes(bytes).map_err(|e| Error::Parse(format!("plist {path}: {e}")))?;
        let profile = opts.effective_profile();
        walk_discover(&value, "", path, &profile, table);
        Ok(())
    }

    fn rewrite(
        &self,
        path: &str,
        bytes: &[u8],
        map: &Mapping,
        _opts: &AnonOptions,
    ) -> Result<Vec<u8>> {
        let was_binary = bytes.starts_with(b"bplist");
        let mut value: plist::Value =
            plist::from_bytes(bytes).map_err(|e| Error::Parse(format!("plist {path}: {e}")))?;
        walk_rewrite(&mut value, "", map);
        let mut out = Vec::new();
        if was_binary {
            plist::to_writer_binary(&mut out, &value)
                .map_err(|e| Error::Parse(format!("plist write: {e}")))?;
        } else {
            plist::to_writer_xml(&mut out, &value)
                .map_err(|e| Error::Parse(format!("plist write: {e}")))?;
        }
        Ok(out)
    }
}

fn walk_discover(
    value: &plist::Value,
    key_path: &str,
    member: &str,
    profile: &fm_core::Profile,
    table: &mut EntityTable,
) {
    match value {
        plist::Value::String(s) => {
            if let Some(kind) = kind_from_key_path(key_path) {
                table.insert_hit(
                    Hit {
                        kind,
                        value: s.clone(),
                        canonical: canonicalize(kind, s),
                        confidence: Confidence::High,
                        start: 0,
                        end: s.len(),
                    },
                    Location {
                        member: member.to_string(),
                        section: None,
                        line: None,
                        key_path: Some(key_path.to_string()),
                    },
                    profile.action_for(kind),
                );
            } else {
                let ctx = ScanContext {
                    member,
                    section: None,
                    key_path: Some(key_path),
                    profile,
                };
                for hit in fm_detect::scan_text(s, &ctx) {
                    table.insert_hit(
                        hit,
                        Location {
                            member: member.to_string(),
                            section: None,
                            line: None,
                            key_path: Some(key_path.to_string()),
                        },
                        profile.action_for(EntityKind::Email),
                    );
                }
            }
        }
        plist::Value::Dictionary(dict) => {
            for (k, v) in dict.iter() {
                let kp = if key_path.is_empty() {
                    k.clone()
                } else {
                    format!("{key_path}.{k}")
                };
                walk_discover(v, &kp, member, profile, table);
            }
        }
        plist::Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                let kp = format!("{key_path}[{i}]");
                walk_discover(v, &kp, member, profile, table);
            }
        }
        _ => {}
    }
}

fn walk_rewrite(value: &mut plist::Value, key_path: &str, map: &Mapping) {
    match value {
        plist::Value::String(s) => {
            if let Some(rep) = map.replace_surface(s) {
                *s = rep.to_string();
            } else {
                *s = map.apply_to_text(s);
            }
        }
        plist::Value::Dictionary(dict) => {
            // Collect keys to avoid borrow issues
            let keys: Vec<String> = dict.keys().cloned().collect();
            for k in keys {
                let kp = if key_path.is_empty() {
                    k.clone()
                } else {
                    format!("{key_path}.{k}")
                };
                if let Some(v) = dict.get_mut(&k) {
                    walk_rewrite(v, &kp, map);
                }
            }
        }
        plist::Value::Array(arr) => {
            for (i, v) in arr.iter_mut().enumerate() {
                walk_rewrite(v, &format!("{key_path}[{i}]"), map);
            }
        }
        _ => {}
    }
}

fn canonicalize(kind: EntityKind, s: &str) -> String {
    match kind {
        EntityKind::Email | EntityKind::MacAddress | EntityKind::Bssid | EntityKind::Uuid => {
            s.to_ascii_lowercase()
        }
        _ => s.to_string(),
    }
}
