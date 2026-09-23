use crate::FormatHandler;
use fm_core::{AnonOptions, EntityTable, Error, Location, Mapping, Result};
use fm_detect::{scan_text, ScanContext};
use serde_json::Value;

pub struct IpsHandler;

impl FormatHandler for IpsHandler {
    fn can_handle(&self, path: &str, _magic: &[u8]) -> bool {
        let p = path.to_ascii_lowercase();
        p.ends_with(".ips") || p.ends_with(".panic") || p.contains("tombstone")
    }

    fn discover(
        &self,
        path: &str,
        bytes: &[u8],
        table: &mut EntityTable,
        opts: &AnonOptions,
    ) -> Result<()> {
        let text = match std::str::from_utf8(bytes) {
            Ok(text) => text,
            // Some tombstone/ANR members are binary. Keep them; do not abort the archive.
            Err(_) => return Ok(()),
        };
        let profile = opts.effective_profile();
        let ctx = ScanContext {
            member: path,
            section: Some("ips"),
            key_path: None,
            profile: &profile,
        };
        // .ips: first line JSON header, rest JSON body (or text for tombstones)
        for hit in scan_text(text, &ctx) {
            // Keep crash evidence fields — only act on identity kinds
            if matches!(
                hit.kind,
                fm_core::EntityKind::Email
                    | fm_core::EntityKind::UserName
                    | fm_core::EntityKind::ContainerUuid
                    | fm_core::EntityKind::FilePathLeaf
                    | fm_core::EntityKind::PhoneNumber
            ) {
                let action = profile.action_for(hit.kind);
                table.insert_hit(
                    hit,
                    Location {
                        member: path.to_string(),
                        section: Some("ips".into()),
                        line: None,
                        key_path: None,
                    },
                    action,
                );
            }
        }
        Ok(())
    }

    fn rewrite(
        &self,
        path: &str,
        bytes: &[u8],
        map: &Mapping,
        _opts: &AnonOptions,
    ) -> Result<Vec<u8>> {
        let text = match std::str::from_utf8(bytes) {
            Ok(text) => text,
            Err(_) => return Ok(bytes.to_vec()),
        };

        // Try JSON header + body
        if let Some((first, rest)) = text.split_once('\n') {
            if let (Ok(mut header), Ok(mut body)) = (
                serde_json::from_str::<Value>(first),
                serde_json::from_str::<Value>(rest),
            ) {
                rewrite_json_value(&mut header, map);
                rewrite_json_value(&mut body, map);
                let h = serde_json::to_string(&header).map_err(|e| Error::Parse(e.to_string()))?;
                let b = serde_json::to_string(&body).map_err(|e| Error::Parse(e.to_string()))?;
                return Ok(format!("{h}\n{b}").into_bytes());
            }
        }

        // Tombstone / ANR: drop hexdump blocks that still hold originals, then pseudonymize the rest.
        let dropped = drop_memory_near_blocks_with_pii(text, map);
        let out = map.apply_to_text(&dropped);
        let _ = path;
        Ok(out.into_bytes())
    }
}

fn rewrite_json_value(v: &mut Value, map: &Mapping) {
    match v {
        Value::String(s) => {
            *s = map.apply_to_text(s);
        }
        Value::Array(arr) => {
            for x in arr {
                rewrite_json_value(x, map);
            }
        }
        Value::Object(obj) => {
            // Keep evidence keys untouched if they're crash mechanics — still safe to apply mapping
            // since mapping only has PII surfaces
            for (_k, val) in obj.iter_mut() {
                rewrite_json_value(val, map);
            }
        }
        _ => {}
    }
}

fn drop_memory_near_blocks_with_pii(text: &str, map: &Mapping) -> String {
    // If a "memory near" block would still contain an original surface, drop the block
    let mut out = String::new();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        if line.to_ascii_lowercase().contains("memory near") {
            let mut block = vec![line.to_string()];
            while let Some(l) = lines.peek() {
                if l.starts_with(' ') || l.starts_with('\t') || l.contains(':') && l.len() > 20 {
                    block.push(lines.next().unwrap().to_string());
                } else {
                    break;
                }
            }
            let block_text = block.join("\n");
            let has_original = map.entries().iter().any(|e| {
                e.surface_forms.iter().any(|s| block_text.contains(s.as_str()))
                    || block_text.contains(&e.original)
            });
            if has_original {
                out.push_str("memory near <hexdump dropped: contained PII>\n");
            } else {
                out.push_str(&block_text);
                out.push('\n');
            }
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}
