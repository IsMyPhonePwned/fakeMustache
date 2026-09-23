use crate::FormatHandler;
use fm_core::{
    Action, AnonOptions, EntityKind, EntityTable, Location, Mapping, Result,
};
use fm_detect::{scan_with_encodings, split_dumpstate_sections, ScanContext};

pub struct TextHandler;

impl FormatHandler for TextHandler {
    fn can_handle(&self, path: &str, magic: &[u8]) -> bool {
        let p = path.to_ascii_lowercase();
        if p.ends_with(".txt")
            || p.ends_with(".log")
            || p.contains("dumpstate")
            || p.contains("bugreport")
        {
            return true;
        }
        // UTF-8 text heuristic
        magic.iter().take(8).all(|&b| b == 0 || b == b'\n' || b == b'\r' || b == b'\t' || (32..=126).contains(&b))
            && std::str::from_utf8(magic).is_ok()
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
            // Magic bytes can look like text while the member is binary.
            Err(_) => return Ok(()),
        };
        let profile = opts.effective_profile();

        if path.contains("dumpstate") || path.contains("bugreport") || text.contains("DUMP OF SERVICE ")
        {
            for sec in split_dumpstate_sections(text) {
                let ctx = ScanContext {
                    member: path,
                    section: Some(&sec.name),
                    key_path: None,
                    profile: &profile,
                };
                for hit in scan_with_encodings(&sec.body, &ctx) {
                    let action = profile.action_for(hit.kind);
                    table.insert_hit(
                        hit,
                        Location {
                            member: path.to_string(),
                            section: Some(sec.name.clone()),
                            line: Some(sec.start_line as u32),
                            key_path: None,
                        },
                        action,
                    );
                }
            }
        } else {
            let ctx = ScanContext {
                member: path,
                section: None,
                key_path: None,
                profile: &profile,
            };
            for hit in scan_with_encodings(text, &ctx) {
                let action = profile.action_for(hit.kind);
                table.insert_hit(
                    hit,
                    Location {
                        member: path.to_string(),
                        section: None,
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
        _path: &str,
        bytes: &[u8],
        map: &Mapping,
        opts: &AnonOptions,
    ) -> Result<Vec<u8>> {
        let text = match std::str::from_utf8(bytes) {
            Ok(text) => text,
            Err(_) => return Ok(bytes.to_vec()),
        };
        // GPS drop is format-aware so ±accuracy survives. Skip it when policy keeps coordinates.
        let drop_gps = opts.rewrite_mode != fm_core::RewriteMode::Encrypt
            && opts.effective_profile().action_for(EntityKind::GpsCoordinate) == Action::Drop;
        let mut out = if drop_gps {
            rewrite_gps_drop(text)
        } else {
            text.to_string()
        };
        out = drop_package_lines(&out, &opts.drop_text_from_packages);
        out = map.apply_to_text(&out);

        if let Some(dur) = opts.time_shift {
            out = crate::time_shift::shift_timestamps_in_text(&out, dur);
        }

        // Preserve exact trailing newline behaviour
        let ends_nl = text.ends_with('\n');
        if ends_nl && !out.ends_with('\n') {
            out.push('\n');
        }
        Ok(out.into_bytes())
    }
}

fn drop_package_lines(text: &str, packages: &[String]) -> String {
    if packages.iter().all(|p| p.is_empty()) {
        return text.to_string();
    }
    let mut out = String::new();
    for line in text.split_inclusive('\n') {
        let body = line.trim_end_matches(['\n', '\r']);
        if packages
            .iter()
            .any(|p| !p.is_empty() && body.contains(p.as_str()))
        {
            out.push_str("<log line dropped>");
            if line.ends_with('\n') {
                out.push('\n');
            }
        } else {
            out.push_str(line);
        }
    }
    out
}

fn rewrite_gps_drop(text: &str) -> String {
    // {fused, 52.392128,4.902320±14.69m → {fused, <redacted>±14.69m
    static RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"\{([^,]+),\s*-?\d+\.\d+\s*,\s*-?\d+\.\d+(±[^,}]*)?").unwrap()
    });
    RE.replace_all(text, |caps: &regex::Captures| {
        let provider = &caps[1];
        let acc = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        format!("{{{provider}, <redacted>{acc}")
    })
    .into_owned()
}

// re-export Action usage silence
#[allow(dead_code)]
fn _action_keep() -> Action {
    Action::Keep
}
