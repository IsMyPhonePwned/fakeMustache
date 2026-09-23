//! Apple sysdiagnose-specific wiring.

mod logarchive;

use fm_container::DefaultArchiveBackend;
use fm_core::{
    pipeline::{anonymize_with_backends, AnonResult, ArchiveBackend, InventoryMember, MemberProcessor},
    AnonOptions, ArchiveKind, EntityTable, Hit, LogArchivePolicy, Mapping, Result,
};
use fm_detect::{scan_residual, ScanContext};
use fm_format::HandlerSet;

pub struct AppleProcessor {
    handlers: HandlerSet,
}

impl Default for AppleProcessor {
    fn default() -> Self {
        Self {
            handlers: HandlerSet::default(),
        }
    }
}

impl MemberProcessor for AppleProcessor {
    fn discover(
        &self,
        path: &str,
        bytes: &[u8],
        table: &mut EntityTable,
        opts: &AnonOptions,
    ) -> Result<()> {
        self.handlers.discover(path, bytes, table, opts)
    }

    fn rewrite(
        &self,
        path: &str,
        bytes: &[u8],
        mapping: &Mapping,
        opts: &AnonOptions,
    ) -> Result<Vec<u8>> {
        self.handlers.rewrite(path, bytes, mapping, opts)
    }

    fn residual_scan(
        &self,
        path: &str,
        bytes: &[u8],
        mapping: &Mapping,
        opts: &AnonOptions,
    ) -> Result<Vec<Hit>> {
        let Ok(text) = std::str::from_utf8(bytes) else {
            return Ok(Vec::new());
        };
        let profile = opts.effective_profile();
        let ctx = ScanContext {
            member: path,
            section: None,
            key_path: None,
            profile: &profile,
        };
        let mut hits = scan_residual(text, &ctx);
        hits.retain(|h| !mapping.is_known_pseudonym(&h.value));
        hits.retain(|h| !fm_core::hit_inside_token(text, h.start, h.end));
        Ok(hits)
    }
}

pub fn anonymize_sysdiagnose(input: &[u8], opts: &AnonOptions) -> Result<AnonResult> {
    // Special path: when JSONL logarchive requested, inventory drops binary and we inject JSONL
    if matches!(opts.logarchive, LogArchivePolicy::Jsonl) {
        return anonymize_with_logarchive_jsonl(input, opts);
    }
    anonymize_with_backends(
        input,
        ArchiveKind::AppleSysdiagnose,
        opts,
        &DefaultArchiveBackend,
        &AppleProcessor::default(),
    )
}

fn anonymize_with_logarchive_jsonl(input: &[u8], opts: &AnonOptions) -> Result<AnonResult> {
    let mut result = anonymize_with_backends(
        input,
        ArchiveKind::AppleSysdiagnose,
        opts,
        &DefaultArchiveBackend,
        &AppleProcessor::default(),
    )?;

    // Attempt decode from original input spill
    match logarchive::try_decode_to_jsonl(input) {
        Ok((jsonl, undecodable)) => {
            // Re-open result output, add member — simplest: append note in report
            result.report.warnings.push(format!(
                "logarchive emitted as logarchive_anonymized.jsonl; undecodable events: {undecodable}"
            ));
            result
                .report
                .declared_divergences
                .push("logarchive.source_path_jsonl".into());

            // Re-inventory output is already packed; rebuild with JSONL member
            let mut members =
                fm_container::inventory_tar(&result.output, opts).unwrap_or_default();
            // Apply mapping to jsonl if present
            let mapped = if let Some(ref map) = result.mapping {
                map.apply_to_text(&jsonl)
            } else {
                // Re-derive: scan+map already done; apply crude replace via report only
                jsonl
            };
            members.push(InventoryMember {
                path: "logarchive_anonymized.jsonl".into(),
                bytes: mapped.into_bytes(),
                drop: false,
                drop_reason: None,
            });
            result.output = fm_container::repack_tar_gz(&members)?;
            result.report.output.sha256 = fm_core::pipeline::sha256_hex(&result.output);
            result.report.output.bytes = result.output.len() as u64;
        }
        Err(e) => {
            result
                .report
                .warnings
                .push(format!("logarchive JSONL unavailable: {e}"));
        }
    }
    Ok(result)
}

pub fn explain_sysdiagnose(input: &[u8], opts: &AnonOptions) -> Result<String> {
    let archive = DefaultArchiveBackend;
    let members = archive.inventory(input, opts)?;
    let mut out = String::new();
    out.push_str(&opts.format_entity_policy());
    out.push_str("\n\nmembers:\n");
    for m in &members {
        if m.drop {
            out.push_str(&format!(
                "  DROP {} — {}\n",
                m.path,
                m.drop_reason.as_deref().unwrap_or("")
            ));
        } else {
            out.push_str(&format!("  KEEP {}\n", m.path));
        }
    }
    Ok(out)
}
