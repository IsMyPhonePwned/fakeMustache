//! Android bugreport-specific wiring.

use fm_container::DefaultArchiveBackend;
use fm_core::{
    pipeline::{anonymize_with_backends, AnonResult, MemberProcessor},
    AnonOptions, ArchiveKind, EntityTable, Hit, Mapping, Result,
};
use fm_detect::{scan_residual, ScanContext};
use fm_format::HandlerSet;

pub struct AndroidProcessor {
    handlers: HandlerSet,
}

impl Default for AndroidProcessor {
    fn default() -> Self {
        Self {
            handlers: HandlerSet::default(),
        }
    }
}

impl MemberProcessor for AndroidProcessor {
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
        hits.retain(|h| !h.value.contains("<redacted>"));
        Ok(hits)
    }
}

pub fn anonymize_bugreport(input: &[u8], opts: &AnonOptions) -> Result<AnonResult> {
    anonymize_with_backends(
        input,
        ArchiveKind::AndroidBugreport,
        opts,
        &DefaultArchiveBackend,
        &AndroidProcessor::default(),
    )
}

/// Explain decisions without writing output.
pub fn explain_bugreport(input: &[u8], opts: &AnonOptions) -> Result<String> {
    let archive = DefaultArchiveBackend;
    let members = fm_core::pipeline::ArchiveBackend::inventory(&archive, input, opts)?;
    let mut out = String::new();
    out.push_str(&opts.format_entity_policy());
    out.push_str("\n\nmembers:\n");
    for m in &members {
        if m.drop {
            out.push_str(&format!(
                "  DROP {} ({} bytes) — {}\n",
                m.path,
                m.bytes.len(),
                m.drop_reason.as_deref().unwrap_or("policy")
            ));
        } else {
            out.push_str(&format!("  KEEP {} ({} bytes)\n", m.path, m.bytes.len()));
        }
    }
    let mut table = EntityTable::new();
    let proc = AndroidProcessor::default();
    for m in members.iter().filter(|m| !m.drop) {
        proc.discover(&m.path, &m.bytes, &mut table, opts)?;
    }
    out.push_str("\nentities:\n");
    let profile = opts.effective_profile();
    for e in table.iter() {
        let action = profile.action_for(e.kind);
        out.push_str(&format!(
            "  {:?} x{} → {:?} (confidence {:?})\n",
            e.kind, e.occurrences, action, e.confidence
        ));
    }
    Ok(out)
}
