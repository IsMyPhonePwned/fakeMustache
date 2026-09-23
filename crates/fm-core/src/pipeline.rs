//! High-level anonymization pipeline orchestration.
//!
//! Format-specific work is injected via callbacks so fm-core stays I/O-light
//! for WASM; native crates wire real handlers.

use crate::audit::{AuditReport, MemberDrop, ResidualFinding};
use crate::entity::{Action, Confidence, EntityKind, EntityTable, Hit, Location};
use crate::error::{Error, Result};
use crate::mapping::Mapping;
use crate::options::{AnonOptions, ArchiveKind, RewriteMode};
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct AnonResult {
    pub output: Vec<u8>,
    pub report: AuditReport,
    pub mapping: Option<Mapping>,
}

#[derive(Clone)]
pub struct InventoryMember {
    pub path: String,
    pub bytes: Vec<u8>,
    pub drop: bool,
    pub drop_reason: Option<String>,
}

/// Pluggable archive backend.
pub trait ArchiveBackend {
    fn detect_kind(&self, input: &[u8]) -> ArchiveKind;
    fn inventory(&self, input: &[u8], opts: &AnonOptions) -> Result<Vec<InventoryMember>>;
    fn repack(&self, members: &[InventoryMember], kind: ArchiveKind) -> Result<Vec<u8>>;
}

/// Pluggable discovery + rewrite over a member's bytes.
pub trait MemberProcessor {
    fn discover(
        &self,
        path: &str,
        bytes: &[u8],
        table: &mut EntityTable,
        opts: &AnonOptions,
    ) -> Result<()>;

    fn rewrite(
        &self,
        path: &str,
        bytes: &[u8],
        mapping: &Mapping,
        opts: &AnonOptions,
    ) -> Result<Vec<u8>>;

    fn residual_scan(
        &self,
        path: &str,
        bytes: &[u8],
        mapping: &Mapping,
        opts: &AnonOptions,
    ) -> Result<Vec<Hit>>;
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

pub fn anonymize_with_backends(
    input: &[u8],
    kind_hint: ArchiveKind,
    opts: &AnonOptions,
    archive: &dyn ArchiveBackend,
    processor: &dyn MemberProcessor,
) -> Result<AnonResult> {
    let profile = opts.effective_profile();
    let kind = match kind_hint {
        ArchiveKind::Auto => archive.detect_kind(input),
        other => other,
    };
    let kind_str = match kind {
        ArchiveKind::AndroidBugreport => "android_bugreport",
        ArchiveKind::AppleSysdiagnose => "apple_sysdiagnose",
        ArchiveKind::Auto => "unknown",
    };

    let input_sha = sha256_hex(input);
    if opts.rewrite_mode == RewriteMode::Encrypt && matches!(opts.key_source, crate::options::KeySource::Random)
    {
        return Err(Error::Other(
            "reversible mode needs --key-file or --passphrase, so the same key can restore the originals"
                .into(),
        ));
    }
    let mut report = AuditReport::new(&profile.name, input_sha.clone(), input.len() as u64, kind_str);
    if profile.is_research() {
        report.warnings.push(
            "RESEARCH PROFILE: output is NOT safe for public release.".into(),
        );
    }
    if opts.rewrite_mode == RewriteMode::Encrypt {
        report.warnings.push(
            "Reversible: private values are fm1 tokens. The same key restores them. Do not ship the key with the archive.".into(),
        );
    }

    let key = opts.resolve_key(input_sha.as_bytes())?;

    // 1. Inventory
    let mut members = archive.inventory(input, opts)?;
    for m in &members {
        if m.drop {
            report.members_dropped.push(MemberDrop {
                path: m.path.clone(),
                bytes: m.bytes.len() as u64,
                reason: m
                    .drop_reason
                    .clone()
                    .unwrap_or_else(|| "policy".into()),
            });
        }
    }

    // 2. Discovery
    let mut table = EntityTable::new();
    for m in members.iter().filter(|m| !m.drop) {
        processor.discover(&m.path, &m.bytes, &mut table, opts)?;
    }

    // Apply policy actions / confidence filter + allowlists
    let min_conf = profile.min_confidence();
    let mut entities = table.into_entities();
    for ent in &mut entities {
        if ent.confidence < min_conf {
            report.warnings.push(format!(
                "low-confidence {:?} candidate skipped: {} occurrence(s)",
                ent.kind, ent.occurrences
            ));
            ent.action = Action::Keep;
            continue;
        }
        ent.action = profile.action_for(ent.kind);
        // Known infrastructure domains stay literal only when the action is pseudo.
        if ent.kind == EntityKind::DomainName
            && ent.action == Action::Pseudo
            && crate::allowlists::should_keep_domain(&ent.canonical)
        {
            ent.action = Action::Keep;
        }
        // Allowlist exception applies only to --pseudo-third-party-packages,
        // not to an explicit package_name=pseudo override.
        if ent.kind == EntityKind::PackageName
            && opts.pseudo_third_party_packages
            && crate::allowlists::should_keep_package(&ent.canonical)
        {
            ent.action = Action::Keep;
        }
    }

    // Summaries
    {
        use std::collections::HashMap;
        let mut counts: HashMap<(EntityKind, Action), u32> = HashMap::new();
        for e in &entities {
            *counts.entry((e.kind, e.action)).or_default() += e.occurrences;
        }
        for ((kind, action), count) in counts {
            report.push_entity(kind, count, action);
        }
    }

    // Declared divergences
    if opts.rewrite_mode != RewriteMode::Encrypt
        && entities
            .iter()
            .any(|e| e.kind == EntityKind::GpsCoordinate && e.action == Action::Drop)
    {
        report
            .declared_divergences
            .push("privacy_parser.location.coordinates".into());
    }
    if matches!(opts.logarchive, crate::options::LogArchivePolicy::Jsonl) {
        report
            .declared_divergences
            .push("logarchive.source_path_jsonl".into());
    } else {
        report
            .declared_divergences
            .push("logarchive.dropped".into());
    }

    // 3. Mapping
    let mapping = Mapping::from_entities_mode(&entities, &key, opts.ordinal, opts.rewrite_mode)?;

    // 4. Rewrite
    for m in members.iter_mut().filter(|m| !m.drop) {
        m.bytes = processor.rewrite(&m.path, &m.bytes, &mapping, opts)?;
    }
    // Remove dropped from repack set
    let kept: Vec<InventoryMember> = members.into_iter().filter(|m| !m.drop).collect();
    let output = archive.repack(&kept, kind)?;

    // 5. Residual scan
    let mut findings = Vec::new();
    for m in &kept {
        let hits = processor.residual_scan(&m.path, &m.bytes, &mapping, opts)?;
        for h in hits {
            if mapping.is_known_pseudonym(&h.value) {
                continue;
            }
            // Kinds the user chose to keep are not leaks.
            if profile.action_for(h.kind) == Action::Keep {
                continue;
            }
            if h.confidence >= Confidence::Medium {
                findings.push(ResidualFinding {
                    kind: h.kind.as_str().to_string(),
                    member: m.path.clone(),
                    confidence: format!("{:?}", h.confidence),
                    snippet_len: h.value.len(),
                });
            }
        }
    }

    if !findings.is_empty() && !profile.is_research() {
        report.residual_scan.status = "failed".into();
        report.residual_scan.findings = findings;
        return Err(Error::ResidualPii(format!(
            "{} residual finding(s); output withheld",
            report.residual_scan.findings.len()
        )));
    }
    if !findings.is_empty() {
        report.residual_scan.status = "warnings".into();
        report.residual_scan.findings = findings;
        report
            .warnings
            .push("residual findings present; research profile continued".into());
    } else {
        report.residual_scan.status = "clean".into();
    }

    report.output.sha256 = sha256_hex(&output);
    report.output.bytes = output.len() as u64;

    Ok(AnonResult {
        output,
        report,
        mapping: if opts.include_mapping {
            Some(mapping)
        } else {
            None
        },
    })
}

/// Placeholder used until format backends are wired; processes plain UTF-8 text blobs.
pub fn anonymize_bytes(
    input: &[u8],
    _kind: ArchiveKind,
    opts: &AnonOptions,
) -> Result<AnonResult> {
    // Minimal text-only path for unit tests / explain stubs
    let input_sha = sha256_hex(input);
    let profile = opts.effective_profile();
    let mut report = AuditReport::new(
        &profile.name,
        input_sha.clone(),
        input.len() as u64,
        "raw_bytes",
    );
    let key = opts.resolve_key(input_sha.as_bytes())?;

    let text = String::from_utf8_lossy(input);
    let mut table = EntityTable::new();
    // Lightweight email discovery for the core path
    for (li, line) in text.lines().enumerate() {
        for email in crude_emails(line) {
            table.insert_hit(
                Hit {
                    kind: EntityKind::Email,
                    value: email.clone(),
                    canonical: email.to_ascii_lowercase(),
                    confidence: Confidence::Medium,
                    start: 0,
                    end: email.len(),
                },
                Location {
                    member: "stdin".into(),
                    section: None,
                    line: Some(li as u32 + 1),
                    key_path: None,
                },
                profile.action_for(EntityKind::Email),
            );
        }
    }
    let mut entities = table.into_entities();
    for e in &mut entities {
        e.action = profile.action_for(e.kind);
        report.push_entity(e.kind, e.occurrences, e.action);
    }
    let mapping = Mapping::from_entities_mode(&entities, &key, opts.ordinal, opts.rewrite_mode)?;
    let out_text = mapping.apply_to_text(&text);
    let output = out_text.into_bytes();
    report.output.sha256 = sha256_hex(&output);
    report.output.bytes = output.len() as u64;
    report.residual_scan.status = "clean".into();

    Ok(AnonResult {
        output,
        report,
        mapping: if opts.include_mapping {
            Some(mapping)
        } else {
            None
        },
    })
}

fn crude_emails(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    for token in line.split_whitespace() {
        let t = token.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '@' && c != '.' && c != '_' && c != '-' && c != '+');
        if t.contains('@') && t.contains('.') && !t.ends_with(".invalid") {
            out.push(t.to_string());
        }
    }
    out
}
