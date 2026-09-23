use crate::entity::{Action, EntityKind};
use crate::error::Result;
use crate::key::Key;
use crate::policy::{load_bundled_profile, Profile, ProfileName};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveKind {
    Auto,
    AndroidBugreport,
    AppleSysdiagnose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogArchivePolicy {
    Drop,
    Jsonl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RewriteMode {
    /// Irreversible format-preserving pseudonyms. Default.
    #[default]
    Pseudonym,
    /// Replace each private value with an `fm1.` token that the same key can open.
    Encrypt,
}

#[derive(Debug, Clone)]
pub enum KeySource {
    Random,
    Bytes([u8; 32]),
    Passphrase(String),
    File(PathBuf),
}

#[derive(Debug, Clone)]
pub struct AnonOptions {
    pub profile: Profile,
    pub key_source: KeySource,
    pub rewrite_mode: RewriteMode,
    pub logarchive: LogArchivePolicy,
    pub ordinal: bool,
    pub time_shift: Option<Duration>,
    pub keep_location: bool,
    pub keep_cell_ids: bool,
    pub generalize_carrier: bool,
    pub drop_carrier: bool,
    pub pseudo_third_party_packages: bool,
    pub drop_text_from_packages: Vec<String>,
    /// When set, kinds not in this set are forced to `keep` (before explicit overrides).
    pub only_kinds: Option<HashSet<EntityKind>>,
    /// Highest-precedence per-kind action. Wins over the profile and `--only`.
    pub entity_overrides: HashMap<EntityKind, Action>,
    pub include_mapping: bool,
    pub vault_passphrase: Option<String>,
}

impl Default for AnonOptions {
    fn default() -> Self {
        Self {
            profile: load_bundled_profile(ProfileName::Balanced)
                .expect("bundled balanced profile"),
            key_source: KeySource::Random,
            rewrite_mode: RewriteMode::Pseudonym,
            logarchive: LogArchivePolicy::Drop,
            ordinal: false,
            time_shift: None,
            keep_location: false,
            keep_cell_ids: false,
            generalize_carrier: false,
            drop_carrier: false,
            pseudo_third_party_packages: false,
            drop_text_from_packages: Vec::new(),
            only_kinds: None,
            entity_overrides: HashMap::new(),
            include_mapping: false,
            vault_passphrase: None,
        }
    }
}

impl AnonOptions {
    pub fn builder() -> AnonOptionsBuilder {
        AnonOptionsBuilder {
            inner: Self::default(),
        }
    }

    pub fn resolve_key(&self, archive_id: &[u8]) -> Result<Key> {
        match &self.key_source {
            KeySource::Random => Key::random(),
            KeySource::Bytes(b) => Ok(Key::from_bytes(*b)),
            KeySource::Passphrase(p) => {
                // Reversible mode must open with the passphrase alone, not the
                // original archive hash (the recipient of a restore does not have it).
                let salt = if self.rewrite_mode == RewriteMode::Encrypt {
                    b"fakemustache-reversible-v1".as_slice()
                } else {
                    archive_id
                };
                Key::from_passphrase(p, salt)
            }
            KeySource::File(path) => Key::from_file(path),
        }
    }

    pub fn effective_profile(&self) -> Profile {
        let mut p = self.profile.clone();
        if self.keep_location {
            p.entity_actions
                .insert(crate::entity::EntityKind::GpsCoordinate, crate::entity::Action::Keep);
        }
        if self.keep_cell_ids {
            p.entity_actions
                .insert(crate::entity::EntityKind::CellId, crate::entity::Action::Keep);
        }
        if self.drop_carrier {
            p.entity_actions
                .insert(crate::entity::EntityKind::Carrier, crate::entity::Action::Drop);
        } else if self.generalize_carrier {
            p.entity_actions.insert(
                crate::entity::EntityKind::Carrier,
                crate::entity::Action::Generalize,
            );
        }
        if self.pseudo_third_party_packages {
            p.entity_actions
                .insert(crate::entity::EntityKind::PackageName, crate::entity::Action::Pseudo);
        }
        if self.time_shift.is_some() {
            p.entity_actions
                .insert(crate::entity::EntityKind::Timestamp, crate::entity::Action::Shift);
        }
        if let Some(only) = &self.only_kinds {
            for kind in EntityKind::all() {
                if !only.contains(kind) {
                    p.entity_actions.insert(*kind, Action::Keep);
                }
            }
        }
        for (kind, action) in &self.entity_overrides {
            p.entity_actions.insert(*kind, *action);
        }
        p
    }

    /// Human-readable table of the action each kind will receive.
    pub fn format_entity_policy(&self) -> String {
        let profile = self.effective_profile();
        let mut lines = vec![format!("profile: {}", profile.name)];
        if let Some(only) = &self.only_kinds {
            let mut names: Vec<_> = only.iter().map(|k| k.as_str()).collect();
            names.sort_unstable();
            lines.push(format!("only: {}", names.join(",")));
        }
        lines.push("kind                 action".into());
        for kind in EntityKind::all() {
            let action = profile.action_for(*kind);
            let marker = if self.entity_overrides.contains_key(kind) {
                "  (override)"
            } else if self
                .only_kinds
                .as_ref()
                .is_some_and(|only| !only.contains(kind))
            {
                "  (outside --only)"
            } else {
                ""
            };
            lines.push(format!("  {:<20} {}{marker}", kind.as_str(), action.as_str()));
        }
        lines.join("\n")
    }

    pub fn apply_only_spec(&mut self, spec: &str) -> Result<()> {
        let kinds = crate::selection::parse_kind_list(spec)?;
        self.only_kinds = Some(kinds.into_iter().collect());
        Ok(())
    }

    pub fn apply_entity_spec(&mut self, spec: &str) -> Result<()> {
        for (kind, action) in crate::selection::parse_entity_spec(spec)? {
            self.entity_overrides.insert(kind, action);
        }
        Ok(())
    }
}

pub struct AnonOptionsBuilder {
    inner: AnonOptions,
}

impl AnonOptionsBuilder {
    pub fn profile(mut self, name: ProfileName) -> Self {
        self.inner.profile = load_bundled_profile(name).expect("profile");
        self
    }

    pub fn key(mut self, key: Key) -> Self {
        self.inner.key_source = KeySource::Bytes(*key.as_bytes());
        self
    }

    pub fn key_source(mut self, src: KeySource) -> Self {
        self.inner.key_source = src;
        self
    }

    pub fn logarchive(mut self, p: LogArchivePolicy) -> Self {
        self.inner.logarchive = p;
        self
    }

    pub fn ordinal(mut self, v: bool) -> Self {
        self.inner.ordinal = v;
        self
    }

    pub fn time_shift(mut self, d: Duration) -> Self {
        self.inner.time_shift = Some(d);
        self
    }

    pub fn keep_location(mut self, v: bool) -> Self {
        self.inner.keep_location = v;
        self
    }

    pub fn include_mapping(mut self, v: bool) -> Self {
        self.inner.include_mapping = v;
        self
    }

    pub fn build(self) -> AnonOptions {
        self.inner
    }
}
