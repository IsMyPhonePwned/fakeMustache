//! fakeMustache core: entities, policy, pseudonymization, audit, and pipeline types.

pub mod allowlists;
pub mod audit;
pub mod entity;
pub mod error;
pub mod generators;
pub mod key;
pub mod mapping;
pub mod options;
pub mod pipeline;
pub mod policy;
pub mod pseudonym;
pub mod seal;
pub mod selection;
pub mod vault;

pub use audit::{AuditReport, DeclaredDivergence, EntitySummary, MemberDrop};
pub use entity::{Action, Confidence, Entity, EntityKind, EntityTable, Hit, Location};
pub use error::{Error, Result};
pub use key::Key;
pub use mapping::Mapping;
pub use options::{AnonOptions, ArchiveKind, KeySource, LogArchivePolicy, RewriteMode};
pub use pipeline::{anonymize_bytes, AnonResult};
pub use policy::{load_bundled_profile, Profile, ProfileName};
pub use pseudonym::Pseudonymizer;
pub use seal::{hit_inside_token, is_token, open_text, seal};
pub use selection::{parse_entity_spec, parse_kind_list};
