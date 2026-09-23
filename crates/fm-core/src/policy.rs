use crate::entity::{Action, EntityKind};
use crate::error::{Error, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileName {
    Strict,
    Balanced,
    Research,
}

impl ProfileName {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Balanced => "balanced",
            Self::Research => "research",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "strict" => Some(Self::Strict),
            "balanced" | "default" => Some(Self::Balanced),
            "research" => Some(Self::Research),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RawProfile {
    profile: RawMeta,
    entity: HashMap<String, RawEntityAction>,
    #[serde(default)]
    section_rule: Vec<RawSectionRule>,
    #[serde(default)]
    member_rule: Vec<RawMemberRule>,
    #[serde(default)]
    unknown_members: Option<RawUnknown>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawMeta {
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct RawEntityAction {
    action: String,
}

#[derive(Debug, Clone, Deserialize)]
struct RawSectionRule {
    #[serde(rename = "match")]
    match_: String,
    #[serde(default)]
    detect: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawMemberRule {
    #[serde(rename = "match")]
    match_: String,
    action: String,
    #[serde(default)]
    reason: String,
}

#[derive(Debug, Clone, Deserialize)]
struct RawUnknown {
    action: String,
}

#[derive(Debug, Clone)]
pub struct SectionRule {
    pub match_pattern: String,
    pub detect: Vec<EntityKind>,
}

#[derive(Debug, Clone)]
pub struct MemberRule {
    pub match_pattern: String,
    pub action: Action,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct Profile {
    pub name: String,
    pub entity_actions: HashMap<EntityKind, Action>,
    pub section_rules: Vec<SectionRule>,
    pub member_rules: Vec<MemberRule>,
    pub unknown_member_action: Action,
}

impl Profile {
    pub fn action_for(&self, kind: EntityKind) -> Action {
        self.entity_actions
            .get(&kind)
            .copied()
            .unwrap_or(Action::Pseudo)
    }

    pub fn is_strict(&self) -> bool {
        self.name == "strict"
    }

    pub fn is_research(&self) -> bool {
        self.name == "research"
    }

    /// Minimum confidence that triggers action.
    pub fn min_confidence(&self) -> crate::entity::Confidence {
        use crate::entity::Confidence;
        match self.name.as_str() {
            "strict" => Confidence::Low,
            "research" => Confidence::Medium,
            _ => Confidence::Medium, // balanced
        }
    }
}

pub fn load_profile_str(toml_str: &str) -> Result<Profile> {
    let raw: RawProfile =
        toml::from_str(toml_str).map_err(|e| Error::Policy(format!("toml: {e}")))?;
    let mut entity_actions = HashMap::new();
    for (k, v) in raw.entity {
        let kind = EntityKind::from_str_lossy(&k)
            .ok_or_else(|| Error::Policy(format!("unknown entity kind: {k}")))?;
        let action = Action::from_str_lossy(&v.action)
            .ok_or_else(|| Error::Policy(format!("unknown action: {}", v.action)))?;
        entity_actions.insert(kind, action);
    }
    let section_rules = raw
        .section_rule
        .into_iter()
        .map(|r| SectionRule {
            match_pattern: r.match_,
            detect: r
                .detect
                .iter()
                .filter_map(|s| EntityKind::from_str_lossy(s))
                .collect(),
        })
        .collect();
    let member_rules = raw
        .member_rule
        .into_iter()
        .map(|r| {
            Ok(MemberRule {
                match_pattern: r.match_,
                action: Action::from_str_lossy(&r.action)
                    .ok_or_else(|| Error::Policy(format!("bad member action: {}", r.action)))?,
                reason: r.reason,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let unknown_member_action = raw
        .unknown_members
        .as_ref()
        .and_then(|u| Action::from_str_lossy(&u.action))
        .unwrap_or(Action::Drop);

    Ok(Profile {
        name: raw.profile.name,
        entity_actions,
        section_rules,
        member_rules,
        unknown_member_action,
    })
}

pub fn load_profile_file(path: &Path) -> Result<Profile> {
    let s = std::fs::read_to_string(path)?;
    load_profile_str(&s)
}

pub fn load_bundled_profile(name: ProfileName) -> Result<Profile> {
    let toml_str = match name {
        ProfileName::Balanced => include_str!("../../../policy/balanced.toml"),
        ProfileName::Strict => include_str!("../../../policy/strict.toml"),
        ProfileName::Research => include_str!("../../../policy/research.toml"),
    };
    load_profile_str(toml_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balanced_loads() {
        let p = load_bundled_profile(ProfileName::Balanced).unwrap();
        assert_eq!(p.name, "balanced");
        assert_eq!(p.action_for(EntityKind::Email), Action::Pseudo);
        assert_eq!(p.action_for(EntityKind::GpsCoordinate), Action::Drop);
        assert_eq!(p.action_for(EntityKind::PackageName), Action::Keep);
    }
}
