//! Parse `--only` lists and `--entity kind=action` overrides.

use crate::entity::{Action, EntityKind};
use crate::error::{Error, Result};
use std::collections::HashSet;

/// Expand a comma-separated list of kinds and group names.
pub fn parse_kind_list(spec: &str) -> Result<Vec<EntityKind>> {
    let mut out = Vec::new();
    for raw in spec.split(|c| c == ',' || c == ' ') {
        let token = raw.trim();
        if token.is_empty() {
            continue;
        }
        out.extend(expand_token(token)?);
    }
    if out.is_empty() {
        return Err(Error::Policy("empty kind list".into()));
    }
    Ok(out)
}

/// `kind=action`, where kind may be a single kind or a group.
pub fn parse_entity_spec(spec: &str) -> Result<Vec<(EntityKind, Action)>> {
    let (kind_s, action_s) = spec.split_once('=').ok_or_else(|| {
        Error::Policy(format!(
            "expected KIND=ACTION, got `{spec}` (example: email=pseudo)"
        ))
    })?;
    let action = Action::from_str_lossy(action_s.trim()).ok_or_else(|| {
        Error::Policy(format!(
            "unknown action `{action_s}` (keep, pseudo, drop, generalize, shift)"
        ))
    })?;
    let kinds = expand_token(kind_s.trim())?;
    Ok(kinds.into_iter().map(|k| (k, action)).collect())
}

pub fn expand_token(token: &str) -> Result<Vec<EntityKind>> {
    let key = token.trim().to_ascii_lowercase().replace('-', "_");
    if let Some(group) = group_kinds(&key) {
        return Ok(group.to_vec());
    }
    EntityKind::from_str_lossy(&key)
        .map(|k| vec![k])
        .ok_or_else(|| Error::Policy(format!("unknown entity kind or group `{token}`")))
}

pub fn group_names() -> &'static [&'static str] {
    &["identifiers", "accounts", "device", "network", "location", "all"]
}

fn group_kinds(name: &str) -> Option<Vec<EntityKind>> {
    Some(match name {
        "identifiers" => vec![
            EntityKind::Email,
            EntityKind::PhoneNumber,
            EntityKind::Imei,
            EntityKind::Imsi,
            EntityKind::Iccid,
            EntityKind::SerialNumber,
            EntityKind::Udid,
            EntityKind::AndroidId,
            EntityKind::UserName,
            EntityKind::PersonName,
            EntityKind::OrganizationName,
        ],
        "accounts" => vec![
            EntityKind::Email,
            EntityKind::UserName,
            EntityKind::PersonName,
            EntityKind::OrganizationName,
        ],
        "device" => vec![
            EntityKind::Imei,
            EntityKind::Imsi,
            EntityKind::Iccid,
            EntityKind::SerialNumber,
            EntityKind::Udid,
            EntityKind::AndroidId,
        ],
        "network" => vec![
            EntityKind::MacAddress,
            EntityKind::Bssid,
            EntityKind::Ssid,
            EntityKind::BluetoothName,
            EntityKind::IpV4Public,
            EntityKind::IpV6,
            EntityKind::DomainName,
            EntityKind::Url,
        ],
        "location" => vec![EntityKind::GpsCoordinate, EntityKind::CellId],
        "all" => EntityKind::all().to_vec(),
        _ => return None,
    })
}

pub fn dedup_kinds(kinds: impl IntoIterator<Item = EntityKind>) -> HashSet<EntityKind> {
    kinds.into_iter().collect()
}
