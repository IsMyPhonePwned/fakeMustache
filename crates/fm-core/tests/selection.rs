//! Per-kind selection: --only and --entity.

use fm_core::{Action, AnonOptions, EntityKind, ProfileName};

#[test]
fn only_keeps_everything_else() {
    let mut opts = AnonOptions::builder().profile(ProfileName::Balanced).build();
    opts.apply_only_spec("email,imei").unwrap();
    let p = opts.effective_profile();
    assert_eq!(p.action_for(EntityKind::Email), Action::Pseudo);
    assert_eq!(p.action_for(EntityKind::Imei), Action::Pseudo);
    assert_eq!(p.action_for(EntityKind::GpsCoordinate), Action::Keep);
    assert_eq!(p.action_for(EntityKind::Ssid), Action::Keep);
    assert_eq!(p.action_for(EntityKind::PhoneNumber), Action::Keep);
}

#[test]
fn groups_expand() {
    let mut opts = AnonOptions::default();
    opts.apply_only_spec("location,accounts").unwrap();
    let p = opts.effective_profile();
    assert_eq!(p.action_for(EntityKind::GpsCoordinate), Action::Drop);
    assert_eq!(p.action_for(EntityKind::CellId), Action::Drop);
    assert_eq!(p.action_for(EntityKind::Email), Action::Pseudo);
    assert_eq!(p.action_for(EntityKind::Imei), Action::Keep);
}

#[test]
fn entity_override_wins_over_only_and_profile() {
    let mut opts = AnonOptions::builder().profile(ProfileName::Balanced).build();
    opts.apply_only_spec("identifiers").unwrap();
    opts.apply_entity_spec("gps=drop").unwrap();
    opts.apply_entity_spec("email=keep").unwrap();
    opts.apply_entity_spec("device=drop").unwrap();
    let p = opts.effective_profile();
    assert_eq!(p.action_for(EntityKind::GpsCoordinate), Action::Drop);
    assert_eq!(p.action_for(EntityKind::Email), Action::Keep);
    assert_eq!(p.action_for(EntityKind::Imei), Action::Drop);
    assert_eq!(p.action_for(EntityKind::PhoneNumber), Action::Pseudo);
    assert_eq!(p.action_for(EntityKind::Ssid), Action::Keep);
}

#[test]
fn unknown_kind_is_an_error() {
    let mut opts = AnonOptions::default();
    assert!(opts.apply_entity_spec("not_a_thing=pseudo").is_err());
    assert!(opts.apply_entity_spec("email").is_err());
    assert!(opts.apply_only_spec("").is_err());
}

#[test]
fn format_lists_overrides() {
    let mut opts = AnonOptions::default();
    opts.apply_entity_spec("ssid=keep").unwrap();
    let text = opts.format_entity_policy();
    assert!(text.contains("ssid                 keep  (override)"));
    assert!(text.contains("email                pseudo"));
}
