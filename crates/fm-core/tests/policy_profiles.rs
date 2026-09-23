//! Policy profiles and allowlists.

use fm_core::{
    allowlists, load_bundled_profile, Action, EntityKind, ProfileName,
};

#[test]
fn all_three_profiles_load() {
    for name in [ProfileName::Balanced, ProfileName::Strict, ProfileName::Research] {
        let p = load_bundled_profile(name).unwrap();
        assert_eq!(p.name, name.as_str());
        assert_eq!(p.unknown_member_action, Action::Drop);
    }
}

#[test]
fn balanced_defaults_match_spec_table() {
    let p = load_bundled_profile(ProfileName::Balanced).unwrap();
    assert_eq!(p.action_for(EntityKind::Email), Action::Pseudo);
    assert_eq!(p.action_for(EntityKind::GpsCoordinate), Action::Drop);
    assert_eq!(p.action_for(EntityKind::CellId), Action::Drop);
    assert_eq!(p.action_for(EntityKind::PackageName), Action::Keep);
    assert_eq!(p.action_for(EntityKind::Timestamp), Action::Keep);
    assert_eq!(p.action_for(EntityKind::IpV4Private), Action::Keep);
    assert_eq!(p.action_for(EntityKind::IpV4Public), Action::Pseudo);
}

#[test]
fn research_keeps_location_and_cell() {
    let p = load_bundled_profile(ProfileName::Research).unwrap();
    assert_eq!(p.action_for(EntityKind::GpsCoordinate), Action::Keep);
    assert_eq!(p.action_for(EntityKind::CellId), Action::Keep);
}

#[test]
fn strict_min_confidence_is_low() {
    let p = load_bundled_profile(ProfileName::Strict).unwrap();
    assert_eq!(p.min_confidence(), fm_core::Confidence::Low);
    assert_eq!(
        load_bundled_profile(ProfileName::Balanced)
            .unwrap()
            .min_confidence(),
        fm_core::Confidence::Medium
    );
}

#[test]
fn package_and_domain_allowlists() {
    assert!(allowlists::should_keep_package("com.android.settings"));
    assert!(allowlists::should_keep_package("com.google.android.gms"));
    assert!(allowlists::should_keep_package("com.anon.pkgdeadbeef"));
    assert!(!allowlists::should_keep_package("com.evil.stalkerware"));

    assert!(allowlists::should_keep_domain("googleapis.com"));
    assert!(allowlists::should_keep_domain("foo.googleapis.com"));
    assert!(!allowlists::should_keep_domain("evil.example"));
}
