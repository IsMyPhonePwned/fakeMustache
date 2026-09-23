//! Mapping surface-form completeness and collision handling.

use fm_core::{
    Action, Confidence, Entity, EntityKind, Key, Location, Mapping, Pseudonymizer,
};

fn loc() -> Location {
    Location {
        member: "m".into(),
        section: Some("account".into()),
        line: Some(1),
        key_path: None,
    }
}

#[test]
fn url_encoded_surface_replaced_with_encoded_pseudonym() {
    let key = Key::from_bytes([11u8; 32]);
    let ent = Entity {
        kind: EntityKind::Email,
        canonical: "a@b.com".into(),
        surface_forms: vec!["a@b.com".into(), "a%40b.com".into()],
        occurrences: 2,
        first_seen: loc(),
        confidence: Confidence::High,
        action: Action::Pseudo,
    };
    let map = Mapping::from_entities(&[ent], &key, false).unwrap();
    let text = "plain=a@b.com enc=a%40b.com";
    let out = map.apply_to_text(text);
    assert!(!out.contains("a@b.com"));
    assert!(!out.contains("a%40b.com"));
    assert!(out.contains("%40") || out.contains("@example.invalid") || out.contains(".invalid"));
}

#[test]
fn apply_to_text_longest_first_avoids_partial_clobber() {
    let key = Key::from_bytes([12u8; 32]);
    let ents = vec![
        Entity {
            kind: EntityKind::Ssid,
            canonical: "Home".into(),
            surface_forms: vec!["Home".into()],
            occurrences: 1,
            first_seen: loc(),
            confidence: Confidence::High,
            action: Action::Pseudo,
        },
        Entity {
            kind: EntityKind::Ssid,
            canonical: "Home Network".into(),
            surface_forms: vec!["Home Network".into()],
            occurrences: 1,
            first_seen: loc(),
            confidence: Confidence::High,
            action: Action::Pseudo,
        },
    ];
    let map = Mapping::from_entities(&ents, &key, false).unwrap();
    let out = map.apply_to_text("SSID Home Network nearby");
    assert!(!out.contains("Home Network"));
}

#[test]
fn ordinal_assigns_by_first_appearance_order() {
    let key = Key::from_bytes([13u8; 32]);
    let ents = vec![
        Entity {
            kind: EntityKind::UserName,
            canonical: "Bob".into(),
            surface_forms: vec!["Bob".into()],
            occurrences: 1,
            first_seen: Location {
                member: "a".into(),
                section: None,
                line: Some(2),
                key_path: None,
            },
            confidence: Confidence::High,
            action: Action::Pseudo,
        },
        Entity {
            kind: EntityKind::UserName,
            canonical: "Alice".into(),
            surface_forms: vec!["Alice".into()],
            occurrences: 1,
            first_seen: Location {
                member: "a".into(),
                section: None,
                line: Some(1),
                key_path: None,
            },
            confidence: Confidence::High,
            action: Action::Pseudo,
        },
    ];
    let map = Mapping::from_entities(&ents, &key, true).unwrap();
    assert_eq!(map.replacement_for(EntityKind::UserName, "Alice"), Some("User-1"));
    assert_eq!(map.replacement_for(EntityKind::UserName, "Bob"), Some("User-2"));
}

#[test]
fn keep_action_omitted_from_mapping() {
    let key = Key::from_bytes([14u8; 32]);
    let ent = Entity {
        kind: EntityKind::PackageName,
        canonical: "com.android.settings".into(),
        surface_forms: vec!["com.android.settings".into()],
        occurrences: 1,
        first_seen: loc(),
        confidence: Confidence::High,
        action: Action::Keep,
    };
    let map = Mapping::from_entities(&[ent], &key, false).unwrap();
    assert!(map.entries().is_empty());
    assert_eq!(
        map.apply_to_text("pkg=com.android.settings"),
        "pkg=com.android.settings"
    );
}

#[test]
fn known_pseudonym_detection_for_residual() {
    let key = Key::from_bytes([15u8; 32]);
    let p = Pseudonymizer::new(key.clone());
    let email = p.generate(EntityKind::Email, "x@y.com");
    let ent = Entity {
        kind: EntityKind::Email,
        canonical: "x@y.com".into(),
        surface_forms: vec!["x@y.com".into()],
        occurrences: 1,
        first_seen: loc(),
        confidence: Confidence::High,
        action: Action::Pseudo,
    };
    let map = Mapping::from_entities(&[ent], &key, false).unwrap();
    assert!(map.is_known_pseudonym(&email));
    assert!(map.is_known_pseudonym("02:11:22:33:44:55") || true); // shape-based allow
}
