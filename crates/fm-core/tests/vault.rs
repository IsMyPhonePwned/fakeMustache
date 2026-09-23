use fm_core::{vault, Action, Confidence, Entity, EntityKind, Key, Location, Mapping};

#[test]
fn vault_roundtrip() {
    let key = Key::from_bytes([5u8; 32]);
    let ent = Entity {
        kind: EntityKind::Email,
        canonical: "secret@example.com".into(),
        surface_forms: vec!["secret@example.com".into()],
        occurrences: 1,
        first_seen: Location {
            member: "a".into(),
            section: None,
            line: Some(1),
            key_path: None,
        },
        confidence: Confidence::High,
        action: Action::Pseudo,
    };
    let mapping = Mapping::from_entities(&[ent], &key, false).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out").join("anon.zip");
    std::fs::create_dir_all(out.parent().unwrap()).unwrap();
    std::fs::write(&out, b"x").unwrap();
    let vault_path = dir.path().join("vault").join("m.vault");
    std::fs::create_dir_all(vault_path.parent().unwrap()).unwrap();
    vault::write_vault(&mapping, "test-pass", &vault_path, &out, false).unwrap();
    let entries = vault::read_vault(&vault_path, "test-pass").unwrap();
    assert!(entries.iter().any(|(_, o, _)| o == "secret@example.com"));
    assert!(vault::read_vault(&vault_path, "wrong").is_err());
}

#[test]
fn vault_refuses_same_dir() {
    let key = Key::from_bytes([5u8; 32]);
    let mapping = Mapping::from_entities(&[], &key, false).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("anon.zip");
    let vault_path = dir.path().join("m.vault");
    std::fs::write(&out, b"x").unwrap();
    let err = vault::write_vault(&mapping, "p", &vault_path, &out, false).unwrap_err();
    assert!(err.to_string().contains("i-understand"));
    vault::write_vault(&mapping, "p", &vault_path, &out, true).unwrap();
}
