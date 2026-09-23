use fm_core::{open_text, seal, Key};

#[test]
fn token_round_trips_and_is_deterministic() {
    let key = Key::from_bytes([9u8; 32]);
    let token = seal(&key, "victim@corp.example.com").unwrap();
    assert!(token.starts_with("fm1."));
    assert!(!token.contains('@'));
    assert_eq!(token, seal(&key, "victim@corp.example.com").unwrap());
    let (text, n) = open_text(&key, &format!("id={token} end")).unwrap();
    assert_eq!(n, 1);
    assert_eq!(text, "id=victim@corp.example.com end");
}

#[test]
fn wrong_key_does_not_open() {
    let token = seal(&Key::from_bytes([1u8; 32]), "secret").unwrap();
    assert!(open_text(&Key::from_bytes([2u8; 32]), &token).is_err());
}

#[test]
fn sealing_a_token_is_a_noop() {
    let key = Key::from_bytes([3u8; 32]);
    let token = seal(&key, "alice@x.com").unwrap();
    assert_eq!(seal(&key, &token).unwrap(), token);
}
