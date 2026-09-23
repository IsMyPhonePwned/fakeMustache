//! Restore puts the exact original back in plist and SQLite.

#![cfg(not(target_arch = "wasm32"))]

use fm_core::{AnonOptions, EntityTable, Key, KeySource, Mapping, RewriteMode};
use fm_format::{restore_member, FormatHandler, PlistHandler, SqliteHandler};
use rusqlite::Connection;

fn key() -> Key {
    Key::from_bytes([8u8; 32])
}

fn opts() -> AnonOptions {
    let mut o = AnonOptions::builder().key(key()).build();
    o.key_source = KeySource::Bytes(*key().as_bytes());
    o.rewrite_mode = RewriteMode::Encrypt;
    o
}

#[test]
fn plist_binary_round_trip_restores_ssid() {
    let mut dict = plist::Dictionary::new();
    dict.insert("SSID".into(), plist::Value::String("Cafe Guest".into()));
    let value = plist::Value::Dictionary(dict);
    let mut raw = Vec::new();
    plist::to_writer_binary(&mut raw, &value).unwrap();
    assert!(raw.starts_with(b"bplist"));

    let o = opts();
    let mut table = EntityTable::new();
    PlistHandler
        .discover("WiFi/known.plist", &raw, &mut table, &o)
        .unwrap();
    let map = Mapping::from_entities_mode(&table.into_entities(), &key(), false, RewriteMode::Encrypt)
        .unwrap();
    let sealed = PlistHandler
        .rewrite("WiFi/known.plist", &raw, &map, &o)
        .unwrap();
    assert!(sealed.starts_with(b"bplist"));
    let sealed_text = String::from_utf8_lossy(&sealed);
    assert!(!sealed_text.contains("Cafe Guest"));

    let (back, n) = restore_member("WiFi/known.plist", &sealed, &key()).unwrap();
    assert!(n >= 1);
    assert!(back.starts_with(b"bplist"));
    let value: plist::Value = plist::from_bytes(&back).unwrap();
    let ssid = value
        .as_dictionary()
        .unwrap()
        .get("SSID")
        .unwrap()
        .as_string()
        .unwrap();
    assert_eq!(ssid, "Cafe Guest");
}

#[test]
fn sqlite_restore_puts_email_back_and_vacuum_removed_it() {
    let path = std::env::temp_dir().join(format!("fm-restore-src-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE accounts (email TEXT);
             INSERT INTO accounts VALUES ('victim@corp.example.com');",
        )
        .unwrap();
    }
    let raw = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);

    let o = opts();
    let mut table = EntityTable::new();
    SqliteHandler
        .discover("accounts.db", &raw, &mut table, &o)
        .unwrap();
    let map = Mapping::from_entities_mode(&table.into_entities(), &key(), false, RewriteMode::Encrypt)
        .unwrap();
    let sealed = SqliteHandler
        .rewrite("accounts.db", &raw, &map, &o)
        .unwrap();
    assert!(!String::from_utf8_lossy(&sealed).contains("victim@corp.example.com"));

    let (back, n) = restore_member("accounts.db", &sealed, &key()).unwrap();
    assert!(n >= 1);
    let out = std::env::temp_dir().join(format!("fm-restore-out-{}", std::process::id()));
    std::fs::write(&out, &back).unwrap();
    let conn = Connection::open(&out).unwrap();
    let email: String = conn
        .query_row("SELECT email FROM accounts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(email, "victim@corp.example.com");
    let _ = std::fs::remove_file(&out);
}

#[test]
fn tombstone_hexdump_with_email_is_dropped_not_rewritten() {
    use fm_core::{Action, Confidence, Entity, EntityKind, Location};
    use fm_format::IpsHandler;

    let text = "signal 11\nmemory near:\n  0000 victim@x.com 4141\nbacktrace\n";
    let ent = Entity {
        kind: EntityKind::Email,
        canonical: "victim@x.com".into(),
        surface_forms: vec!["victim@x.com".into()],
        occurrences: 1,
        first_seen: Location {
            member: "tombstone_00".into(),
            section: None,
            line: Some(2),
            key_path: None,
        },
        confidence: Confidence::High,
        action: Action::Pseudo,
    };
    let map = Mapping::from_entities(&[ent], &key(), false).unwrap();
    let out = IpsHandler
        .rewrite("tombstone_00", text.as_bytes(), &map, &opts())
        .unwrap();
    let s = String::from_utf8(out).unwrap();
    assert!(s.contains("hexdump dropped"));
    assert!(!s.contains("victim@x.com"));
    assert!(s.contains("signal 11"));
    assert!(s.contains("backtrace"));
}
