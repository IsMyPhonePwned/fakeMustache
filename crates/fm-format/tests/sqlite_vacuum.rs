//! SQLite rewrite + mandatory VACUUM: original plaintext must not survive in file bytes.

#![cfg(not(target_arch = "wasm32"))]

use fm_core::{AnonOptions, EntityTable, Key, Mapping};
use fm_format::{FormatHandler, SqliteHandler};
use rusqlite::Connection;

fn make_db_with_pii() -> Vec<u8> {
    let path = std::env::temp_dir().join(format!("fm-vac-src-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE accounts (id INTEGER PRIMARY KEY, email TEXT);
             INSERT INTO accounts(email) VALUES ('victim@corp.example.com');
             INSERT INTO accounts(email) VALUES ('other@example.org');",
        )
        .unwrap();
    }
    let bytes = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    bytes
}

#[test]
fn sqlite_rewrites_and_vacuum_removes_original_plaintext() {
    let bytes = make_db_with_pii();
    assert!(
        String::from_utf8_lossy(&bytes).contains("victim@corp.example.com"),
        "precondition: plaintext present in raw sqlite file"
    );

    let opts = AnonOptions::builder()
        .key(Key::from_bytes([21u8; 32]))
        .build();
    let mut table = EntityTable::new();
    SqliteHandler
        .discover("tcc.db", &bytes, &mut table, &opts)
        .unwrap();
    assert!(table.len() >= 1);

    let entities = table.into_entities();
    let map = Mapping::from_entities(&entities, &Key::from_bytes([21u8; 32]), false).unwrap();
    let out = SqliteHandler
        .rewrite("tcc.db", &bytes, &map, &opts)
        .unwrap();

    let hay = String::from_utf8_lossy(&out);
    assert!(
        !hay.contains("victim@corp.example.com"),
        "original email must not survive in output bytes after VACUUM"
    );
    assert!(!hay.contains("other@example.org"));

    // DB still opens and has rows
    let path = std::env::temp_dir().join(format!("fm-vac-out-{}", std::process::id()));
    std::fs::write(&path, &out).unwrap();
    let conn = Connection::open(&path).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM accounts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 2);
    let email: String = conn
        .query_row("SELECT email FROM accounts WHERE id=1", [], |r| r.get(0))
        .unwrap();
    assert!(email.ends_with(".invalid") || email.starts_with("user-"));
    let _ = std::fs::remove_file(&path);
}
