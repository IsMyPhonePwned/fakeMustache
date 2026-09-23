use crate::FormatHandler;
use fm_core::{AnonOptions, EntityTable, Error, Mapping, Result};

pub struct SqliteHandler;

impl FormatHandler for SqliteHandler {
    fn can_handle(&self, path: &str, magic: &[u8]) -> bool {
        let p = path.to_ascii_lowercase();
        p.ends_with(".db")
            || p.ends_with(".sqlite")
            || p.ends_with(".sqlite3")
            || p.ends_with(".sqlitedb")
            || magic.starts_with(b"SQLite format 3")
    }

    fn discover(
        &self,
        path: &str,
        bytes: &[u8],
        table: &mut EntityTable,
        opts: &AnonOptions,
    ) -> Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = (path, bytes, table, opts);
            // WASM: SQLite dropped by container policy; no-op discover
            return Ok(());
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            native::discover(path, bytes, table, opts)
        }
    }

    fn rewrite(
        &self,
        path: &str,
        bytes: &[u8],
        map: &Mapping,
        opts: &AnonOptions,
    ) -> Result<Vec<u8>> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = (path, map, opts);
            Err(Error::Other(format!(
                "SQLite rewrite unavailable on WASM; member should have been dropped: {path}"
            )))
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            native::rewrite(path, bytes, map, opts)
        }
    }
}

/// Open `fm1.` tokens stored in SQLite text columns.
pub fn restore_sqlite(path: &str, bytes: &[u8], key: &fm_core::Key) -> Result<(Vec<u8>, u32)> {
    #[cfg(target_arch = "wasm32")]
    {
        let _ = (path, key);
        Ok((bytes.to_vec(), 0))
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        native::restore(path, bytes, key)
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use super::*;
    use fm_core::{Confidence, Hit, Location};
    use fm_detect::{kind_from_key_path, scan_text, ScanContext};
    use rusqlite::Connection;
    use std::io::Write;

    pub fn discover(
        path: &str,
        bytes: &[u8],
        table: &mut EntityTable,
        opts: &AnonOptions,
    ) -> Result<()> {
        let dir = tempfile_dir()?;
        let db_path = dir.join("db.sqlite");
        std::fs::write(&db_path, bytes)?;
        let conn = Connection::open(&db_path).map_err(|e| Error::Parse(e.to_string()))?;
        let profile = opts.effective_profile();
        let tables = list_tables(&conn)?;
        for tname in tables {
            let cols = list_columns(&conn, &tname)?;
            for col in &cols {
                let key_path = format!("{tname}.{col}");
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT \"{col}\" FROM \"{tname}\" WHERE \"{col}\" IS NOT NULL"
                    ))
                    .map_err(|e| Error::Parse(e.to_string()))?;
                let vals = stmt
                    .query_map([], |row| row.get::<_, String>(0))
                    .map_err(|e| Error::Parse(e.to_string()))?;
                for v in vals.flatten() {
                    if let Some(kind) = kind_from_key_path(&key_path) {
                        table.insert_hit(
                            Hit {
                                kind,
                                value: v.clone(),
                                canonical: v.clone(),
                                confidence: Confidence::High,
                                start: 0,
                                end: v.len(),
                            },
                            Location {
                                member: path.to_string(),
                                section: None,
                                line: None,
                                key_path: Some(key_path.clone()),
                            },
                            profile.action_for(kind),
                        );
                    } else {
                        let ctx = ScanContext {
                            member: path,
                            section: None,
                            key_path: Some(&key_path),
                            profile: &profile,
                        };
                        for hit in scan_text(&v, &ctx) {
                            let action = profile.action_for(hit.kind);
                            table.insert_hit(
                                hit,
                                Location {
                                    member: path.to_string(),
                                    section: None,
                                    line: None,
                                    key_path: Some(key_path.clone()),
                                },
                                action,
                            );
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn rewrite(
        path: &str,
        bytes: &[u8],
        map: &Mapping,
        _opts: &AnonOptions,
    ) -> Result<Vec<u8>> {
        let dir = tempfile_dir()?;
        let db_path = dir.join("db.sqlite");
        std::fs::write(&db_path, bytes)?;
        let conn = Connection::open(&db_path).map_err(|e| Error::Parse(e.to_string()))?;
        conn.execute_batch("BEGIN;")
            .map_err(|e| Error::Parse(e.to_string()))?;
        let tables = list_tables(&conn)?;
        for tname in tables {
            let cols = list_columns(&conn, &tname)?;
            for col in cols {
                // Rewrite text columns
                let sql = format!(
                    "SELECT rowid, \"{col}\" FROM \"{tname}\" WHERE typeof(\"{col}\") = 'text'"
                );
                let mut stmt = match conn.prepare(&sql) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let rows: Vec<(i64, String)> = stmt
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                    .map_err(|e| Error::Parse(e.to_string()))?
                    .filter_map(|r| r.ok())
                    .collect();
                drop(stmt);
                for (rowid, val) in rows {
                    let new_val = map.apply_to_text(&val);
                    if new_val != val {
                        conn.execute(
                            &format!("UPDATE \"{tname}\" SET \"{col}\" = ?1 WHERE rowid = ?2"),
                            rusqlite::params![new_val, rowid],
                        )
                        .map_err(|e| Error::Parse(e.to_string()))?;
                    }
                }
            }
        }
        conn.execute_batch("COMMIT;")
            .map_err(|e| Error::Parse(e.to_string()))?;
        // Mandatory VACUUM — free pages retain old PII otherwise
        conn.execute_batch("VACUUM;")
            .map_err(|e| Error::Parse(format!("VACUUM {path}: {e}")))?;
        drop(conn);
        std::fs::read(&db_path).map_err(Error::from)
    }

    fn list_tables(conn: &Connection) -> Result<Vec<String>> {
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
            .map_err(|e| Error::Parse(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| Error::Parse(e.to_string()))?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    fn list_columns(conn: &Connection, table: &str) -> Result<Vec<String>> {
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info(\"{table}\")"))
            .map_err(|e| Error::Parse(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|e| Error::Parse(e.to_string()))?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    fn tempfile_dir() -> Result<std::path::PathBuf> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        let unique = format!("fm-sqlite-{}-{n}", std::process::id());
        path.push(unique);
        std::fs::create_dir_all(&path)?;
        // write marker so empty dirs ok
        let mut f = std::fs::File::create(path.join(".fm"))?;
        f.write_all(b"1")?;
        Ok(path)
    }

    pub fn restore(path: &str, bytes: &[u8], key: &fm_core::Key) -> Result<(Vec<u8>, u32)> {
        let dir = tempfile_dir()?;
        let db_path = dir.join("db-restore.sqlite");
        std::fs::write(&db_path, bytes)?;
        let conn = Connection::open(&db_path).map_err(|e| Error::Parse(e.to_string()))?;
        conn.execute_batch("BEGIN;")
            .map_err(|e| Error::Parse(e.to_string()))?;
        let mut opened = 0u32;
        let tables = list_tables(&conn)?;
        for tname in tables {
            let cols = list_columns(&conn, &tname)?;
            for col in cols {
                let sql = format!(
                    "SELECT rowid, \"{col}\" FROM \"{tname}\" WHERE typeof(\"{col}\") = 'text'"
                );
                let mut stmt = match conn.prepare(&sql) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let rows: Vec<(i64, String)> = stmt
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                    .map_err(|e| Error::Parse(e.to_string()))?
                    .filter_map(|r| r.ok())
                    .collect();
                drop(stmt);
                for (rowid, val) in rows {
                    let (new_val, n) = fm_core::open_text(key, &val)?;
                    opened += n;
                    if new_val != val {
                        conn.execute(
                            &format!("UPDATE \"{tname}\" SET \"{col}\" = ?1 WHERE rowid = ?2"),
                            rusqlite::params![new_val, rowid],
                        )
                        .map_err(|e| Error::Parse(e.to_string()))?;
                    }
                }
            }
        }
        conn.execute_batch("COMMIT;")
            .map_err(|e| Error::Parse(e.to_string()))?;
        let _ = path;
        drop(conn);
        let out = std::fs::read(&db_path)?;
        Ok((out, opened))
    }
}
