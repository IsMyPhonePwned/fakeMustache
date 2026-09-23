//! Put original values back into a member that was written with `--reversible`.

use fm_core::{open_text, Key, Result};
use plist::Value;

pub fn restore_member(path: &str, bytes: &[u8], key: &Key) -> Result<(Vec<u8>, u32)> {
    let lower = path.to_ascii_lowercase();
    if bytes.starts_with(b"SQLite format 3")
        || lower.ends_with(".db")
        || lower.ends_with(".sqlite")
        || lower.ends_with(".sqlite3")
        || lower.ends_with(".sqlitedb")
    {
        return crate::sqlite::restore_sqlite(path, bytes, key);
    }
    if bytes.starts_with(b"bplist") || lower.ends_with(".plist") {
        return restore_plist(bytes, key);
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        let (out, n) = open_text(key, text)?;
        return Ok((out.into_bytes(), n));
    }
    Ok((bytes.to_vec(), 0))
}

fn restore_plist(bytes: &[u8], key: &Key) -> Result<(Vec<u8>, u32)> {
    let was_binary = bytes.starts_with(b"bplist");
    let mut value: Value = match plist::from_bytes(bytes) {
        Ok(v) => v,
        Err(_) => {
            if let Ok(text) = std::str::from_utf8(bytes) {
                let (out, n) = open_text(key, text)?;
                return Ok((out.into_bytes(), n));
            }
            return Ok((bytes.to_vec(), 0));
        }
    };
    let n = walk_plist(&mut value, key)?;
    let mut out = Vec::new();
    if was_binary {
        plist::to_writer_binary(&mut out, &value)
            .map_err(|e| fm_core::Error::Parse(format!("plist write: {e}")))?;
    } else {
        plist::to_writer_xml(&mut out, &value)
            .map_err(|e| fm_core::Error::Parse(format!("plist write: {e}")))?;
    }
    Ok((out, n))
}

fn walk_plist(value: &mut Value, key: &Key) -> Result<u32> {
    match value {
        Value::String(s) => {
            let (next, n) = open_text(key, s)?;
            *s = next;
            Ok(n)
        }
        Value::Array(arr) => {
            let mut n = 0;
            for item in arr {
                n += walk_plist(item, key)?;
            }
            Ok(n)
        }
        Value::Dictionary(dict) => {
            let mut n = 0;
            let keys: Vec<String> = dict.keys().cloned().collect();
            for k in keys {
                if let Some(v) = dict.get_mut(&k) {
                    n += walk_plist(v, key)?;
                }
            }
            Ok(n)
        }
        _ => Ok(0),
    }
}
