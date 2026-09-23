use crate::classify::member_action;
use fm_core::{pipeline::InventoryMember, AnonOptions, Error, Result};
use std::io::{Cursor, Read, Write};
use zip::{CompressionMethod, ZipArchive, ZipWriter};

pub const DUMPSTATE_CANDIDATE: &str = "__dumpstate__";

pub fn is_zip(data: &[u8]) -> bool {
    data.len() >= 4 && data[0] == 0x50 && data[1] == 0x4b && data[2] == 0x03 && data[3] == 0x04
}

pub fn inventory_zip(input: &[u8], opts: &AnonOptions) -> Result<Vec<InventoryMember>> {
    let cursor = Cursor::new(input);
    let mut archive =
        ZipArchive::new(cursor).map_err(|e| Error::Parse(format!("zip: {e}")))?;
    let mut members = Vec::new();
    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| Error::Parse(format!("zip entry: {e}")))?;
        if file.is_dir() {
            continue;
        }
        let path = file.name().to_string();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|e| Error::Parse(format!("zip read {path}: {e}")))?;
        let action = member_action(&path, opts);
        members.push(InventoryMember {
            path,
            bytes,
            drop: action.drop,
            drop_reason: if action.drop {
                Some(action.reason)
            } else {
                None
            },
        });
    }
    Ok(members)
}

/// Every file, including ones anonymize would drop. Used by `--restore`.
pub fn read_zip(input: &[u8]) -> Result<Vec<InventoryMember>> {
    let cursor = Cursor::new(input);
    let mut archive =
        ZipArchive::new(cursor).map_err(|e| Error::Parse(format!("zip: {e}")))?;
    let mut members = Vec::new();
    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| Error::Parse(format!("zip entry: {e}")))?;
        if file.is_dir() {
            continue;
        }
        let path = file.name().to_string();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|e| Error::Parse(format!("zip read {path}: {e}")))?;
        members.push(InventoryMember {
            path,
            bytes,
            drop: false,
            drop_reason: None,
        });
    }
    Ok(members)
}

pub fn repack_zip(members: &[InventoryMember]) -> Result<Vec<u8>> {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut cursor);
        let opts = zip::write::FileOptions::default().compression_method(CompressionMethod::Deflated);
        for m in members {
            zip.start_file(&m.path, opts)
                .map_err(|e| Error::Parse(format!("zip start: {e}")))?;
            zip.write_all(&m.bytes)
                .map_err(|e| Error::Parse(format!("zip write: {e}")))?;
        }
        zip.finish()
            .map_err(|e| Error::Parse(format!("zip finish: {e}")))?;
    }
    Ok(cursor.into_inner())
}

/// BEL-compatible 5-pass dumpstate discovery among zip members.
pub fn extract_dumpstate_member(members: &[InventoryMember]) -> Option<&InventoryMember> {
    // Pass 1: exact dumpstate.txt
    if let Some(m) = members.iter().find(|m| {
        let name = m.path.rsplit('/').next().unwrap_or(&m.path);
        name == "dumpstate.txt"
    }) {
        return Some(m);
    }
    // Pass 2: dumpstate-*.txt skipping dumpstate_log / _debug
    if let Some(m) = members.iter().find(|m| {
        let name = m.path.rsplit('/').next().unwrap_or(&m.path);
        name.starts_with("dumpstate-")
            && name.ends_with(".txt")
            && !name.contains("dumpstate_log")
            && !name.contains("_debug")
    }) {
        return Some(m);
    }
    // Pass 3: name contains dumpstate.txt
    if let Some(m) = members
        .iter()
        .find(|m| m.path.contains("dumpstate.txt"))
    {
        return Some(m);
    }
    // Pass 4: bugreport-*.txt
    if let Some(m) = members.iter().find(|m| {
        let name = m.path.rsplit('/').next().unwrap_or(&m.path);
        name.starts_with("bugreport-") && name.ends_with(".txt")
    }) {
        return Some(m);
    }
    // Pass 5: largest root-ish .txt > 100KB
    members
        .iter()
        .filter(|m| {
            m.path.ends_with(".txt")
                && m.bytes.len() > 100_000
                && !m.path.contains('/')
        })
        .max_by_key(|m| m.bytes.len())
        .or_else(|| {
            members
                .iter()
                .filter(|m| m.path.ends_with(".txt") && m.bytes.len() > 100_000)
                .max_by_key(|m| m.bytes.len())
        })
}
