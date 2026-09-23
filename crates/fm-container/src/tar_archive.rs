use crate::classify::member_action;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use fm_core::{pipeline::InventoryMember, AnonOptions, Error, Result};
use std::io::{Cursor, Read, Write};
use tar::{Archive, Builder, Header};

pub fn is_tar_gz(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

pub fn is_tar_xz(data: &[u8]) -> bool {
    data.len() >= 6 && data[..6] == [0xfd, b'7', b'z', b'X', b'Z', 0x00]
}

pub fn inventory_tar(input: &[u8], opts: &AnonOptions) -> Result<Vec<InventoryMember>> {
    let uncompressed = decompress(input)?;
    let cursor = Cursor::new(uncompressed);
    let mut archive = Archive::new(cursor);
    let mut members = Vec::new();
    let entries = archive
        .entries()
        .map_err(|e| Error::Parse(format!("tar: {e}")))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| Error::Parse(format!("tar entry: {e}")))?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry
            .path()
            .map_err(|e| Error::Parse(e.to_string()))?
            .to_string_lossy()
            .to_string();
        let path = normalize_member_path(&path);
        if path.is_empty() || path.contains("/._") || path.starts_with("._") {
            continue;
        }
        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .map_err(|e| Error::Parse(format!("tar read {path}: {e}")))?;
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

pub fn repack_tar_gz(members: &[InventoryMember]) -> Result<Vec<u8>> {
    let mut tar_buf = Cursor::new(Vec::new());
    {
        let mut builder = Builder::new(&mut tar_buf);
        for m in members {
            let mut header = Header::new_gnu();
            header
                .set_path(&m.path)
                .map_err(|e| Error::Parse(e.to_string()))?;
            header.set_size(m.bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append(&header, m.bytes.as_slice())
                .map_err(|e| Error::Parse(e.to_string()))?;
        }
        builder
            .finish()
            .map_err(|e| Error::Parse(e.to_string()))?;
    }
    let tar_bytes = tar_buf.into_inner();
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(&tar_bytes)?;
    enc.finish().map_err(Error::from)
}

fn decompress(input: &[u8]) -> Result<Vec<u8>> {
    if is_tar_gz(input) {
        let mut dec = GzDecoder::new(input);
        let mut out = Vec::new();
        dec.read_to_end(&mut out)
            .map_err(|e| Error::Parse(format!("gzip: {e}")))?;
        return Ok(out);
    }
    if is_tar_xz(input) {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut dec = xz2::read::XzDecoder::new(input);
            let mut out = Vec::new();
            dec.read_to_end(&mut out)
                .map_err(|e| Error::Parse(format!("xz: {e}")))?;
            return Ok(out);
        }
        #[cfg(target_arch = "wasm32")]
        {
            return Err(Error::Parse("xz unsupported on WASM".into()));
        }
    }
    // Maybe bare tar
    Ok(input.to_vec())
}

fn normalize_member_path(path: &str) -> String {
    let path = path.replace('\\', "/");
    let mut parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    // Strip top-level sysdiagnose_* bundle dir
    if let Some(first) = parts.first() {
        if first.starts_with("sysdiagnose") {
            parts.remove(0);
        }
    }
    parts.join("/")
}
