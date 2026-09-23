//! Generic protobuf: rewrite length-delimited UTF-8 fields.

use crate::FormatHandler;
use fm_core::{AnonOptions, EntityTable, Error, Location, Mapping, Result};
use fm_detect::{scan_text, ScanContext};

pub struct ProtobufHandler;

impl FormatHandler for ProtobufHandler {
    fn can_handle(&self, path: &str, _magic: &[u8]) -> bool {
        let p = path.to_ascii_lowercase();
        // Bugreport traces live at `proto/Name.proto` (no slash before "proto")
        // as well as `FS/proto/...`. Those files are binary, not text schemas.
        p.contains("proto/")
            || p.ends_with(".proto")
            || p.ends_with(".proto.bin")
            || p.ends_with(".pb")
    }

    fn discover(
        &self,
        path: &str,
        bytes: &[u8],
        table: &mut EntityTable,
        opts: &AnonOptions,
    ) -> Result<()> {
        let profile = opts.effective_profile();
        let strings = extract_utf8_strings(bytes);
        let ctx = ScanContext {
            member: path,
            section: Some("protobuf"),
            key_path: None,
            profile: &profile,
        };
        for s in strings {
            for hit in scan_text(&s, &ctx) {
                let action = profile.action_for(hit.kind);
                table.insert_hit(
                    hit,
                    Location {
                        member: path.to_string(),
                        section: Some("protobuf".into()),
                        line: None,
                        key_path: None,
                    },
                    action,
                );
            }
        }
        Ok(())
    }

    fn rewrite(
        &self,
        _path: &str,
        bytes: &[u8],
        map: &Mapping,
        _opts: &AnonOptions,
    ) -> Result<Vec<u8>> {
        match rewrite_protobuf(bytes, map) {
            Ok(out) => Ok(out),
            // A `.proto` trace that is not well-formed protobuf is kept as-is.
            Err(_) => Ok(bytes.to_vec()),
        }
    }
}

fn extract_utf8_strings(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let (tag, ni) = match read_varint(bytes, i) {
            Some(x) => x,
            None => break,
        };
        i = ni;
        let wire = (tag & 0x7) as u8;
        match wire {
            0 => {
                // varint
                if let Some((_, n)) = read_varint(bytes, i) {
                    i = n;
                } else {
                    break;
                }
            }
            1 => {
                i += 8;
            } // 64-bit
            5 => {
                i += 4;
            } // 32-bit
            2 => {
                let (len, n) = match read_varint(bytes, i) {
                    Some(x) => x,
                    None => break,
                };
                i = n;
                let len = len as usize;
                if i + len > bytes.len() {
                    break;
                }
                let slice = &bytes[i..i + len];
                if let Ok(s) = std::str::from_utf8(slice) {
                    if s.chars().any(|c| c.is_ascii_alphanumeric()) {
                        out.push(s.to_string());
                    }
                }
                i += len;
            }
            _ => break,
        }
    }
    out
}

fn rewrite_protobuf(bytes: &[u8], map: &Mapping) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        let (tag, ni) = match read_varint(bytes, i) {
            Some(x) => x,
            None => {
                out.extend_from_slice(&bytes[start..]);
                break;
            }
        };
        i = ni;
        let wire = (tag & 0x7) as u8;
        match wire {
            0 => {
                let (v, n) = read_varint(bytes, i).ok_or_else(|| Error::Parse("varint".into()))?;
                write_varint(&mut out, tag);
                write_varint(&mut out, v);
                i = n;
            }
            1 => {
                if i + 8 > bytes.len() {
                    return Err(Error::Parse("short fixed64".into()));
                }
                write_varint(&mut out, tag);
                out.extend_from_slice(&bytes[i..i + 8]);
                i += 8;
            }
            5 => {
                if i + 4 > bytes.len() {
                    return Err(Error::Parse("short fixed32".into()));
                }
                write_varint(&mut out, tag);
                out.extend_from_slice(&bytes[i..i + 4]);
                i += 4;
            }
            2 => {
                let (len, n) =
                    read_varint(bytes, i).ok_or_else(|| Error::Parse("len".into()))?;
                i = n;
                let len = len as usize;
                if i + len > bytes.len() {
                    return Err(Error::Parse("short ld".into()));
                }
                let slice = &bytes[i..i + len];
                write_varint(&mut out, tag);
                if let Ok(s) = std::str::from_utf8(slice) {
                    let new_s = map.apply_to_text(s);
                    write_varint(&mut out, new_s.len() as u64);
                    out.extend_from_slice(new_s.as_bytes());
                } else {
                    write_varint(&mut out, len as u64);
                    out.extend_from_slice(slice);
                }
                i += len;
            }
            _ => {
                // Unknown — copy remainder
                out.extend_from_slice(&bytes[start..]);
                break;
            }
        }
    }
    Ok(out)
}

fn read_varint(data: &[u8], mut i: usize) -> Option<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0;
    while i < data.len() {
        let b = data[i];
        i += 1;
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some((result, i));
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    None
}

fn write_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
            out.push(b);
        } else {
            out.push(b);
            break;
        }
    }
}
