use crate::{scan_text, ScanContext};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use fm_core::Hit;
use once_cell::sync::Lazy;
use regex::Regex;

/// Scan literal text plus derived encodings; surface forms preserved on hits.
pub fn scan_with_encodings(chunk: &str, ctx: &ScanContext<'_>) -> Vec<Hit> {
    let mut hits = scan_text(chunk, ctx);

    // URL-decoded view
    if chunk.contains('%') {
        if let Ok(decoded) = url_decode(chunk) {
            if decoded != chunk {
                for mut h in scan_text(&decoded, ctx) {
                    // Record surface as percent-encoded original span if possible
                    h.value = url_encode(&h.value);
                    hits.push(h);
                }
            }
        }
    }

    // Base64 blobs ≥16 chars
    static B64RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"[A-Za-z0-9+/]{16,}={0,2}").unwrap());
    for m in B64RE.find_iter(chunk) {
        if let Ok(bytes) = B64.decode(m.as_str()) {
            if let Ok(inner) = std::str::from_utf8(&bytes) {
                for h in scan_text(inner, ctx) {
                    // Mark whole blob as surface — rewrite replaces entire b64
                    hits.push(Hit {
                        value: m.as_str().to_string(),
                        canonical: h.canonical,
                        kind: h.kind,
                        confidence: h.confidence,
                        start: m.start(),
                        end: m.end(),
                    });
                }
            }
        }
    }

    hits
}

fn url_decode(s: &str) -> Result<String, ()> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).map_err(|_| ())?;
            let v = u8::from_str_radix(hex, 16).map_err(|_| ())?;
            out.push(v);
            i += 3;
        } else if b[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| ())
}

fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
