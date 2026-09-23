//! In-place reversible tokens.
//!
//! A private value is replaced by `fm1.` plus an AES-256-GCM ciphertext.
//! The same key opens it back to the exact original bytes. The nonce is
//! derived from the plaintext, so one value always becomes the same token
//! and joins still work. The nonce is stored in the token, so restore does
//! not need a side table.

use crate::error::{Error, Result};
use crate::key::Key;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use regex::Regex;
use sha2::Sha256;
use std::sync::OnceLock;

type HmacSha256 = Hmac<Sha256>;

const PREFIX: &str = "fm1.";
const AAD: &[u8] = b"fakemustache-fm1";

fn token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"fm1\.[A-Za-z0-9_-]{20,}").expect("token regex"))
}

pub fn is_token(value: &str) -> bool {
    value.starts_with(PREFIX) && token_re().is_match(value)
}

/// Seal `plaintext` under `key`. Deterministic: same input, same token.
pub fn seal(key: &Key, plaintext: &str) -> Result<String> {
    if plaintext.is_empty() || is_token(plaintext) {
        return Ok(plaintext.to_string());
    }
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let nonce_bytes = nonce_for(key, plaintext);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext.as_bytes(),
                aad: AAD,
            },
        )
        .map_err(|e| Error::Crypto(format!("seal: {e}")))?;
    let mut blob = Vec::with_capacity(12 + ct.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ct);
    Ok(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(blob)))
}

/// Open every `fm1.` token in `text`. A bad token is an error (wrong key).
pub fn open_text(key: &Key, text: &str) -> Result<(String, u32)> {
    let mut count = 0u32;
    let mut err: Option<Error> = None;
    let out = token_re().replace_all(text, |caps: &regex::Captures| {
        let token = caps.get(0).unwrap().as_str();
        match open_token(key, token) {
            Ok(plain) => {
                count += 1;
                plain
            }
            Err(e) => {
                if err.is_none() {
                    err = Some(e);
                }
                token.to_string()
            }
        }
    });
    if let Some(e) = err {
        return Err(e);
    }
    Ok((out.into_owned(), count))
}

pub fn open_token(key: &Key, token: &str) -> Result<String> {
    let b64 = token
        .strip_prefix(PREFIX)
        .ok_or_else(|| Error::Crypto("not a reversible token".into()))?;
    let blob = URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|_| Error::Crypto("reversible token is corrupt, or the key is wrong".into()))?;
    if blob.len() < 12 + 16 {
        return Err(Error::Crypto(
            "reversible token is corrupt, or the key is wrong".into(),
        ));
    }
    let (nonce_bytes, ct) = blob.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let plain = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ct,
                aad: AAD,
            },
        )
        .map_err(|_| Error::Crypto("reversible token is corrupt, or the key is wrong".into()))?;
    String::from_utf8(plain).map_err(|_| Error::Crypto("restored value is not text".into()))
}

/// True when a detector hit sits inside a sealed token (base64 can look like an id).
pub fn hit_inside_token(text: &str, start: usize, end: usize) -> bool {
    token_re().find_iter(text).any(|m| start >= m.start() && end <= m.end())
}

fn nonce_for(key: &Key, plaintext: &str) -> [u8; 12] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key.as_bytes()).expect("hmac key");
    mac.update(b"fm1-nonce|");
    mac.update(plaintext.as_bytes());
    let full = mac.finalize().into_bytes();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&full[..12]);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detector_hit_inside_a_token_is_ignored() {
        let key = Key::from_bytes([3u8; 32]);
        let token = seal(&key, "490154203237518").unwrap();
        let text = format!("before {token} after");
        let start = text.find("fm1.").unwrap() + 4;
        assert!(hit_inside_token(&text, start, start + 8));
        assert!(!hit_inside_token(&text, 0, 4));
        assert_eq!(open_token(&key, &token).unwrap(), "490154203237518");
    }
}
