use crate::error::{Error, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, Mac};
use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use rand::SeedableRng;
use sha2::Sha256;
use std::path::Path;

type HmacSha256 = Hmac<Sha256>;

/// 32-byte pseudonymization key. Never use a keyless hash for low-entropy PII.
#[derive(Clone)]
pub struct Key {
    bytes: [u8; 32],
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key([redacted])")
    }
}

impl Key {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub fn random() -> Result<Self> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|e| Error::Crypto(e.to_string()))?;
        Ok(Self { bytes })
    }

    /// Argon2id(passphrase, salt = archive_id).
    pub fn from_passphrase(passphrase: &str, archive_id: &[u8]) -> Result<Self> {
        let params = Params::new(19_456, 2, 1, Some(32))
            .map_err(|e| Error::Crypto(format!("argon2 params: {e}")))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; 32];
        // Salt must be at least 8 bytes for argon2; pad/hash archive_id if short.
        let mut salt = [0u8; 16];
        if archive_id.len() >= 16 {
            salt.copy_from_slice(&archive_id[..16]);
        } else {
            let mut h = <HmacSha256 as Mac>::new_from_slice(b"fakemustache-salt")
                .map_err(|e| Error::Crypto(e.to_string()))?;
            h.update(archive_id);
            salt.copy_from_slice(&h.finalize().into_bytes()[..16]);
        }
        argon
            .hash_password_into(passphrase.as_bytes(), &salt, &mut out)
            .map_err(|e| Error::Crypto(format!("argon2: {e}")))?;
        Ok(Self { bytes: out })
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        if data.len() == 32 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data);
            return Ok(Self { bytes });
        }
        // Treat file contents as passphrase with fixed salt for reproducibility.
        Self::from_passphrase(
            &String::from_utf8_lossy(&data),
            b"fakemustache-key-file",
        )
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// HMAC-SHA256(key, kind_tag || canonical_value) → 32-byte tag.
    pub fn tag(&self, kind_tag: &[u8], canonical: &str) -> [u8; 32] {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.bytes)
            .expect("HMAC accepts 32-byte key");
        mac.update(kind_tag);
        mac.update(b"|");
        mac.update(canonical.as_bytes());
        let result = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Seeded RNG for fallbacks that need extra entropy from the tag.
    pub fn rng_from_tag(tag: &[u8; 32]) -> ChaCha20Rng {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(tag);
        ChaCha20Rng::from_seed(seed)
    }

    pub fn write_file(&self, path: &Path) -> Result<()> {
        std::fs::write(path, self.bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }
        Ok(())
    }
}

/// Fill `buf` with cryptographically random bytes (for salts/nonces).
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    rand::thread_rng().fill_bytes(buf);
    Ok(())
}
