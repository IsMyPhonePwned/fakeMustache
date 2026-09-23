//! Encrypted mapping vault (AES-256-GCM + Argon2id).

use crate::error::{Error, Result};
use crate::mapping::Mapping;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const MAGIC: &[u8] = b"FMVAULT1";

#[derive(Serialize, Deserialize)]
struct VaultPayload {
    entries: Vec<VaultEntry>,
}

#[derive(Serialize, Deserialize)]
struct VaultEntry {
    kind: String,
    original: String,
    replacement: String,
}

pub fn write_vault(
    mapping: &Mapping,
    passphrase: &str,
    vault_path: &Path,
    output_path: &Path,
    i_understand: bool,
) -> Result<()> {
    if let (Some(vp), Some(op)) = (vault_path.parent(), output_path.parent()) {
        if vp == op && !i_understand {
            return Err(Error::Vault(
                "refusing to write vault into the same directory as the output without --i-understand"
                    .into(),
            ));
        }
    }

    let payload = VaultPayload {
        entries: mapping
            .entries()
            .iter()
            .map(|e| VaultEntry {
                kind: e.kind.as_str().to_string(),
                original: e.original.clone(),
                replacement: e.replacement.clone(),
            })
            .collect(),
    };
    let plaintext =
        serde_json::to_vec(&payload).map_err(|e| Error::Vault(e.to_string()))?;

    let mut salt = [0u8; 16];
    crate::key::fill_random(&mut salt)?;
    let mut key = [0u8; 32];
    let params = Params::new(19_456, 2, 1, Some(32))
        .map_err(|e| Error::Crypto(e.to_string()))?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
        .map_err(|e| Error::Crypto(e.to_string()))?;

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| Error::Crypto(e.to_string()))?;
    let mut nonce_bytes = [0u8; 12];
    crate::key::fill_random(&mut nonce_bytes)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| Error::Crypto(format!("encrypt: {e}")))?;

    let mut file = Vec::new();
    file.extend_from_slice(MAGIC);
    file.extend_from_slice(&salt);
    file.extend_from_slice(&nonce_bytes);
    file.extend_from_slice(&ciphertext);
    std::fs::write(vault_path, &file)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(vault_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(vault_path, perms)?;
    }

    Ok(())
}

pub fn read_vault(vault_path: &Path, passphrase: &str) -> Result<Vec<(String, String, String)>> {
    let data = std::fs::read(vault_path)?;
    if data.len() < MAGIC.len() + 16 + 12 + 16 {
        return Err(Error::Vault("vault too short".into()));
    }
    if &data[..MAGIC.len()] != MAGIC {
        return Err(Error::Vault("bad vault magic".into()));
    }
    let salt = &data[8..24];
    let nonce_bytes = &data[24..36];
    let ciphertext = &data[36..];

    let mut key = [0u8; 32];
    let params = Params::new(19_456, 2, 1, Some(32))
        .map_err(|e| Error::Crypto(e.to_string()))?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| Error::Crypto(e.to_string()))?;

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| Error::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| Error::Vault("decryption failed (bad passphrase?)".into()))?;
    let payload: VaultPayload =
        serde_json::from_slice(&plaintext).map_err(|e| Error::Vault(e.to_string()))?;
    Ok(payload
        .entries
        .into_iter()
        .map(|e| (e.kind, e.original, e.replacement))
        .collect())
}

pub fn same_dir(a: &Path, b: &Path) -> bool {
    match (a.parent(), b.parent()) {
        (Some(pa), Some(pb)) => {
            let pa = pa.canonicalize().unwrap_or_else(|_| PathBuf::from(pa));
            let pb = pb.canonicalize().unwrap_or_else(|_| PathBuf::from(pb));
            pa == pb
        }
        _ => false,
    }
}
