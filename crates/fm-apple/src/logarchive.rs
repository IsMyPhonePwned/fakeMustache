use fm_core::{Error, Result};

/// Decode logarchive from a sysdiagnose tar.gz into JSONL text.
/// Requires the `logarchive-decode` feature and a materialized directory (native).
pub fn try_decode_to_jsonl(sysdiagnose_bytes: &[u8]) -> Result<(String, u64)> {
    let _ = sysdiagnose_bytes;
    #[cfg(all(feature = "logarchive-decode", not(target_arch = "wasm32")))]
    {
        // Without extracting the full logarchive tree to disk, decode cannot run.
        // Stub: return empty JSONL with warning count — full integration extracts
        // system_logs.logarchive/ to a tempdir then calls decode_logarchive_dir.
        return extract_and_decode(sysdiagnose_bytes);
    }
    #[cfg(not(all(feature = "logarchive-decode", not(target_arch = "wasm32"))))]
    {
        Err(Error::Other(
            "logarchive-decode feature not enabled; use --features logarchive-decode".into(),
        ))
    }
}

#[cfg(all(feature = "logarchive-decode", not(target_arch = "wasm32")))]
fn extract_and_decode(sysdiagnose_bytes: &[u8]) -> Result<(String, u64)> {
    use flate2::read::GzDecoder;
    use std::io::{Cursor, Read};
    use tar::Archive;

    let tmp = std::env::temp_dir().join(format!("fm-logarchive-{}", std::process::id()));
    std::fs::create_dir_all(&tmp)?;
    let mut dec = GzDecoder::new(sysdiagnose_bytes);
    let mut tar_bytes = Vec::new();
    dec.read_to_end(&mut tar_bytes)
        .map_err(|e| Error::Parse(e.to_string()))?;
    let mut archive = Archive::new(Cursor::new(tar_bytes));
    let mut has_logarchive = false;
    for entry in archive.entries().map_err(|e| Error::Parse(e.to_string()))? {
        let mut entry = entry.map_err(|e| Error::Parse(e.to_string()))?;
        let path = entry
            .path()
            .map_err(|e| Error::Parse(e.to_string()))?
            .to_string_lossy()
            .to_string();
        if !path.contains("system_logs.logarchive") {
            continue;
        }
        has_logarchive = true;
        // Strip up to and including system_logs.logarchive/
        let idx = path.find("system_logs.logarchive").unwrap();
        let rel = &path[idx..];
        let out_path = tmp.join(rel);
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if entry.header().entry_type().is_file() {
            let mut f = std::fs::File::create(&out_path)?;
            std::io::copy(&mut entry, &mut f)?;
        }
    }
    if !has_logarchive {
        return Err(Error::Other("no system_logs.logarchive in archive".into()));
    }
    let log_dir = tmp.join("system_logs.logarchive");
    let events = sysdiagnose_logarchive_decode::decode_logarchive_dir(&log_dir, 10_000)
        .map_err(Error::Other)?;
    let undecodable = 0u64;
    let mut jsonl = String::new();
    for ev in &events {
        let line = serde_json::json!({
            "datetime": ev.datetime,
            "message": ev.message,
            "subsystem": ev.subsystem,
            "category": ev.category,
            "process": ev.process,
            "pid": ev.pid,
            "event_type": ev.event_type,
        });
        jsonl.push_str(&line.to_string());
        jsonl.push('\n');
    }
    let _ = std::fs::remove_dir_all(&tmp);
    Ok((jsonl, undecodable))
}
