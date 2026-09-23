//! Browser entry: anonymize archives client-side so raw diagnostics never leave the device.
//!
//! Memory strategy: process per-member (decompress → rewrite → re-compress → release).
//! A 500 MB sysdiagnose must not be held three times over in a 4 GB WASM heap.

use std::time::Duration;

use fm_android::{anonymize_bugreport, explain_bugreport};
use fm_apple::{anonymize_sysdiagnose, explain_sysdiagnose};
use fm_container::{is_tar_gz, is_tar_xz, is_zip, restore_archive};
use fm_core::{
    selection::group_names, AnonOptions, ArchiveKind, EntityKind, Key, KeySource, LogArchivePolicy,
    ProfileName, RewriteMode,
};
use serde::Deserialize;
use wasm_bindgen::prelude::*;

#[derive(Deserialize)]
struct JsOpts {
    #[serde(default = "default_profile")]
    profile: String,
    #[serde(default)]
    passphrase: Option<String>,
    #[serde(default)]
    logarchive: Option<String>,
    #[serde(default)]
    ordinal: bool,
    #[serde(default)]
    keep_location: bool,
    #[serde(default)]
    keep_cell_ids: bool,
    #[serde(default)]
    generalize_carrier: bool,
    #[serde(default)]
    drop_carrier: bool,
    #[serde(default)]
    pseudo_third_party_packages: bool,
    #[serde(default)]
    drop_text_from_packages: Option<String>,
    /// Comma-separated kinds or groups. Everything else is kept.
    #[serde(default)]
    only: Option<String>,
    /// `KIND=ACTION` overrides. Wins over `only` and the profile.
    #[serde(default)]
    entities: Vec<String>,
    /// Uniform shift, e.g. `72h`, `30m`, `3600s`.
    #[serde(default)]
    time_shift: Option<String>,
    /// Encrypt values in place so the same key can restore them.
    #[serde(default)]
    reversible: bool,
    /// Raw key file, standard base64. 32 bytes is a key; anything else is a passphrase file.
    #[serde(default)]
    key_b64: Option<String>,
}

fn default_profile() -> String {
    "balanced".into()
}

#[wasm_bindgen]
pub struct AnonOutput {
    output: Vec<u8>,
    report_json: String,
}

#[wasm_bindgen]
impl AnonOutput {
    #[wasm_bindgen(getter)]
    pub fn output(&self) -> Vec<u8> {
        self.output.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn report_json(&self) -> String {
        self.report_json.clone()
    }
}

fn js_err(err: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&err.to_string())
}

fn nonempty(value: Option<String>) -> Option<String> {
    value.and_then(|s| {
        let t = s.trim().to_string();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    })
}

fn parse_duration(raw: &str) -> Result<Duration, JsValue> {
    let (number, factor) = if let Some(h) = raw.strip_suffix('h') {
        (h, 3600u64)
    } else if let Some(m) = raw.strip_suffix('m') {
        (m, 60)
    } else if let Some(s) = raw.strip_suffix('s') {
        (s, 1)
    } else {
        (raw, 1)
    };
    let n: u64 = number
        .trim()
        .parse()
        .map_err(|_| js_err(format!("bad duration '{raw}' (use 72h, 30m, or 3600s)")))?;
    Ok(Duration::from_secs(n.saturating_mul(factor)))
}

fn options_from_js(opts: JsValue) -> Result<AnonOptions, JsValue> {
    let js_opts: JsOpts = serde_wasm_bindgen_compat(opts)?;
    let profile = ProfileName::parse(&js_opts.profile)
        .ok_or_else(|| js_err(format!("unknown profile '{}'", js_opts.profile)))?;
    let logarchive = match js_opts.logarchive.as_deref().unwrap_or("drop") {
        "" | "drop" => LogArchivePolicy::Drop,
        "jsonl" => LogArchivePolicy::Jsonl,
        other => return Err(js_err(format!("unknown logarchive policy '{other}'"))),
    };
    let mut options = AnonOptions::builder()
        .profile(profile)
        .logarchive(logarchive)
        .ordinal(js_opts.ordinal)
        .keep_location(js_opts.keep_location)
        .build();
    options.keep_cell_ids = js_opts.keep_cell_ids;
    options.generalize_carrier = js_opts.generalize_carrier;
    options.drop_carrier = js_opts.drop_carrier;
    options.pseudo_third_party_packages = js_opts.pseudo_third_party_packages;
    if let Some(list) = nonempty(js_opts.drop_text_from_packages) {
        options.drop_text_from_packages = list
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Some(only) = nonempty(js_opts.only) {
        options.apply_only_spec(&only).map_err(js_err)?;
    }
    for spec in js_opts.entities {
        let spec = spec.trim();
        if spec.is_empty() {
            continue;
        }
        options.apply_entity_spec(spec).map_err(js_err)?;
    }
    if let Some(shift) = nonempty(js_opts.time_shift) {
        options.time_shift = Some(parse_duration(&shift)?);
    }
    if js_opts.reversible {
        options.rewrite_mode = RewriteMode::Encrypt;
    }
    if let Some(b64) = nonempty(js_opts.key_b64) {
        options.key_source = key_from_b64(&b64)?;
    } else if let Some(pp) = nonempty(js_opts.passphrase) {
        options.key_source = KeySource::Passphrase(pp);
    }
    Ok(options)
}

fn key_from_b64(b64: &str) -> Result<KeySource, JsValue> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| js_err(format!("key file is not base64: {e}")))?;
    if raw.len() == 32 {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&raw);
        return Ok(KeySource::Bytes(bytes));
    }
    let key = Key::from_passphrase(&String::from_utf8_lossy(&raw), b"fakemustache-key-file")
        .map_err(js_err)?;
    Ok(KeySource::Bytes(*key.as_bytes()))
}

fn kind_of(input: &[u8]) -> ArchiveKind {
    if is_zip(input) {
        ArchiveKind::AndroidBugreport
    } else if is_tar_gz(input) || is_tar_xz(input) {
        ArchiveKind::AppleSysdiagnose
    } else {
        ArchiveKind::Auto
    }
}

#[wasm_bindgen]
pub fn anonymize(input: &[u8], opts: JsValue) -> Result<AnonOutput, JsValue> {
    let options = options_from_js(opts)?;
    let result = match kind_of(input) {
        ArchiveKind::AndroidBugreport => anonymize_bugreport(input, &options),
        ArchiveKind::AppleSysdiagnose => anonymize_sysdiagnose(input, &options),
        ArchiveKind::Auto => anonymize_bugreport(input, &options)
            .or_else(|_| anonymize_sysdiagnose(input, &options)),
    }
    .map_err(js_err)?;

    Ok(AnonOutput {
        output: result.output,
        report_json: result.report.to_json().map_err(js_err)?,
    })
}

/// Open `fm1.` tokens written by reversible mode. Needs the same passphrase or key file.
#[wasm_bindgen]
pub fn restore(input: &[u8], opts: JsValue) -> Result<AnonOutput, JsValue> {
    let mut options = options_from_js(opts)?;
    options.rewrite_mode = RewriteMode::Encrypt;
    if matches!(options.key_source, KeySource::Random) {
        return Err(js_err(
            "restore needs the same passphrase or key file used with reversible mode",
        ));
    }
    let key = options
        .resolve_key(b"fakemustache-reversible-v1")
        .map_err(js_err)?;
    let (output, opened) = restore_archive(input, &key).map_err(js_err)?;
    Ok(AnonOutput {
        output,
        report_json: format!(r#"{{"opened":{opened}}}"#),
    })
}

/// Dry-run: decisions only, no rewritten archive.
#[wasm_bindgen]
pub fn explain(input: &[u8], opts: JsValue) -> Result<String, JsValue> {
    let options = options_from_js(opts)?;
    match kind_of(input) {
        ArchiveKind::AndroidBugreport => explain_bugreport(input, &options).map_err(js_err),
        ArchiveKind::AppleSysdiagnose => explain_sysdiagnose(input, &options).map_err(js_err),
        ArchiveKind::Auto => explain_bugreport(input, &options)
            .or_else(|_| explain_sysdiagnose(input, &options))
            .map_err(js_err),
    }
}

/// Effective action for every information type, given the current options.
#[wasm_bindgen]
pub fn describe_policy(opts: JsValue) -> Result<String, JsValue> {
    let options = options_from_js(opts)?;
    Ok(options.format_entity_policy())
}

/// Kinds, groups, and actions the UI can offer.
#[wasm_bindgen]
pub fn entity_catalog() -> String {
    let kinds: Vec<&str> = EntityKind::all().iter().map(|k| k.as_str()).collect();
    serde_json::json!({
        "kinds": kinds,
        "groups": group_names(),
        "actions": ["keep", "pseudo", "drop", "generalize", "shift"],
    })
    .to_string()
}

fn serde_wasm_bindgen_compat(opts: JsValue) -> Result<JsOpts, JsValue> {
    let json = js_sys::JSON::stringify(&opts).map_err(|e| e)?;
    let s = json.as_string().unwrap_or_else(|| "{}".into());
    serde_json::from_str(&s).map_err(js_err)
}

#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
