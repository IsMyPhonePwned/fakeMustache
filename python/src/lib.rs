//! Python module `fakemustache`.
//!
//! Removes identifiers from a diagnostic archive. It does not defeat someone who already
//! suspects a particular person.

use std::time::Duration;

use fm_android::{anonymize_bugreport, explain_bugreport};
use fm_apple::{anonymize_sysdiagnose, explain_sysdiagnose};
use fm_container::{is_tar_gz, is_tar_xz, is_zip};
use fm_core::{AnonOptions, ArchiveKind, KeySource, LogArchivePolicy, ProfileName};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

fn err(err: impl std::fmt::Display) -> PyErr {
    PyValueError::new_err(err.to_string())
}

struct Opts {
    profile: String,
    ordinal: bool,
    keep_location: bool,
    logarchive: String,
    time_shift: Option<String>,
    passphrase: Option<String>,
}

fn options(opts: &Opts) -> PyResult<AnonOptions> {
    let profile = ProfileName::parse(&opts.profile)
        .ok_or_else(|| err(format!("unknown profile '{}'", opts.profile)))?;
    let logarchive = match opts.logarchive.as_str() {
        "drop" => LogArchivePolicy::Drop,
        "jsonl" => LogArchivePolicy::Jsonl,
        other => return Err(err(format!("unknown logarchive policy '{other}'"))),
    };
    let mut built = AnonOptions::builder()
        .profile(profile)
        .logarchive(logarchive)
        .ordinal(opts.ordinal)
        .keep_location(opts.keep_location)
        .build();
    if let Some(shift) = &opts.time_shift {
        built.time_shift = Some(parse_duration(shift)?);
    }
    if let Some(pass) = &opts.passphrase {
        built.key_source = KeySource::Passphrase(pass.clone());
    }
    Ok(built)
}

fn kind_of(bytes: &[u8]) -> ArchiveKind {
    if is_zip(bytes) {
        ArchiveKind::AndroidBugreport
    } else if is_tar_gz(bytes) || is_tar_xz(bytes) {
        ArchiveKind::AppleSysdiagnose
    } else {
        ArchiveKind::Auto
    }
}

fn parse_duration(raw: &str) -> PyResult<Duration> {
    let (number, factor) = if let Some(h) = raw.strip_suffix('h') {
        (h, 3600)
    } else if let Some(m) = raw.strip_suffix('m') {
        (m, 60)
    } else if let Some(s) = raw.strip_suffix('s') {
        (s, 1)
    } else {
        (raw, 1)
    };
    let n: u64 = number.parse().map_err(|_| err(format!("bad duration '{raw}'")))?;
    Ok(Duration::from_secs(n.saturating_mul(factor)))
}

/// Explain what would be rewritten. Returns text.
#[pyfunction]
#[pyo3(signature = (data, profile="balanced", ordinal=false, keep_location=false, logarchive="drop", time_shift=None, passphrase=None))]
fn explain(
    data: &[u8],
    profile: &str,
    ordinal: bool,
    keep_location: bool,
    logarchive: &str,
    time_shift: Option<String>,
    passphrase: Option<String>,
) -> PyResult<String> {
    let opts = options(&Opts {
        profile: profile.to_string(),
        ordinal,
        keep_location,
        logarchive: logarchive.to_string(),
        time_shift,
        passphrase,
    })?;
    match kind_of(data) {
        ArchiveKind::AndroidBugreport => explain_bugreport(data, &opts).map_err(err),
        ArchiveKind::AppleSysdiagnose => explain_sysdiagnose(data, &opts).map_err(err),
        ArchiveKind::Auto => explain_bugreport(data, &opts)
            .or_else(|_| explain_sysdiagnose(data, &opts))
            .map_err(err),
    }
}

/// Anonymize archive bytes. Returns `(output_bytes, report_dict)`.
#[pyfunction]
#[pyo3(signature = (data, profile="balanced", ordinal=false, keep_location=false, logarchive="drop", time_shift=None, passphrase=None))]
fn anonymize<'py>(
    py: Python<'py>,
    data: &[u8],
    profile: &str,
    ordinal: bool,
    keep_location: bool,
    logarchive: &str,
    time_shift: Option<String>,
    passphrase: Option<String>,
) -> PyResult<(Bound<'py, PyBytes>, Py<PyAny>)> {
    let opts = options(&Opts {
        profile: profile.to_string(),
        ordinal,
        keep_location,
        logarchive: logarchive.to_string(),
        time_shift,
        passphrase,
    })?;
    let result = match kind_of(data) {
        ArchiveKind::AndroidBugreport => anonymize_bugreport(data, &opts).map_err(err)?,
        ArchiveKind::AppleSysdiagnose => anonymize_sysdiagnose(data, &opts).map_err(err)?,
        ArchiveKind::Auto => anonymize_bugreport(data, &opts)
            .or_else(|_| anonymize_sysdiagnose(data, &opts))
            .map_err(err)?,
    };
    let report = result.report.to_json().map_err(err)?;
    let report_obj = py.import("json")?.call_method1("loads", (report,))?.unbind();
    Ok((PyBytes::new(py, &result.output), report_obj))
}

#[pymodule]
fn fakemustache(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(explain, m)?)?;
    m.add_function(wrap_pyfunction!(anonymize, m)?)?;
    Ok(())
}
