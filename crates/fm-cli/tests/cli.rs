//! The CLI wires the same pipeline the libraries do.

use std::io::{Cursor, Read, Write};
use std::process::Command;
use zip::write::FileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_fakemustache")
}

fn zip_bytes(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut cursor);
        let opts = FileOptions::default().compression_method(CompressionMethod::Deflated);
        for (name, data) in files {
            zip.start_file(*name, opts).unwrap();
            zip.write_all(data).unwrap();
        }
        zip.finish().unwrap();
    }
    cursor.into_inner()
}

fn member(bytes: &[u8], name: &str) -> String {
    let mut archive = ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut file = archive.by_name(name).unwrap();
    let mut text = String::new();
    file.read_to_string(&mut text).unwrap();
    text
}

fn dump() -> &'static str {
    "DUMP OF SERVICE account:\nAccount {name=victim.user@corp.example.com, type=com.google}\n\nDUMP OF SERVICE iphonesubinfo:\nIMEI: 490154203237518\n\nDUMP OF SERVICE user:\nUserInfo{0:Alice Victim:13}\n\nSYSTEM LOG:\n06-01 12:00:00.000 E sync: ok\n"
}

#[test]
fn list_entities_prints_the_effective_table() {
    let out = Command::new(bin()).arg("--list-entities").output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("email"));
    assert!(text.contains("pseudo"));
    assert!(text.contains("groups:"));
}

#[test]
fn reversible_without_a_key_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("in.zip");
    let output = dir.path().join("out.zip");
    std::fs::write(&input, zip_bytes(&[("dumpstate.txt", dump().as_bytes())])).unwrap();
    let out = Command::new(bin())
        .args([
            "-i",
            input.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "--reversible",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert!(!output.exists());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("reversible") || err.contains("key"), "{err}");
}

#[test]
fn key_file_round_trip_and_only_and_shift_and_ordinal() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("in.zip");
    let shared = dir.path().join("shared.zip");
    let back = dir.path().join("back.zip");
    let only = dir.path().join("only.zip");
    let shifted = dir.path().join("shift.zip");
    let key = dir.path().join("owner.key");
    std::fs::write(&input, zip_bytes(&[("dumpstate.txt", dump().as_bytes())])).unwrap();
    std::fs::write(&key, [9u8; 32]).unwrap();

    let sealed = Command::new(bin())
        .args([
            "-i",
            input.to_str().unwrap(),
            "-o",
            shared.to_str().unwrap(),
            "--reversible",
            "--key-file",
            key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        sealed.status.success(),
        "{}",
        String::from_utf8_lossy(&sealed.stderr)
    );
    let shared_text = member(&std::fs::read(&shared).unwrap(), "dumpstate.txt");
    assert!(!shared_text.contains("victim.user@corp.example.com"));
    assert!(shared_text.contains("fm1."));
    let report = std::fs::read_to_string(dir.path().join("fakemustache-report.json")).unwrap();
    assert!(!report.contains("victim.user@corp.example.com"));
    assert!(!report.contains("490154203237518"));

    let restored = Command::new(bin())
        .args([
            "-i",
            shared.to_str().unwrap(),
            "-o",
            back.to_str().unwrap(),
            "--restore",
            "--key-file",
            key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        restored.status.success(),
        "{}",
        String::from_utf8_lossy(&restored.stderr)
    );
    let back_text = member(&std::fs::read(&back).unwrap(), "dumpstate.txt");
    assert!(back_text.contains("victim.user@corp.example.com"));
    assert!(back_text.contains("490154203237518"));

    let only_run = Command::new(bin())
        .args([
            "-i",
            input.to_str().unwrap(),
            "-o",
            only.to_str().unwrap(),
            "--only",
            "email",
            "--key-file",
            key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        only_run.status.success(),
        "{}",
        String::from_utf8_lossy(&only_run.stderr)
    );
    let only_text = member(&std::fs::read(&only).unwrap(), "dumpstate.txt");
    assert!(!only_text.contains("victim.user@corp.example.com"));
    assert!(only_text.contains("490154203237518"));

    let shift = Command::new(bin())
        .args([
            "-i",
            input.to_str().unwrap(),
            "-o",
            shifted.to_str().unwrap(),
            "--time-shift",
            "1h",
            "--ordinal",
            "--key-file",
            key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        shift.status.success(),
        "{}",
        String::from_utf8_lossy(&shift.stderr)
    );
    let shifted_text = member(&std::fs::read(&shifted).unwrap(), "dumpstate.txt");
    assert!(shifted_text.contains("13:00:00.000"));
    assert!(!shifted_text.contains("12:00:00.000"));
    assert!(shifted_text.contains("User-1"));
    assert!(!shifted_text.contains("Alice Victim"));
}
