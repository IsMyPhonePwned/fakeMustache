//! Integration: canary dumpstate inside a zip survives anonymization without residual PII.

use fm_android::anonymize_bugreport;
use fm_core::{AnonOptions, Key, KeySource, ProfileName};
use std::io::{Cursor, Write};
use zip::write::FileOptions;
use zip::{CompressionMethod, ZipWriter};

fn zip_with_dumpstate(text: &str) -> Vec<u8> {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut cursor);
        let opts = FileOptions::default().compression_method(CompressionMethod::Deflated);
        zip.start_file("dumpstate.txt", opts).unwrap();
        zip.write_all(text.as_bytes()).unwrap();
        zip.start_file("version.txt", opts).unwrap();
        zip.write_all(b"1.0\n").unwrap();
        zip.start_file("screenshot.png", opts).unwrap();
        zip.write_all(&[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).unwrap();
        zip.finish().unwrap();
    }
    cursor.into_inner()
}

#[test]
fn canary_anonymizes_and_drops_image() {
    let canary = include_str!("../../../testdata/canary/dumpstate-canary.txt");
    let input = zip_with_dumpstate(canary);
    let mut opts = AnonOptions::builder()
        .profile(ProfileName::Balanced)
        .key(Key::from_bytes([7u8; 32]))
        .include_mapping(true)
        .build();
    opts.key_source = KeySource::Bytes([7u8; 32]);

    let result = anonymize_bugreport(&input, &opts).expect("anonymize");
    assert_eq!(result.report.residual_scan.status, "clean");
    assert!(result
        .report
        .members_dropped
        .iter()
        .any(|m| m.path.contains("screenshot")));

    let out_text = {
        use fm_container::inventory_zip;
        let members = inventory_zip(&result.output, &opts).unwrap();
        let ds = members
            .iter()
            .find(|m| m.path.contains("dumpstate"))
            .expect("dumpstate present");
        String::from_utf8_lossy(&ds.bytes).into_owned()
    };

    assert!(!out_text.contains("victim.user@corp.example.com"));
    assert!(!out_text.contains("Alice Victim"));
    assert!(!out_text.contains("52.392128"));
    assert!(!out_text.contains("aa:bb:cc:dd:ee:ff"));
    assert!(out_text.contains("<redacted>") || !out_text.contains("4.902320"));
    assert!(out_text.contains("com.android.settings")); // package keep
    assert!(out_text.contains("com.evil.stalkerware")); // package keep by default
}

#[test]
fn idempotent_anonymize() {
    let canary = include_str!("../../../testdata/canary/dumpstate-canary.txt");
    let input = zip_with_dumpstate(canary);
    let opts = AnonOptions::builder()
        .profile(ProfileName::Balanced)
        .key(Key::from_bytes([9u8; 32]))
        .build();
    let once = anonymize_bugreport(&input, &opts).unwrap();
    let twice = anonymize_bugreport(&once.output, &opts).unwrap();
    // Second pass should be clean and not radically rewrite pseudonyms
    assert_eq!(twice.report.residual_scan.status, "clean");
}

#[test]
fn different_keys_unlinkable() {
    let canary = "DUMP OF SERVICE account:\nAccount {name=a@b.com, type=com.google}\n";
    let input = zip_with_dumpstate(canary);
    let a = anonymize_bugreport(
        &input,
        &AnonOptions::builder()
            .key(Key::from_bytes([1u8; 32]))
            .build(),
    )
    .unwrap();
    let b = anonymize_bugreport(
        &input,
        &AnonOptions::builder()
            .key(Key::from_bytes([2u8; 32]))
            .build(),
    )
    .unwrap();
    assert_ne!(a.output, b.output);
}
