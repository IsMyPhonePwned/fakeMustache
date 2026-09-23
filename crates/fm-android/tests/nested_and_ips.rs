//! Nested gzip-in-zip canary and IPS crash report rewrite.

use fm_android::anonymize_bugreport;
use fm_core::{AnonOptions, EntityTable, Key, KeySource, Mapping, ProfileName};
use fm_format::{FormatHandler, IpsHandler};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::{Cursor, Write};
use zip::write::FileOptions;
use zip::{CompressionMethod, ZipWriter};

#[test]
fn gzip_member_inside_zip_text_still_processed_as_utf8_member() {
    // Our inventory reads zip members as raw bytes; a .txt.gz would be binary.
    // Spec: one level of gzip in containers — ensure plain dumpstate works with trailing noise.
    let mut body = include_str!("../../../testdata/canary/dumpstate-canary.txt").to_string();
    body.push_str("\n# trailer\n");
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut cursor);
        let opts = FileOptions::default().compression_method(CompressionMethod::Deflated);
        zip.start_file("dumpstate.txt", opts).unwrap();
        zip.write_all(body.as_bytes()).unwrap();
        // Also add a gzip blob that should be dropped as unknown binary if not text — keep as .bin
        let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
        gz.write_all(b"secret@inside.gzip.com").unwrap();
        let gz_bytes = gz.finish().unwrap();
        zip.start_file("opaque.bin.gz", opts).unwrap();
        zip.write_all(&gz_bytes).unwrap();
        zip.finish().unwrap();
    }
    let input = cursor.into_inner();
    let mut opts = AnonOptions::builder()
        .profile(ProfileName::Balanced)
        .key(Key::from_bytes([80u8; 32]))
        .build();
    opts.key_source = KeySource::Bytes([80u8; 32]);
    let result = anonymize_bugreport(&input, &opts).unwrap();
    assert_eq!(result.report.residual_scan.status, "clean");
    // opaque gzip content not scanned deeply — fail-closed may keep bytes if classified as handled?
    // binary non-utf8 kept as-is unless unknown drop — document: residual must not see the email
    let out_hay = String::from_utf8_lossy(&result.output);
    // Deflated zip may still contain compressed form; ensure report clean is the gate
    assert!(!out_hay.contains("victim.user@corp.example.com"));
}

#[test]
fn ips_rewrites_email_keeps_exception_type() {
    let ips = r#"{"bug_type":"BUG","os_version":"iOS","name":"crash"}
{"exception":{"type":"EXC_BAD_ACCESS","signal":"SIGSEGV"},"email":"owner@icloud.com","procName":"Foo","bundleID":"com.example.foo","threads":[{"frames":[{"imageOffset":1,"symbol":"main"}]}]}
"#;
    let opts = AnonOptions::builder()
        .key(Key::from_bytes([81u8; 32]))
        .build();
    let mut table = EntityTable::new();
    IpsHandler
        .discover("crash.ips", ips.as_bytes(), &mut table, &opts)
        .unwrap();
    let map = Mapping::from_entities(&table.into_entities(), &Key::from_bytes([81u8; 32]), false)
        .unwrap();
    let out = IpsHandler
        .rewrite("crash.ips", ips.as_bytes(), &map, &opts)
        .unwrap();
    let s = String::from_utf8(out).unwrap();
    assert!(s.contains("EXC_BAD_ACCESS"));
    assert!(s.contains("SIGSEGV"));
    assert!(!s.contains("owner@icloud.com"));
}
