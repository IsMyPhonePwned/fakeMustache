use fm_apple::anonymize_sysdiagnose;
use fm_core::{AnonOptions, Key, KeySource};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::{Cursor, Write};
use tar::{Builder, Header};

fn tar_gz_with(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar_buf = Cursor::new(Vec::new());
    {
        let mut builder = Builder::new(&mut tar_buf);
        for (path, data) in files {
            let mut header = Header::new_gnu();
            header.set_path(path).unwrap();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, *data).unwrap();
        }
        builder.finish().unwrap();
    }
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(&tar_buf.into_inner()).unwrap();
    enc.finish().unwrap()
}

#[test]
fn drops_safari_and_images_keeps_text() {
    let input = tar_gz_with(&[
        (
            "sysdiagnose_test/logs/Safari/History.db",
            b"SQLite format 3\0fake",
        ),
        (
            "sysdiagnose_test/WiFi/note.txt",
            b"SSID: \"Cafe Guest\"\nuser@icloud.com\n",
        ),
        ("sysdiagnose_test/shot.png", &[0x89, 0x50, 0x4e, 0x47]),
    ]);
    let mut opts = AnonOptions::builder()
        .key(Key::from_bytes([3u8; 32]))
        .build();
    opts.key_source = KeySource::Bytes([3u8; 32]);
    let result = anonymize_sysdiagnose(&input, &opts).expect("anon");
    assert!(result
        .report
        .members_dropped
        .iter()
        .any(|m| m.path.contains("Safari") || m.reason.contains("browsing")));
    assert!(result
        .report
        .members_dropped
        .iter()
        .any(|m| m.path.contains("shot.png")));
}
