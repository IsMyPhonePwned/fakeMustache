//! Sysdiagnose: member drops, plist wifi SSID rewrite, logarchive drop default.

use fm_apple::anonymize_sysdiagnose;
use fm_core::{AnonOptions, Key, KeySource, LogArchivePolicy, ProfileName, RewriteMode};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::{Cursor, Write};
use tar::{Builder, Header};

fn tar_gz(files: &[(&str, &[u8])]) -> Vec<u8> {
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

fn opts(seed: u8) -> AnonOptions {
    let mut o = AnonOptions::builder()
        .profile(ProfileName::Balanced)
        .key(Key::from_bytes([seed; 32]))
        .logarchive(LogArchivePolicy::Drop)
        .build();
    o.key_source = KeySource::Bytes([seed; 32]);
    o
}

#[test]
fn wifi_plist_ssid_pseudonymized() {
    let plist = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>SSID</key>
  <string>Cafe Guest Network</string>
  <key>BSSID</key>
  <string>aa:bb:cc:dd:ee:ff</string>
</dict>
</plist>"#;
    let input = tar_gz(&[(
        "sysdiagnose_x/WiFi/com.apple.wifi.known-networks.plist",
        plist,
    )]);
    let result = anonymize_sysdiagnose(&input, &opts(70)).unwrap();
    assert_eq!(result.report.residual_scan.status, "clean");
    let members = fm_container::inventory_tar(&result.output, &opts(70)).unwrap();
    let pl = members
        .iter()
        .find(|m| m.path.ends_with(".plist"))
        .expect("plist kept");
    let text = String::from_utf8_lossy(&pl.bytes);
    assert!(!text.contains("Cafe Guest Network"));
    assert!(!text.contains("aa:bb:cc:dd:ee:ff"));
}

#[test]
fn drops_logarchive_knowledgec_safari_images() {
    let input = tar_gz(&[
        ("sysdiagnose_x/system_logs.logarchive/logdata.LiveData.tracev3", b"binary"),
        ("sysdiagnose_x/logs/Knowledge/knowledgeC.db", b"SQLite format 3\0"),
        ("sysdiagnose_x/logs/Safari/History.db", b"SQLite format 3\0"),
        ("sysdiagnose_x/screen.png", &[0x89, 0x50, 0x4e, 0x47]),
        ("sysdiagnose_x/ps.txt", b"root 1 /sbin/launchd\n"),
    ]);
    let result = anonymize_sysdiagnose(&input, &opts(71)).unwrap();
    let dropped: Vec<_> = result
        .report
        .members_dropped
        .iter()
        .map(|m| m.path.as_str())
        .collect();
    assert!(dropped.iter().any(|p| p.contains("logarchive") || p.contains("tracev3")));
    assert!(dropped.iter().any(|p| p.to_ascii_lowercase().contains("knowledgec")));
    assert!(dropped.iter().any(|p| p.to_ascii_lowercase().contains("safari")));
    assert!(dropped.iter().any(|p| p.contains("screen.png")));
    // ps.txt kept
    let members = fm_container::inventory_tar(&result.output, &opts(71)).unwrap();
    assert!(members.iter().any(|m| m.path.ends_with("ps.txt")));
}

#[test]
fn audit_never_contains_original_email() {
    let input = tar_gz(&[(
        "sysdiagnose_x/note.txt",
        b"apple id is victim@icloud.com\n",
    )]);
    let result = anonymize_sysdiagnose(&input, &opts(72)).unwrap();
    let json = result.report.to_json().unwrap();
    let md = result.report.to_markdown();
    assert!(!json.contains("victim@icloud.com"));
    assert!(!md.contains("victim@icloud.com"));
}

#[test]
fn reversible_plist_restores_the_ssid() {
    let plist = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>SSID</key>
  <string>Cafe Guest Network</string>
</dict>
</plist>"#;
    let input = tar_gz(&[("sysdiagnose_x/WiFi/known.plist", plist)]);
    let mut o = opts(80);
    o.rewrite_mode = RewriteMode::Encrypt;
    let sealed = anonymize_sysdiagnose(&input, &o).unwrap();
    let members = fm_container::inventory_tar(&sealed.output, &o).unwrap();
    let text = String::from_utf8_lossy(
        &members
            .iter()
            .find(|m| m.path.ends_with(".plist"))
            .unwrap()
            .bytes,
    );
    assert!(!text.contains("Cafe Guest Network"));
    assert!(text.contains("fm1."));

    let (back, n) =
        fm_container::restore_archive(&sealed.output, &Key::from_bytes([80u8; 32])).unwrap();
    assert!(n >= 1);
    let members = fm_container::inventory_tar(&back, &o).unwrap();
    let restored = String::from_utf8_lossy(
        &members
            .iter()
            .find(|m| m.path.ends_with(".plist"))
            .unwrap()
            .bytes,
    );
    assert!(restored.contains("Cafe Guest Network"));
}
