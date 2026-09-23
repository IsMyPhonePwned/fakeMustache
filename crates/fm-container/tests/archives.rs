//! Container classification and path normalization.

use flate2::write::GzEncoder;
use flate2::Compression;
use fm_container::{inventory_tar, is_zip, read_zip, repack_zip};
use fm_core::pipeline::InventoryMember;
use fm_core::AnonOptions;
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

#[test]
fn sysdiagnose_bundle_prefix_is_stripped_and_images_marked_drop() {
    let input = tar_gz(&[
        ("sysdiagnose_2026_iPhone/ps.txt", b"launchd\n"),
        ("sysdiagnose_2026_iPhone/shot.png", &[0x89, 0x50, 0x4e, 0x47]),
        ("sysdiagnose_2026_iPhone/._ps.txt", b"appledouble"),
    ]);
    let members = inventory_tar(&input, &AnonOptions::default()).unwrap();
    let ps = members.iter().find(|m| m.path.ends_with("ps.txt")).unwrap();
    assert_eq!(ps.path, "ps.txt");
    assert!(!ps.drop);
    let shot = members.iter().find(|m| m.path.ends_with("shot.png")).unwrap();
    assert!(shot.drop);
    assert!(shot.drop_reason.as_deref().unwrap().contains("image"));
    assert!(members.iter().all(|m| !m.path.contains("._")));
}

#[test]
fn zip_repack_round_trip_keeps_bytes() {
    let members = vec![InventoryMember {
        path: "version.txt".into(),
        bytes: b"1\n".to_vec(),
        drop: false,
        drop_reason: None,
    }];
    let zipped = repack_zip(&members).unwrap();
    assert!(is_zip(&zipped));
    let back = read_zip(&zipped).unwrap();
    assert_eq!(back.len(), 1);
    assert_eq!(back[0].path, "version.txt");
    assert_eq!(back[0].bytes, b"1\n");
}
