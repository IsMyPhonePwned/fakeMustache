//! Archive inventory and repack for ZIP and tar.gz/xz.

mod classify;
mod tar_archive;
mod zip_archive;

use fm_core::{
    pipeline::{ArchiveBackend, InventoryMember},
    AnonOptions, ArchiveKind, Error, Result,
};

pub use classify::{is_image_path, member_action, MemberAction};
pub use tar_archive::{inventory_tar, is_tar_gz, is_tar_xz, repack_tar_gz};
pub use zip_archive::{
    extract_dumpstate_member, inventory_zip, is_zip, read_zip, repack_zip, DUMPSTATE_CANDIDATE,
};

/// Open every `fm1.` token in an anonymized archive. Members are not dropped.
pub fn restore_archive(input: &[u8], key: &fm_core::Key) -> Result<(Vec<u8>, u32)> {
    let backend = DefaultArchiveBackend;
    let kind = backend.detect_kind(input);
    let opts = AnonOptions::default();
    let mut members = match kind {
        ArchiveKind::AndroidBugreport => read_zip(input)?,
        ArchiveKind::AppleSysdiagnose => {
            let mut members = tar_archive::inventory_tar(input, &opts)?;
            for m in &mut members {
                m.drop = false;
            }
            members
        }
        ArchiveKind::Auto => {
            if let Ok(m) = read_zip(input) {
                m
            } else if let Ok(mut m) = tar_archive::inventory_tar(input, &opts) {
                for member in &mut m {
                    member.drop = false;
                }
                m
            } else {
                return Err(Error::UnsupportedArchive);
            }
        }
    };
    let mut opened = 0u32;
    for member in &mut members {
        let (bytes, n) = fm_format::restore_member(&member.path, &member.bytes, key)?;
        member.bytes = bytes;
        member.drop = false;
        opened += n;
    }
    let kept: Vec<_> = members.into_iter().filter(|m| !m.drop).collect();
    let output = backend.repack(&kept, kind)?;
    Ok((output, opened))
}

pub struct DefaultArchiveBackend;

impl ArchiveBackend for DefaultArchiveBackend {
    fn detect_kind(&self, input: &[u8]) -> ArchiveKind {
        if is_zip(input) {
            ArchiveKind::AndroidBugreport
        } else if is_tar_gz(input) || is_tar_xz(input) {
            ArchiveKind::AppleSysdiagnose
        } else {
            ArchiveKind::Auto
        }
    }

    fn inventory(&self, input: &[u8], opts: &AnonOptions) -> Result<Vec<InventoryMember>> {
        match self.detect_kind(input) {
            ArchiveKind::AndroidBugreport => inventory_zip(input, opts),
            ArchiveKind::AppleSysdiagnose => inventory_tar(input, opts),
            ArchiveKind::Auto => {
                if let Ok(m) = inventory_zip(input, opts) {
                    Ok(m)
                } else if let Ok(m) = inventory_tar(input, opts) {
                    Ok(m)
                } else {
                    Err(Error::UnsupportedArchive)
                }
            }
        }
    }

    fn repack(&self, members: &[InventoryMember], kind: ArchiveKind) -> Result<Vec<u8>> {
        match kind {
            ArchiveKind::AndroidBugreport => repack_zip(members),
            ArchiveKind::AppleSysdiagnose => repack_tar_gz(members),
            ArchiveKind::Auto => {
                // Prefer zip if paths look like bugreport
                if members.iter().any(|m| {
                    m.path.contains("dumpstate") || m.path.ends_with("version.txt")
                }) {
                    repack_zip(members)
                } else {
                    repack_tar_gz(members)
                }
            }
        }
    }
}
