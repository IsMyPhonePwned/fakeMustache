//! Pipeline gates: residual fail-closed, reversible key requirement, keep exemption.

use fm_core::pipeline::{
    anonymize_with_backends, ArchiveBackend, InventoryMember, MemberProcessor,
};
use fm_core::{
    Action, AnonOptions, ArchiveKind, Confidence, EntityTable, Error, Hit, Key, KeySource,
    Location, Mapping, ProfileName, Result, RewriteMode,
};

struct OneMember {
    bytes: Vec<u8>,
}

impl ArchiveBackend for OneMember {
    fn detect_kind(&self, _: &[u8]) -> ArchiveKind {
        ArchiveKind::AndroidBugreport
    }
    fn inventory(&self, _: &[u8], _: &AnonOptions) -> Result<Vec<InventoryMember>> {
        Ok(vec![InventoryMember {
            path: "dumpstate.txt".into(),
            bytes: self.bytes.clone(),
            drop: false,
            drop_reason: None,
        }])
    }
    fn repack(&self, members: &[InventoryMember], _: ArchiveKind) -> Result<Vec<u8>> {
        Ok(members.iter().flat_map(|m| m.bytes.clone()).collect())
    }
}

struct LeaveEmail;

impl MemberProcessor for LeaveEmail {
    fn discover(
        &self,
        path: &str,
        _: &[u8],
        table: &mut EntityTable,
        _: &AnonOptions,
    ) -> Result<()> {
        table.insert_hit(
            Hit {
                kind: fm_core::EntityKind::Email,
                value: "leak@example.com".into(),
                canonical: "leak@example.com".into(),
                confidence: Confidence::High,
                start: 0,
                end: 16,
            },
            Location {
                member: path.into(),
                section: Some("account".into()),
                line: Some(1),
                key_path: None,
            },
            Action::Pseudo,
        );
        Ok(())
    }
    fn rewrite(&self, _: &str, bytes: &[u8], _: &Mapping, _: &AnonOptions) -> Result<Vec<u8>> {
        Ok(bytes.to_vec())
    }
    fn residual_scan(
        &self,
        _: &str,
        _: &[u8],
        _: &Mapping,
        _: &AnonOptions,
    ) -> Result<Vec<Hit>> {
        Ok(vec![Hit {
            kind: fm_core::EntityKind::Email,
            value: "leak@example.com".into(),
            canonical: "leak@example.com".into(),
            confidence: Confidence::High,
            start: 0,
            end: 16,
        }])
    }
}

fn opts(profile: ProfileName) -> AnonOptions {
    let mut o = AnonOptions::builder()
        .profile(profile)
        .key(Key::from_bytes([4u8; 32]))
        .build();
    o.key_source = KeySource::Bytes([4u8; 32]);
    o
}

#[test]
fn residual_withholds_output_when_rewrite_leaves_email() {
    let archive = OneMember {
        bytes: b"leak@example.com".to_vec(),
    };
    let err = anonymize_with_backends(
        b"zip",
        ArchiveKind::AndroidBugreport,
        &opts(ProfileName::Balanced),
        &archive,
        &LeaveEmail,
    )
    .unwrap_err();
    assert!(matches!(err, Error::ResidualPii(_)), "{err}");
}

#[test]
fn research_profile_warns_but_keeps_output() {
    let archive = OneMember {
        bytes: b"leak@example.com".to_vec(),
    };
    let result = anonymize_with_backends(
        b"zip",
        ArchiveKind::AndroidBugreport,
        &opts(ProfileName::Research),
        &archive,
        &LeaveEmail,
    )
    .unwrap();
    assert_eq!(result.report.residual_scan.status, "warnings");
    assert!(!result.output.is_empty());
}

#[test]
fn kept_kind_is_not_a_residual_failure() {
    let archive = OneMember {
        bytes: b"leak@example.com".to_vec(),
    };
    let mut o = opts(ProfileName::Balanced);
    o.apply_entity_spec("email=keep").unwrap();
    let result =
        anonymize_with_backends(b"zip", ArchiveKind::AndroidBugreport, &o, &archive, &LeaveEmail)
            .unwrap();
    assert_eq!(result.report.residual_scan.status, "clean");
    assert_eq!(result.output, b"leak@example.com");
}

#[test]
fn reversible_refuses_a_random_key() {
    let archive = OneMember {
        bytes: b"ok".to_vec(),
    };
    let mut o = AnonOptions::default();
    o.rewrite_mode = RewriteMode::Encrypt;
    o.key_source = KeySource::Random;
    let err = anonymize_with_backends(
        b"zip",
        ArchiveKind::AndroidBugreport,
        &o,
        &archive,
        &LeaveEmail,
    )
    .unwrap_err();
    assert!(err.to_string().contains("reversible"), "{err}");
}

#[test]
fn reversible_passphrase_ignores_archive_id() {
    let mut o = AnonOptions::default();
    o.rewrite_mode = RewriteMode::Encrypt;
    o.key_source = KeySource::Passphrase("correct horse".into());
    let a = o.resolve_key(b"archive-a").unwrap();
    let b = o.resolve_key(b"archive-b").unwrap();
    assert_eq!(a.as_bytes(), b.as_bytes());

    o.rewrite_mode = RewriteMode::Pseudonym;
    let c = o.resolve_key(b"archive-a").unwrap();
    let d = o.resolve_key(b"archive-b").unwrap();
    assert_ne!(c.as_bytes(), d.as_bytes());
    assert_ne!(a.as_bytes(), c.as_bytes());
}

struct ApplyHits {
    hits: Vec<(fm_core::EntityKind, String)>,
}

impl MemberProcessor for ApplyHits {
    fn discover(
        &self,
        path: &str,
        _: &[u8],
        table: &mut EntityTable,
        _: &AnonOptions,
    ) -> Result<()> {
        for (kind, value) in &self.hits {
            table.insert_hit(
                Hit {
                    kind: *kind,
                    value: value.clone(),
                    canonical: value.clone(),
                    confidence: Confidence::High,
                    start: 0,
                    end: value.len(),
                },
                Location {
                    member: path.into(),
                    section: None,
                    line: Some(1),
                    key_path: None,
                },
                Action::Pseudo,
            );
        }
        Ok(())
    }

    fn rewrite(&self, _: &str, bytes: &[u8], mapping: &Mapping, _: &AnonOptions) -> Result<Vec<u8>> {
        Ok(mapping
            .apply_to_text(&String::from_utf8_lossy(bytes))
            .into_bytes())
    }

    fn residual_scan(&self, _: &str, _: &[u8], _: &Mapping, _: &AnonOptions) -> Result<Vec<Hit>> {
        Ok(Vec::new())
    }
}

fn run_hits(text: &str, hits: Vec<(fm_core::EntityKind, &str)>, o: &AnonOptions) -> Vec<u8> {
    let archive = OneMember {
        bytes: text.as_bytes().to_vec(),
    };
    let proc = ApplyHits {
        hits: hits
            .into_iter()
            .map(|(k, v)| (k, v.to_string()))
            .collect(),
    };
    anonymize_with_backends(b"zip", ArchiveKind::AndroidBugreport, o, &archive, &proc)
        .unwrap()
        .output
}

#[test]
fn domain_allowlist_keeps_infrastructure_and_rewrites_the_rest() {
    let out = run_hits(
        "googleapis.com evil.example",
        vec![
            (fm_core::EntityKind::DomainName, "googleapis.com"),
            (fm_core::EntityKind::DomainName, "evil.example"),
        ],
        &opts(ProfileName::Balanced),
    );
    let s = String::from_utf8(out).unwrap();
    assert!(s.contains("googleapis.com"));
    assert!(!s.contains("evil.example"));
}

#[test]
fn package_allowlist_only_applies_with_the_flag() {
    let mut o = opts(ProfileName::Balanced);
    o.pseudo_third_party_packages = true;
    let out = run_hits(
        "com.android.settings com.evil.stalkerware",
        vec![
            (fm_core::EntityKind::PackageName, "com.android.settings"),
            (fm_core::EntityKind::PackageName, "com.evil.stalkerware"),
        ],
        &o,
    );
    let s = String::from_utf8(out).unwrap();
    assert!(s.contains("com.android.settings"));
    assert!(!s.contains("com.evil.stalkerware"));
    assert!(s.contains("com.anon.pkg"));
}

#[test]
fn carrier_and_cell_flags_change_the_rewrite() {
    use fm_core::EntityKind;
    let text = "carrier=Verizon mccmnc=310260 cid=12345678";
    let hits = vec![
        (EntityKind::Carrier, "Verizon"),
        (EntityKind::Carrier, "310260"),
        (EntityKind::CellId, "12345678"),
    ];

    let mut drop_c = opts(ProfileName::Balanced);
    drop_c.drop_carrier = true;
    let dropped = String::from_utf8(run_hits(text, hits.clone(), &drop_c)).unwrap();
    assert!(!dropped.contains("Verizon"));
    assert!(!dropped.contains("310260"));
    assert!(!dropped.contains("12345678"));

    let mut gen = opts(ProfileName::Balanced);
    gen.generalize_carrier = true;
    let generalized = String::from_utf8(run_hits(text, hits.clone(), &gen)).unwrap();
    assert!(!generalized.contains("Verizon"));
    assert!(generalized.contains("carrier"));
    assert!(generalized.contains("mcc-310"));
    assert!(!generalized.contains("310260"));

    let mut keep = opts(ProfileName::Balanced);
    keep.keep_cell_ids = true;
    let kept = String::from_utf8(run_hits(text, hits, &keep)).unwrap();
    assert!(kept.contains("12345678"));
    assert!(kept.contains("Verizon"));
}

