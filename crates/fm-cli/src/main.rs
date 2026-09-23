use clap::{Parser, ValueEnum};
use fm_android::{anonymize_bugreport, explain_bugreport};
use fm_apple::{anonymize_sysdiagnose, explain_sysdiagnose};
use fm_container::{is_tar_gz, is_tar_xz, is_zip, restore_archive};
use fm_core::{
    vault, AnonOptions, ArchiveKind, Error, KeySource, LogArchivePolicy, ProfileName, RewriteMode,
};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "fakemustache",
    about = "Anonymize Android bugreports and Apple sysdiagnose archives without destroying forensic value.",
    after_help = "WARNING: This tool removes identifiers; it does not remove behavioural fingerprints.\n\
It makes an archive safer to share with someone who does not already know you;\n\
it does not make you anonymous to someone already investigating you.\n\
\n\
Select exactly which information is rewritten:\n\
  --list-entities\n\
  --only email,imei,ssid\n\
  --only identifiers            # group: email, phone, imei, names, serials, …\n\
  --only network,location\n\
  --entity gps=keep --entity imei=drop\n\
\n\
Reversible (encrypt in place, restore later with the same key):\n\
  fakemustache -i in.zip -o out.zip --reversible --key-file ./owner.key\n\
  fakemustache -i out.zip -o back.zip --restore --key-file ./owner.key\n\
\n\
Do not ship the key with the archive. Without the key the tokens cannot be opened."
)]
struct Cli {
    /// Input archive
    #[arg(short = 'i', long)]
    input: Option<PathBuf>,

    /// Output archive
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,

    /// Policy profile
    #[arg(long, value_enum, default_value = "balanced")]
    profile: ProfileArg,

    /// Print every information type and the action this command will take
    #[arg(long)]
    list_entities: bool,

    /// Anonymize only these kinds (comma-separated). Everything else is kept.
    /// Accepts kind names and groups: identifiers, accounts, device, network, location, all.
    #[arg(long, value_name = "KINDS")]
    only: Option<String>,

    /// Override one kind or group. Repeatable. Example: --entity email=pseudo --entity gps=keep
    #[arg(long = "entity", value_name = "KIND=ACTION")]
    entities: Vec<String>,

    /// Replace private values with fm1 tokens that this key can restore
    #[arg(long)]
    reversible: bool,

    /// Put the originals back. Needs the same --key-file or --passphrase used with --reversible
    #[arg(long)]
    restore: bool,

    /// Dry-run: print decisions, write nothing
    #[arg(long)]
    explain: bool,

    /// Residual-scan an existing anonymized archive
    #[arg(long)]
    verify: bool,

    /// Run §3 contract test (requires sibling extractor libs in private CI)
    #[arg(long)]
    contract_test: bool,

    /// Key source: random (default), file path, or passphrase via --passphrase
    #[arg(long)]
    key_file: Option<PathBuf>,

    #[arg(long)]
    passphrase: Option<String>,

    /// Encrypted mapping vault path
    #[arg(long)]
    vault: Option<PathBuf>,

    /// Allow vault in same directory as output
    #[arg(long)]
    i_understand: bool,

    /// Logarchive policy
    #[arg(long, value_enum, default_value = "drop")]
    logarchive: LogarchiveArg,

    /// Ordinal human-readable pseudonyms
    #[arg(long)]
    ordinal: bool,

    /// Uniform time shift, e.g. 72h or 3600s
    #[arg(long)]
    time_shift: Option<String>,

    #[arg(long)]
    keep_location: bool,

    #[arg(long)]
    keep_cell_ids: bool,

    #[arg(long)]
    generalize_carrier: bool,

    #[arg(long)]
    drop_carrier: bool,

    #[arg(long)]
    pseudo_third_party_packages: bool,

    /// Comma-separated package names whose free-text logs are dropped
    #[arg(long)]
    drop_text_from_packages: Option<String>,
}

#[derive(Clone, Debug, ValueEnum)]
enum ProfileArg {
    Strict,
    Balanced,
    Research,
}

#[derive(Clone, Debug, ValueEnum)]
enum LogarchiveArg {
    Drop,
    Jsonl,
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::from(0),
        Err(Error::ResidualPii(_)) => ExitCode::from(1),
        Err(Error::UnhandledMember(_)) => ExitCode::from(2),
        Err(Error::Parse(_)) | Err(Error::UnsupportedArchive) => ExitCode::from(3),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(3)
        }
    }
}

fn run(cli: Cli) -> fm_core::Result<()> {
    let mut opts = AnonOptions::builder()
        .profile(match cli.profile {
            ProfileArg::Strict => ProfileName::Strict,
            ProfileArg::Balanced => ProfileName::Balanced,
            ProfileArg::Research => ProfileName::Research,
        })
        .logarchive(match cli.logarchive {
            LogarchiveArg::Drop => LogArchivePolicy::Drop,
            LogarchiveArg::Jsonl => LogArchivePolicy::Jsonl,
        })
        .ordinal(cli.ordinal)
        .keep_location(cli.keep_location)
        .build();

    opts.keep_cell_ids = cli.keep_cell_ids;
    opts.generalize_carrier = cli.generalize_carrier;
    opts.drop_carrier = cli.drop_carrier;
    opts.pseudo_third_party_packages = cli.pseudo_third_party_packages;
    if let Some(list) = &cli.drop_text_from_packages {
        opts.drop_text_from_packages = list.split(',').map(|s| s.trim().to_string()).collect();
    }
    if let Some(only) = &cli.only {
        opts.apply_only_spec(only)?;
    }
    for spec in &cli.entities {
        opts.apply_entity_spec(spec)?;
    }
    if let Some(ts) = &cli.time_shift {
        opts.time_shift = Some(parse_duration(ts)?);
        if !fm_format_roundtrip_ok(opts.time_shift.unwrap()) {
            return Err(Error::Other(
                "time-shift self-test failed; refusing to apply".into(),
            ));
        }
    }

    if cli.list_entities {
        println!("{}", opts.format_entity_policy());
        println!("\ngroups: identifiers, accounts, device, network, location, all");
        println!("--entity KIND=ACTION overrides --only and the profile.");
        return Ok(());
    }

    let input_path = cli
        .input
        .clone()
        .ok_or_else(|| Error::Other("--input is required".into()))?;
    let input = std::fs::read(&input_path)?;
    let vault_passphrase = cli.passphrase.clone();
    let vault_path = cli.vault.clone();

    if cli.reversible || cli.restore {
        opts.rewrite_mode = RewriteMode::Encrypt;
    }
    if let Some(kf) = cli.key_file {
        opts.key_source = KeySource::File(kf);
    } else if let Some(ref pp) = vault_passphrase {
        opts.key_source = KeySource::Passphrase(pp.clone());
    } else {
        opts.key_source = KeySource::Random;
    }
    if vault_path.is_some() {
        opts.include_mapping = true;
        opts.vault_passphrase = vault_passphrase
            .clone()
            .or_else(|| std::env::var("FAKEMUSTACHE_VAULT_PASS").ok());
        if opts.vault_passphrase.is_none() {
            return Err(Error::Vault(
                "--vault requires --passphrase or FAKEMUSTACHE_VAULT_PASS".into(),
            ));
        }
    }

    let kind = if is_zip(&input) {
        ArchiveKind::AndroidBugreport
    } else if is_tar_gz(&input) || is_tar_xz(&input) {
        ArchiveKind::AppleSysdiagnose
    } else {
        ArchiveKind::Auto
    };

    if cli.restore {
        if matches!(opts.key_source, KeySource::Random) {
            return Err(Error::Other(
                "--restore needs the same --key-file or --passphrase used with --reversible".into(),
            ));
        }
        let output_path = cli
            .output
            .ok_or_else(|| Error::Other("--output is required".into()))?;
        let key = opts.resolve_key(b"fakemustache-reversible-v1")?;
        let (output, opened) = restore_archive(&input, &key)?;
        std::fs::write(&output_path, &output)?;
        eprintln!(
            "restored {} token(s) into {}",
            opened,
            output_path.display()
        );
        return Ok(());
    }

    if cli.explain {
        let text = match kind {
            ArchiveKind::AndroidBugreport => explain_bugreport(&input, &opts)?,
            ArchiveKind::AppleSysdiagnose => explain_sysdiagnose(&input, &opts)?,
            ArchiveKind::Auto => explain_bugreport(&input, &opts)
                .or_else(|_| explain_sysdiagnose(&input, &opts))?,
        };
        print!("{text}");
        return Ok(());
    }

    if cli.verify {
        // Residual scan only
        let result = match kind {
            ArchiveKind::AndroidBugreport => anonymize_bugreport(&input, &opts),
            _ => anonymize_sysdiagnose(&input, &opts),
        };
        // For verify on already-anon input, treat residual failure as exit 1
        match result {
            Ok(r) => {
                println!("{}", r.report.to_json()?);
                Ok(())
            }
            Err(e) => Err(e),
        }
    } else if cli.contract_test {
        eprintln!(
            "contract-test: run via `cargo xtask contract` with sibling extractor libraries"
        );
        Ok(())
    } else {
        let output_path = cli
            .output
            .ok_or_else(|| Error::Other("--output is required".into()))?;

        let result = match kind {
            ArchiveKind::AndroidBugreport => anonymize_bugreport(&input, &opts)?,
            ArchiveKind::AppleSysdiagnose => anonymize_sysdiagnose(&input, &opts)?,
            ArchiveKind::Auto => anonymize_bugreport(&input, &opts)
                .or_else(|_| anonymize_sysdiagnose(&input, &opts))?,
        };

        std::fs::write(&output_path, &result.output)?;

        let report_json = output_path.with_file_name("fakemustache-report.json");
        let report_md = output_path.with_file_name("fakemustache-report.md");
        std::fs::write(&report_json, result.report.to_json()?)?;
        std::fs::write(&report_md, result.report.to_markdown())?;

        if let Some(vault_path) = vault_path {
            let pass = opts.vault_passphrase.as_deref().unwrap();
            let mapping = result
                .mapping
                .as_ref()
                .ok_or_else(|| Error::Vault("mapping missing".into()))?;
            vault::write_vault(mapping, pass, &vault_path, &output_path, cli.i_understand)?;
        }

        eprintln!(
            "wrote {} ({} bytes); residual={}",
            output_path.display(),
            result.output.len(),
            result.report.residual_scan.status
        );
        Ok(())
    }
}

fn parse_duration(s: &str) -> fm_core::Result<Duration> {
    if let Some(h) = s.strip_suffix('h') {
        let n: u64 = h
            .parse()
            .map_err(|_| Error::Other(format!("bad duration: {s}")))?;
        return Ok(Duration::from_secs(n * 3600));
    }
    if let Some(m) = s.strip_suffix('m') {
        let n: u64 = m
            .parse()
            .map_err(|_| Error::Other(format!("bad duration: {s}")))?;
        return Ok(Duration::from_secs(n * 60));
    }
    if let Some(sec) = s.strip_suffix('s') {
        let n: u64 = sec
            .parse()
            .map_err(|_| Error::Other(format!("bad duration: {s}")))?;
        return Ok(Duration::from_secs(n));
    }
    let n: u64 = s
        .parse()
        .map_err(|_| Error::Other(format!("bad duration: {s}")))?;
    Ok(Duration::from_secs(n))
}

fn fm_format_roundtrip_ok(d: Duration) -> bool {
    fm_format::round_trip_self_test(d)
}
