# `fakeMustache` — Technical Specification

> Branded implementation of the mobilediag2anon design. Binary: `fakemustache`. Crates: `fm-*`.
> Behavioural contract is unchanged from the original design below (entity names `m2a-*` in prose map to `fm-*`).


**An open-source Rust tool that anonymizes Android bugreports and Apple sysdiagnose archives so they can be shared, without destroying their forensic value.**

Status: design spec, not yet implemented.
Audience: an implementing agent with write access to a new repository.
Sibling context: [`bugreport-extractor-library`](../bugreport-extractor-library), [`sysdiagnose-extractor-library`](../sysdiagnose-extractor-library) — this spec depends on both, and §3 explains why.

---

## 0. Reading order

1. §1 — the problem and the threat model. This is not a redaction tool; the distinction matters and drives everything.
2. §2 — the five design principles.
3. §3 — **the correctness contract.** Read this before any code. It is what makes "doesn't break the evidence" a test rather than a claim.
4. §4 — what is actually inside these archives.
5. §5 — the entity taxonomy: per-entity policy, including the genuinely ambiguous cases.
6. §6–§10 — architecture, detection, pseudonymization, format handlers, policy.
7. §11 — verification, audit, and the mapping vault.
8. §12–§14 — API, testing, failure modes.
9. §15–§17 — phasing, open problems, references.

---

## 1. Problem and threat model

### 1.1 The problem

An Android bugreport (`bugreport-*.zip`, 10–200 MB) and an Apple sysdiagnose (`sysdiagnose_*.tar.gz`, 50–500 MB) are the two richest diagnostic artifacts a phone will produce. They are also the two artifacts most useful for detecting mobile compromise — process anomalies, suspicious installs, crash signatures from exploitation attempts, unexpected network configuration, MDM profiles the user did not install.

They are almost never shared, because they contain everything: the owner's email addresses, phone number, precise GPS coordinates, every Wi-Fi network they have joined, browsing history, contacts, iCloud account, IMEI, device serials, and a large volume of free-text logs that can contain literally anything an app decided to log.

The result is a bad equilibrium. Victims of mobile compromise cannot get help without handing a stranger their entire digital life. Researchers cannot build public corpora. Detection rules cannot be validated against real-world data.

`mobilediag2anon` targets exactly that gap: **transform the archive so that identifying information is gone, while everything a detection pipeline reads is preserved bit-for-bit or structure-for-structure.**

### 1.2 Threat model

| | |
|---|---|
| **Asset** | The identity, location, social graph, and behaviour of the device owner. |
| **Adversary** | Anyone who receives the anonymized archive: a researcher, a support forum, a public corpus, an attacker who scrapes it. Assume the recipient is competent, motivated, and has access to external data (leak databases, WiGLE-style BSSID geolocation, social media). |
| **Adversary capability** | Full read of the output; cross-referencing with public data; cross-referencing with *other* archives from the same tool. No access to the mapping vault (§11.3) or the pseudonymization key. |
| **Goal** | The adversary cannot determine who the device belongs to, where they have been, who they communicate with, or what they browse — and cannot link two archives from the same user unless the user chose to make them linkable. |
| **Explicitly out of scope** | An adversary who already knows the victim and is checking whether a specific archive is theirs (a fingerprinting/confirmation attack). Diagnostic archives contain enough behavioural structure — install timestamps, app sets, crash patterns — that confirmation is nearly always possible without any direct identifier. §16.2 explains why this cannot be fixed without destroying the evidence, and the tool must say so plainly rather than imply otherwise. |

### 1.3 Non-goals

- **Not a redaction tool.** Replacing values with `[REDACTED]` destroys the correlation that makes the archive useful (§2.1).
- **Not a filter.** It does not decide what is "interesting"; it rewrites identity, and preserves the rest.
- **Not a malware scanner.** It does not detect or remove compromise; that is what the extractor libraries and Sigma rules do, downstream.
- **Not a guarantee.** §14 is explicit about residual risk, and the tool's output must carry that statement.

---

## 2. Design principles

### 2.1 Pseudonymize consistently; do not redact

The owner's email appears in the AccountManager dump, in a package's data directory path, in a log line from a sync adapter, in a crash report's user field, and URL-encoded inside an HTTP log. Replacing each with `[REDACTED]` tells the analyst nothing. Replacing each with the *same* pseudonym — `user-a3f1@example.invalid` — preserves:

- **equality** — the analyst can see it is one account, not five;
- **joins across files** — the same account in a bugreport and a sysdiagnose maps identically when the same key is used;
- **cardinality** — "this device has 3 Google accounts" survives;
- **first-appearance ordering** — `user-1`, `user-2` numbering by first occurrence tells a story.

Pseudonyms are derived deterministically (§8), so consistency is automatic and requires no global rename table at rewrite time.

### 2.2 Preserve format, not just meaning

A substitution must satisfy the grammar of its context. A MAC address becomes another well-formed MAC. An IMEI becomes 15 digits. A UUID becomes a UUID of the same version nibble. An IPv4 becomes an IPv4. An e-mail becomes an e-mail with a reserved TLD.

Two reasons. First, downstream parsers use regexes and type coercions that break on malformed values — an `ssid` field that becomes `[REDACTED]` will still parse, but an `ip` field that does will not, and a `versionCode` that does will fail an integer parse and drop the whole record. Second, format-preserving substitution keeps the *shape* information that is sometimes evidence: a private `10.x` address is different from a public one, and that distinction should survive.

**Length preservation** is a softer requirement but worth honouring where cheap: several dumpsys sections are column-aligned tables (`BSSID  Frequency  RSSI  Age(sec)  SSID  Flags`), and while the in-house parsers use regexes, third-party tooling may use column offsets. Prefer same-length substitution when the entity type allows it; never sacrifice format validity for it.

### 2.3 Format-aware rewriting, never blind regex over bytes

A sysdiagnose contains binary plists, SQLite databases, gzip members, `.tar` members, Apple `tracev3` log archives, and CSV. Running a regex-and-replace over the raw bytes of a SQLite file corrupts its page checksums and free-list, and the file silently stops opening. Every container and every leaf format gets a handler that parses, rewrites in the parsed domain, and re-serializes (§9).

### 2.4 Fail closed

An unrecognized file inside the archive is **dropped, not passed through**, in the default profile. A parse failure on a file that is known to contain PII is a hard error, not a warning. The reason is asymmetric harm: a user who shares a partially-anonymized archive believing it clean is worse off than one whose tool refused to run.

Every drop and every failure appears in the audit report (§11.2), so the user can see what was removed and decide whether to loosen policy explicitly.

### 2.5 Evidence beats privacy on ties — but the user decides

Some values are both. Package names are the single most important IOC in a bugreport *and* can identify a person (a regional banking app plus a rare language pack narrows a user substantially). The tool's job is not to resolve that tension silently but to:

1. pick a defensible default (§5 gives one per entity),
2. make the alternative a one-flag change,
3. state in the audit report which choice was made and what it costs.

---

## 3. The correctness contract

This is the part that makes the tool trustworthy, and it is only possible because the extractor libraries exist.

**Contract:** for an archive *A* and its anonymized output *A′*,

> running `bugreport-extractor-library` (or `sysdiagnose-extractor-library`) plus the Sigma rule set over *A* and over *A′* must produce identical results, after applying the pseudonym mapping to the expected output.

Concretely, the test harness:

1. parses *A* with the extractor library → `J`;
2. anonymizes *A* → *A′* and a mapping *M*;
3. parses *A′* with the same library, same version, same parsers → `J′`;
4. applies *M* to `J` (rewriting every original value to its pseudonym) → `J_expected`;
5. asserts `J′ == J_expected`, structurally.

Any difference is a bug in the anonymizer: either it corrupted a file, changed a value it should not have, changed a length that a parser depended on, or missed a value that should have been mapped.

Additionally, the **detection contract**:

> the Sigma rule matches over *A* and *A′* must be identical in rule ID, count, and — modulo pseudonyms — matched fields.

`bugreport-extractor-library/docs/SIGMA_FIELDS.md` enumerates the fields detections consume. **That document is the authoritative preservation list**: every field named in it is evidence, and the anonymizer must justify touching any of them. Treat it as an input to the implementation, and add a test that fails when a new field appears there without a corresponding policy entry in §5.

Three practical notes:

- Some divergence is legitimate and must be *declared*, not discovered: dropping GPS coordinates changes the privacy parser's output. Encode these as an explicit allowed-divergence list, keyed by parser and field, reviewed by a human. An undeclared divergence fails the build.
- Run the contract at **three** policy profiles (§10), not just the default.
- The contract is a regression net, not a proof. It catches "we broke the file"; it does not catch "we left PII in". §11.1 covers the other direction.

---

## 4. What is in these archives

### 4.1 Android bugreport (`bugreport-<device>-<date>.zip`)

A ZIP containing:

| Member | Content | PII density |
|---|---|---|
| `dumpstate-<date>.txt` or `bugreport-*.txt` | The main artifact, 10–150 MB. ~100 `DUMP OF SERVICE <name>:` sections, `/proc` snapshots, `dumpsys` output for every system service. | **Very high** |
| `FS/` | Selected filesystem snapshots, `/data/misc/`, sometimes `/data/system/` fragments | High |
| `dumpstate_log.txt` | dumpstate's own log | Low |
| `version.txt` | Format version | None |
| `main_entry.txt` | Points at the dumpstate file | None |
| `*.png` / screenshots | Some OEMs attach a screenshot | **Very high — always drop** |
| `anr/`, `tombstones/` | ANR traces and native crash dumps | Medium (paths, memory contents) |
| `proto/*.proto` | Protobuf dumps on newer Android (`window`, `activity`, `package`) | High, and binary |

Inside `dumpstate.txt`, the sections that matter most, by parser:

- `DUMP OF SERVICE account:` — **AccountManager accounts**: `Account {name=<email>, type=com.google}`. The single densest PII source.
- `DUMP OF SERVICE user:` — `UserInfo{0:<owner name>:13}`, `Owner name:`
- `DUMP OF SERVICE wifi:` — SSIDs, BSSIDs, scan results with signal strength (geolocatable), saved network configs
- `DUMP OF SERVICE telephony.registry` / `iphonesubinfo` — IMEI, IMSI, ICCID, MSISDN, carrier, cell IDs
- `DUMP OF SERVICE bluetooth_manager:` — BT adapter MAC, paired device names ("Anthony's AirPods") and addresses
- `DUMP OF SERVICE location:` — **raw GPS coordinates** in the form `{fused, 52.392128,4.902320±14.69m, ...}` plus per-package location requests
- `DUMP OF SERVICE package:` — every installed package, install times, installer chain, data directories containing the user handle
- `DUMP OF SERVICE usagestats` / `batterystats` — per-app usage timelines (behavioural fingerprint)
- `DUMP OF SERVICE device_policy:` — MDM profiles, admin package names, organization name
- `SYSTEM LOG` / `EVENT LOG` / `RADIO LOG` — logcat buffers, **unbounded free text**
- `DUMP OF SERVICE netstats:` — per-UID traffic with remote endpoints

### 4.2 Apple sysdiagnose (`sysdiagnose_<date>_<device>.tar.gz`)

A tar.gz (occasionally tar.xz) with a `sysdiagnose_*` root directory. From the parser inventory in `sysdiagnose-extractor-library/src/parsers/`, the PII-relevant members:

| Path pattern | Content | PII density |
|---|---|---|
| `system_logs.logarchive/` | Apple unified log, binary `tracev3` + `dsc` shared caches. Contains *everything*. | **Very high, binary** |
| `logs/Accessibility/TCC.db` | SQLite: per-app privacy grants | Medium |
| `logs/**/knowledgeC.db` | SQLite: app usage, device activity, sometimes contacts | **Very high** |
| `logs/**/Safari*` history | SQLite: **browsing history** | **Very high** |
| `WiFi/*.plist`, `com.apple.wifi.known-networks.plist` | SSIDs, BSSIDs, join timestamps, geolocation-capable | **Very high** |
| `logs/MCState/Shared/profile-*.stub`, `MCSettingsEvents.plist` | MDM profiles, **organization name and email** | High |
| `logs/MobileActivation/mobileactivationd.log*` | Activation records, **Apple ID**, serials | **Very high** |
| `logs/MobileLockdown/lockdownd.log*` | Pairing records, device names, host identifiers | High |
| `logs/appinstallation/*.sqlitedb`, `logs/itunesstored/downloads.*.sqlitedb` | Purchase and install history tied to an Apple ID | High |
| `crashes_and_spins/*.ips` | Crash reports: JSON header + body. Paths contain the user's app containers; some contain memory strings. | Medium-high |
| `logs/Networking/*`, `netusage.sqlite` | Per-process network usage, endpoints | High |
| `brctl/` | iCloud/Brain container dumps, **email addresses** | High |
| `swcutil_show.txt` | Associated domains per app — reveals installed services | Medium |
| `ps.txt`, `taskinfo.txt`, `spindump-nosymbols.txt` | Process lists with container paths containing UUIDs | Medium |
| `security-sysdiagnose.txt` | Keychain metadata, **iCloud account state** | High |
| `logs/SystemVersion/SystemVersion.plist` | Build info | Low |
| `Preferences/` | Per-app preference plists — arbitrary app data | **Unbounded** |

The `.logarchive` deserves its own treatment (§9.6 and §16.1). It is binary, undocumented, enormous, and the highest-value *and* highest-risk component of the whole archive.

---

## 5. Entity taxonomy and policy

This table is the heart of the tool. Each row: what it is, where it appears, the default action, and the reasoning. The implementing agent should turn this into `policy/default.toml` verbatim.

Actions: **`pseudo`** (format-preserving pseudonym), **`keep`** (untouched), **`drop`** (field removed / file removed), **`generalize`** (replaced with a coarser value), **`shift`** (offset by a constant).

### 5.1 Direct identifiers — always `pseudo` or `drop`

| Entity | Examples / location | Action | Notes |
|---|---|---|---|
| Email address | AccountManager, MDM org email, `brctl`, activation logs, free text | `pseudo` | → `user-<8hex>@example.invalid`. Preserve the local/domain split; map domain separately so "same company" survives as `corp-<4hex>.invalid`. |
| Apple ID / Google account | Same as above | `pseudo` | Same generator as email. |
| Phone number (MSISDN) | telephony dumps, contacts in logs, `tel:` URIs | `pseudo` | Preserve `+`, country code, and total length. Use a reserved range (e.g. `+<cc>5550xxxxxxx`). Country code is arguably location data — see §5.4. |
| IMEI | `iphonesubinfo`, radio log | `pseudo` | 15 digits, **Luhn-valid** so parsers that validate accept it. Preserve the TAC (first 8 digits)? **No** — TAC identifies the exact model, which is already in the build fingerprint, so preserving it adds nothing and leaks nothing. Randomize wholly. |
| IMSI / ICCID | Same | `pseudo` | Length-preserving digits. IMSI's MCC/MNC identifies the carrier and country — treat as §5.4. |
| Device serial | `ro.serialno`, build fingerprint, lockdownd, ioreg | `pseudo` | Preserve character class and length; these vary by vendor. |
| UDID / ECID (iOS) | lockdownd, activation | `pseudo` | 40-hex or 25-digit forms. |
| Android ID / GSF ID / advertising ID | `dumpsys` various | `pseudo` | 16-hex / UUID forms. |
| Wi-Fi SSID | wifi dumps, known-networks plists, scan results | `pseudo` | → `SSID-<4hex>`, same length where possible. SSIDs are frequently `<Surname> Family` or a street address. |
| BSSID / any MAC | wifi, bluetooth, netstats | `pseudo` | Keep the locally-administered bit pattern and the OUI? **No.** BSSIDs are directly geolocatable via public wardriving databases; the OUI must go too. Emit from a reserved prefix. |
| Bluetooth device name | `bluetooth_manager` paired devices | `pseudo` | "Anthony's AirPods" → `BT-Device-<4hex>`. Preserve the *type* hint if it is a known product string (`AirPods`, `Tesla Model 3`) — that is device-class evidence, not identity. Implement as a whitelist of generic product strings. |
| User account name | `UserInfo{0:<name>:13}`, `Owner name:` | `pseudo` | → `User-<4hex>`. |
| GPS coordinates | location dumps: `{fused, 52.392128,4.902320±14.69m}` | **`drop`** | See §5.4 — this is the one case where the default destroys data. |
| Personal names in free text | logcat, crash reports | best-effort `pseudo` | See §16.3. |

### 5.2 Evidence — always `keep`

These must survive **bit-identical**. Every one is named in `SIGMA_FIELDS.md` or consumed by a parser.

| Entity | Why it must be kept |
|---|---|
| Package names (`com.*`) | The primary IOC. `installerPackageName`, `initiatingPackageName`, `originatingPackageName` are the entire sideloading-detection story. |
| UIDs, PIDs, PPIDs | Process lineage; IronSift preserves PPID throughout its pipeline for exactly this reason. |
| Timestamps | The timeline *is* the evidence. See §5.4 for the shift option. |
| Build fingerprint, Android/iOS version, security patch level | Vulnerability applicability. |
| Device model / manufacturer | Exploit applicability; also already public. |
| Permissions, granted/requested | Privilege escalation detection. |
| Install/update times, `codePath`, `packageSource`, `versionCode` | Install provenance. |
| Crash signatures, exception types, stack frames, faulting addresses | Exploitation evidence — the reason many of these archives get shared at all. |
| System process names, service names, binder transactions | Baseline behaviour. |
| Memory/battery/thermal statistics | Anomaly detection inputs. |
| SELinux denials, kernel messages | Compromise indicators. |
| Certificate hashes / signing digests | App authenticity. |
| MDM admin **package** names and policy flags | Stalkerware and unwanted-MDM detection — high-value. The *organization name* is PII (`pseudo`); the package and the policies are evidence (`keep`). |

### 5.3 Paths and container identifiers

Paths are a mixed case and need dedicated logic, not a regex.

| Pattern | Action |
|---|---|
| `/data/data/<pkg>/`, `/data/app/~~<hash>/<pkg>-<hash>/` | `keep` — package identity is evidence. |
| `/data/user/<N>/` , `/data/media/<N>/` | `keep` — N is a user *index*, not an identity. |
| `/storage/emulated/0/<...>/<filename>` | **`pseudo` the leaf filename, keep directories.** `Download/`, `DCIM/` are structure; `IMG_20250104_Amsterdam_with_Sarah.jpg` is not. |
| `/private/var/mobile/Containers/Data/Application/<UUID>/` | `pseudo` the UUID consistently — it joins across the archive and must stay joinable. |
| `/Users/<name>/` (from paired-host records in lockdownd) | `pseudo` the username component. |
| App-supplied paths in free text | Treat as free text (§16.3). |

### 5.4 The hard cases — where default policy is a judgement call

These need explicit flags and explicit documentation in the audit report.

**Timestamps.** Default: **`keep`**. The timeline is the evidence; an install at 03:47 followed by a crash at 03:48 is the finding. But absolute timestamps combined with an app set are strongly identifying, and correlate with external data (a known travel date, a public incident). Offer `--time-shift <duration>` applying a **single uniform offset to every timestamp in the archive**, preserving all deltas and orderings. Uniformity is essential and surprisingly hard: timestamps appear as ISO-8601, `MM-DD HH:MM:SS.mmm` (logcat, no year), epoch seconds, epoch milliseconds, Mach absolute time, Apple Cocoa epoch (2001-01-01), and Windows FILETIME in some plists. A shift that misses one format destroys correlation, which is worse than no shift. Ship the shift **off by default** and gate it behind a self-test that verifies round-trip on every known format in the corpus.

**GPS coordinates.** Default: **`drop` the coordinates, keep the event.** `{fused, 52.392128,4.902320±14.69m}` becomes `{fused, <redacted>±14.69m}`. The privacy parser's finding — *package X requested FINE location at time T with accuracy A* — is fully preserved; only the position is gone. Coordinates cannot be pseudonymized usefully: any distance-preserving transform is invertible given two known landmarks, and a random point destroys the data anyway. This is a declared divergence in §3's allowed list. `--keep-location` exists for the case where the user is investigating location abuse specifically and accepts the exposure.

**Package names of third-party apps.** Default: **`keep`**. They are the primary IOC and the reason the archive is being shared. But the *set* of installed apps is a strong fingerprint, and a rare app (a regional bank, a minority-language keyboard, a dating app for a specific community) can be directly identifying or reveal a protected attribute. Offer `--pseudo-third-party-packages`, which keeps every package matching a bundled allowlist of ~5 000 well-known packages (AOSP, GMS, major vendors, top apps, known stalkerware) and pseudonymizes the rest to `com.anon.pkg<8hex>`. Document loudly that this **breaks IOC matching for anything not on the allowlist** — including novel malware, which is precisely what an analyst is hunting. Off by default for that reason.

**Carrier / MCC-MNC / country code.** Default: **`keep`**. Carrier identity is relevant to SIM-swap and SS7 analysis and is coarse (country-level). Offer `--generalize-carrier` to reduce to country only, and `--drop-carrier`.

**Cell tower IDs (CID/LAC/eNB).** Default: **`drop`**. Cell IDs are geolocatable at street level through public databases, and their forensic value is low outside a narrow set of investigations. `--keep-cell-ids` to override.

**IP addresses.** Split by scope: private (RFC1918, CGNAT, link-local) → **`keep`**, they are topology not identity. Public → **`pseudo`**, because a home IP is an address. **Exception:** a public IP that appears in a *destination* position in netstats or a connection log may be a C2 server, which is the finding. Resolve by keeping public IPs that appear as connection destinations and pseudonymizing those that appear as the device's own address. When position cannot be determined, default to `pseudo` and log it as a possible IOC loss in the audit report.

**Domains and URLs.** Default: **`pseudo` the host, `drop` the path and query.** A URL's path routinely contains session tokens and identifiers. The host is often the IOC. Keep hosts matching a bundled list of well-known domains (`googleapis.com`, `icloud.com`, CDNs, ad networks) untouched; pseudonymize the rest to `host-<8hex>.invalid` **while preserving the registrable-domain / subdomain split** so that `a.evil.com` and `b.evil.com` visibly share a parent. Browsing history from Safari's SQLite is not an IOC and is dropped wholesale (§9.4).

**Free-text logs.** Default: **`pseudo` known entity patterns, `keep` the rest.** See §16.3 — this is the tool's largest residual risk and must be stated as such.

---

## 6. Architecture

### 6.1 Crates

```
mobilediag2anon/
  crates/
    m2a-core/        Entity model, pseudonymizer, policy engine, audit. No I/O.
    m2a-detect/      Detectors: regex, validators, contextual rules, encodings.
    m2a-format/      Leaf-format handlers: text, plist, sqlite, json/ips, csv, protobuf.
    m2a-container/   Archive handlers: zip, tar, gzip, xz, nested.
    m2a-android/     Bugreport-specific: dumpstate section map, per-section policy.
    m2a-apple/       Sysdiagnose-specific: member map, logarchive, per-file policy.
    m2a-cli/         `mobilediag2anon` binary.
    m2a-wasm/        wasm-bindgen wrapper for in-browser use.
  policy/            Bundled profiles + allowlists (packages, domains, product names).
  testdata/
  xtask/             Corpus fetch, contract-test driver, coverage reports.
```

`m2a-core`, `m2a-detect` and `m2a-format` must build for `wasm32-unknown-unknown`. This is not optional: the ecosystem this belongs to runs client-side in the browser precisely so the unanonymized archive never leaves the user's machine — and a privacy tool that requires you to upload the thing you are trying to protect is self-defeating. Native-only dependencies (`rusqlite` bundled, `xz2`, `memmap2`, `rayon`) go behind `#[cfg(not(target_arch = "wasm32"))]` with a WASM fallback path, exactly as the two extractor libraries already do.

### 6.2 Dependencies

Mirror the extractor libraries so the workspace stays coherent: `serde`/`serde_json`, `regex`, `plist` 1.9, `zip` 0.6 (deflate only, WASM-safe), `flate2`, `tar`, `globset`, `thiserror`, `tracing`. Add `hmac` + `sha2` (pseudonymization), `rand_chacha` (seeded fallbacks), `aes-gcm` + `argon2` (mapping vault). Native-only: `rusqlite` (bundled), `xz2`, `memmap2`, `rayon`.

### 6.3 Pipeline

```
 input archive
      │
      ▼
 ┌─────────────────┐
 │ 1. Inventory    │  walk containers recursively, classify every member
 │                 │  by (path pattern, magic bytes, parser affinity)
 └────────┬────────┘  → Inventory { members, unknown[], handler assignment }
          ▼
 ┌─────────────────┐
 │ 2. Discovery    │  run detectors over every member IN PARSE DOMAIN;
 │    (pass 1)     │  build the global EntityTable. No mutation.
 └────────┬────────┘  → EntityTable { value → Entity { kind, occurrences } }
          ▼
 ┌─────────────────┐
 │ 3. Resolution   │  canonicalize aliases (same email in 4 encodings),
 │                 │  apply policy, assign pseudonyms, detect conflicts
 └────────┬────────┘  → Mapping { original → replacement }
          ▼
 ┌─────────────────┐
 │ 4. Rewrite      │  per-member, format-aware substitution + re-serialize
 │    (pass 2)     │
 └────────┬────────┘
          ▼
 ┌─────────────────┐
 │ 5. Verify       │  residual scan of the OUTPUT; contract test hooks
 └────────┬────────┘
          ▼
 output archive + audit report (+ encrypted mapping vault)
```

**Why two passes.** A value discovered late must be replaced everywhere, including in members already processed. Discovery must also see *all* occurrences before deciding: an 11-digit number is only an IMEI if it appears in a telephony context, and a bare hex string is only a MAC if it validates and appears near network fields. Single-pass streaming cannot do either.

Memory: discovery stores only entity values and occurrence counts, not positions — positions are re-found in pass 2. An entity table for a 200 MB archive is a few MB.

### 6.4 Core types

```rust
pub enum EntityKind {
    Email, PhoneNumber, Imei, Imsi, Iccid, SerialNumber, Udid, AndroidId,
    MacAddress, Bssid, Ssid, BluetoothName,
    IpV4Public, IpV4Private, IpV6, DomainName, Url,
    Uuid, ContainerUuid,
    PersonName, UserName, OrganizationName,
    GpsCoordinate, CellId,
    FilePathLeaf, PackageName, Other(&'static str),
}

pub enum Action { Keep, Pseudo, Drop, Generalize(GeneralizeRule), Shift }

pub struct Entity {
    pub kind: EntityKind,
    pub canonical: String,       // normalized form used as the pseudonym input
    pub surface_forms: Vec<String>, // every encoding seen (plain, URL-enc, base64, case variants)
    pub occurrences: u32,
    pub first_seen: Location,
    pub confidence: Confidence,  // High | Medium | Low — drives strict-mode behaviour
}

pub struct Location { pub member: String, pub section: Option<String>, pub line: Option<u32> }
```

`surface_forms` is what makes replacement complete: an email found once in plain text and once URL-encoded is **one** entity with two surface forms, and pass 2 replaces both — the second with a URL-encoded pseudonym, so the containing document stays well-formed.

---

## 7. Detection

### 7.1 Detector trait

```rust
pub trait Detector: Send + Sync {
    fn kind(&self) -> EntityKind;
    /// Cheap prefilter: skip this chunk entirely if it cannot contain the entity.
    fn prefilter(&self, chunk: &str) -> bool { true }
    fn scan(&self, chunk: &str, ctx: &ScanContext, out: &mut Vec<Hit>);
}

pub struct ScanContext<'a> {
    pub member: &'a str,
    pub section: Option<&'a str>,   // e.g. "DUMP OF SERVICE wifi:"
    pub key_path: Option<&'a str>,  // e.g. "WiFi.KnownNetworks[3].SSID" for structured formats
    pub profile: &'a Profile,
}
```

### 7.2 Three detector families

**Structural** — the most reliable, and the one to prefer wherever it applies. For structured formats (plist, JSON, SQLite, CSV), the *key* tells you the type: a plist key `SSID` holds an SSID regardless of its value's shape. Build a key→`EntityKind` map from the two extractor libraries' field knowledge (`SIGMA_FIELDS.md` and the parser sources are the source of truth) and match on `key_path`. This handles values that no regex would catch — a Wi-Fi network literally named `192.168.1.1`, a user whose display name is `null`.

**Contextual** — for unstructured text with known grammar. The bugreport's `DUMP OF SERVICE <name>:` sections give the section name as context, and each section has a known line grammar. `Account {name=(.+?), type=(.+?)}` inside `DUMP OF SERVICE account:` is a high-confidence email-or-username capture in a way that a bare email regex over the whole file is not. Port the section-splitting logic from `bugreport-extractor-library` (`extract_dumpsys_section`) rather than reimplementing it — and add a test that both split the same way, so the two do not drift.

**Lexical** — regex plus validator, for free text where nothing else works. Always the lowest confidence. Every lexical detector pairs a pattern with a validator:

| Kind | Pattern sketch | Validator |
|---|---|---|
| Email | RFC-5322-lite | Domain has a valid TLD; reject `foo@2x` (retina asset names), reject known non-email `@` uses in log formats |
| IMEI | `\b\d{15}\b` | Luhn check; reject if the containing line has a timestamp-ish context |
| MAC | `([0-9a-f]{2}:){5}[0-9a-f]{2}` | Reject all-zero and broadcast; check it is not a timestamp (`12:34:56`) — require 6 groups and hex letters, or an explicit network context |
| IPv4 | dotted quad | Each octet ≤ 255; reject version strings (`1.2.3.4` as a version is common) by requiring network context or rejecting when preceded by `version`/`v` |
| Phone | `\+?\d[\d \-()]{7,}` | libphonenumber-style length check per country code; **very** prone to false positives against IDs and byte counts — require context |
| UUID | canonical 8-4-4-4-12 | Version nibble in 1..5 |
| GPS | `-?\d{1,3}\.\d{4,},-?\d{1,3}\.\d{4,}` | Lat ∈ [-90,90], lon ∈ [-180,180]; require ≥4 decimals (fewer is not a position) |

The false-positive cost is real and asymmetric to the false-negative cost: a missed email leaks; a wrongly-pseudonymized version string corrupts evidence and breaks §3's contract. Resolve by confidence tier — `High` (structural/contextual) always acts; `Medium` acts in `strict` and `balanced`; `Low` acts only in `strict` and is always listed in the audit report for review.

### 7.3 Encodings

Scan each text chunk in its literal form **and** in these derived forms, recording the surface form so pass 2 can re-encode:

- URL percent-encoding (`%40` for `@`)
- HTML entities
- Base64 — decode runs of ≥16 base64 chars, scan the result if it is valid UTF-8, and if a hit lands inside, replace the *whole* base64 blob with a re-encoded version
- JSON string escapes (`@`)
- Backslash-escaped and quoted forms inside log lines
- Case variants for case-insensitive entities (emails, domains, SSIDs are case-*sensitive* — do not fold SSIDs)

Do **not** attempt to detect PII inside compressed or encrypted blobs beyond one level of gzip; instead, classify such members as unknown and let §2.4's fail-closed rule drop them.

### 7.4 Already-hashed values

Diagnostic archives contain hashes of PII (e.g. hashed account identifiers in GMS logs). These are still linkable if the adversary can guess the input — an email has low entropy. Detect canonical hash shapes (32/40/64 hex) in contexts labelled as account/user identifiers and pseudonymize them too, preserving length. Do not pseudonymize hashes in signing-certificate or file-integrity contexts — those are evidence.

---

## 8. The pseudonymization engine

### 8.1 Derivation

```
key       = Argon2id(user_passphrase, salt = archive_id)   // or 32 random bytes
tag       = HMAC-SHA256(key, kind_tag || canonical_value)
pseudonym = format_for(kind, tag)
```

Properties this gives:
- **Deterministic** — the same value maps identically everywhere, in one run and across runs with the same key.
- **Unlinkable across users** — two archives anonymized with different keys produce unrelated pseudonyms for the same real value.
- **Linkable when wanted** — an investigator handling two archives from the same device uses the same key and gets a joinable pair. Expose this as `--key-file`, and document it as the deliberate feature it is.
- **Irreversible without the key** — HMAC, not a keyless hash, so an adversary cannot brute-force the low-entropy input space of e.g. phone numbers.

The last point is the reason for HMAC over SHA-256 alone. A keyless hash of a phone number is trivially reversible by enumeration; that mistake is common and fatal.

### 8.2 Format-preserving generators

```rust
pub trait Generator { fn generate(&self, tag: &[u8; 32], original: &str) -> String; }
```

| Kind | Output shape | Constraints |
|---|---|---|
| Email | `user-<8hex>@<domainpseudo>` | Domain mapped separately and consistently; TLD `.invalid` (RFC 2606) so it can never resolve. |
| Domain | `host-<8hex>.invalid` | Preserve label count so `a.b.evil.com` keeps its depth. |
| Phone | `+<cc>` + reserved prefix + digits | Same total length; use each country's reserved/fictional range where known, else `555`. |
| IMEI | 15 digits, Luhn-valid | Derive 14 from the tag, compute the check digit. |
| MAC/BSSID | `02:<5 tag bytes>` | `02` sets the locally-administered bit and clears multicast: unambiguously synthetic, never collides with a real OUI. |
| SSID | `SSID-<n hex>` padded/truncated to the original byte length | SSIDs are ≤32 bytes and may be non-UTF-8; operate on bytes. |
| UUID | canonical form, version nibble preserved | Container UUIDs must stay joinable, so derive from the canonical lowercase form. |
| IPv4 public | `198.51.100.x` / `203.0.113.x` (RFC 5737 doc ranges) | Never emit something routable. |
| Serial | Same length, same character class per position | Vendors differ; infer the class from the original. |
| Person/user name | `User-<4hex>` | Not length-preserving; these are rarely in fixed-width contexts. |
| Path leaf | `file-<8hex>` + original extension | Extension is evidence (a `.apk` in `Download/` matters). |

Every generator must be **injective in practice**: a 32-bit tag over a few thousand entities has a non-trivial birthday collision probability, so use ≥8 hex digits (32 bits) as a floor, detect collisions in the `Mapping` at build time, and extend the tag on conflict. A collision that merges two users' identities is a correctness failure, not a cosmetic one.

### 8.3 Ordinal pseudonyms

For entity kinds where a human-readable sequence helps (`User-1`, `SSID-3`), offer `--ordinal` which assigns numbers by **first appearance in archive order**. This is friendlier to read but leaks ordering information and is not stable across runs if the archive changes. Default off.

---

## 9. Format handlers

```rust
pub trait FormatHandler: Send + Sync {
    fn can_handle(&self, path: &str, magic: &[u8]) -> bool;
    fn discover(&self, bytes: &[u8], ctx: &ScanContext, out: &mut EntityTable) -> Result<()>;
    fn rewrite(&self, bytes: &[u8], map: &Mapping, ctx: &ScanContext) -> Result<Vec<u8>>;
}
```

### 9.1 Plain text / logs

Line-oriented, streaming. For bugreport `dumpstate.txt`, first split into `DUMP OF SERVICE` sections so `ScanContext.section` is populated — this is what upgrades most detections from `Low` to `High` confidence. Preserve line endings and trailing whitespace exactly; some parsers are whitespace-sensitive.

### 9.2 Property lists

`plist` 1.9 handles XML and binary. Parse to `plist::Value`, walk the tree with `key_path` populated, rewrite values, re-serialize **in the original encoding** (binary stays binary — some Apple tooling rejects XML where it expects bplist). Preserve dictionary key order where the format does.

### 9.3 SQLite

Open with `rusqlite`, enumerate tables and columns, apply a per-`(table, column)` policy derived from the structural map. Rewrite with `UPDATE` statements inside one transaction, then `VACUUM` to drop free-list remnants — **this step is mandatory**: deleted rows and old values persist in unvacuumed free pages and are trivially recoverable, which would defeat the whole exercise.

On WASM, `rusqlite` bundled is unavailable. Options, in order of preference: (a) compile SQLite to WASM alongside, (b) implement a minimal read-write path for the specific schemas involved, (c) **drop the file** in the WASM build and record it in the audit. Ship (c) initially and be explicit about it — a WASM build that silently passes SQLite files through would be a serious bug.

### 9.4 Databases that are dropped wholesale

Some SQLite files have no forensic value proportional to their PII load. Default `drop`, with `--keep-<name>` overrides:

- Safari history, Chrome history — browsing history
- `knowledgeC.db` — minute-by-minute behaviour (has *some* value for app-usage anomalies; offer `--knowledgec=metadata-only` keeping the app/bundle columns and dropping the rest)
- Contacts, Messages, Call history if present
- Photo libraries, thumbnails

Dropping is not silent: the audit lists each dropped member with its size and reason, so the recipient knows what is missing.

### 9.5 Crash reports (`.ips`, tombstones, ANR)

`.ips` is a JSON header line followed by a JSON body. Parse both. Keep: exception type, signal, faulting address, register state, binary images (path + UUID + load address), thread backtraces, `procName`, `bundleID`. Pseudonymize: container UUIDs in paths, user-visible app names if they embed a person's name, any `email`/`account` fields the crashing app attached. Tombstones and ANR traces are text: keep the whole structure, pseudonymize path leaves and any detected entity in log fragments.

Stack frames and memory dumps are evidence. Do not touch them — with one exception: a `memory near` hexdump in a tombstone can contain string data including PII. Scan decoded ASCII runs in hexdumps and, on a hit, **drop that hexdump block** rather than attempting to rewrite bytes in place (rewriting would change the hex and break address/content consistency, misleading an analyst).

### 9.6 The `.logarchive`

The hardest member, and the one that most determines whether the tool is actually useful. Options:

1. **Drop it entirely.** Safe, simple, and removes a large fraction of the archive's investigative value. This is the v1 default.
2. **Decode → filter → re-emit as JSONL.** `sysdiagnose-extractor-library` already has `logarchive-decode`, which can turn `tracev3` into structured events. Decode, run the full detection and rewrite pipeline over the structured events, and emit `logarchive_anonymized.jsonl` **in place of** the binary. This loses the ability to open the archive in Console.app but keeps every event available to the extractor library and to Sigma rules. **This is the right answer for v2** and should be the flagship feature.
3. Rewrite `tracev3` in place. Not worth it: the format is undocumented, includes shared string caches (`dsc`) where a single replacement of differing length would require rebuilding offset tables, and errors are silent.

Implement (1) for v1 and (2) for v2, with `--logarchive={drop,jsonl}`. Note that option 2 changes the archive's shape, so §3's contract needs a declared divergence: the `logarchive` parser will report events from a different source path.

### 9.7 Protobuf dumps

Newer Android bugreports include `proto/*.proto` binary dumps. Without the schema, field types are ambiguous. Parse as generic protobuf (field number + wire type), scan length-delimited fields that decode as valid UTF-8, rewrite those, and re-encode with corrected lengths. Fields that do not decode as text are passed through. Where a schema is available from AOSP, prefer it.

### 9.8 Images and media — always dropped

Screenshots attached to bugreports, any image in a sysdiagnose. No exceptions, no override flag. A screenshot defeats every other control in this document, and the audit report records the removal.

---

## 10. Policy and profiles

Policy is data, not code: TOML files in `policy/`, overridable by the user.

```toml
[profile]
name = "balanced"

[entity.email]      action = "pseudo"
[entity.gps]        action = "drop"
[entity.timestamp]  action = "keep"
[entity.ipv4_public] action = "pseudo"
[entity.package_name] action = "keep"

[[section_rule]]           # bugreport dumpsys sections
match  = "DUMP OF SERVICE location:"
detect = ["gps", "package_name"]

[[member_rule]]            # sysdiagnose members
match  = "logs/**/Safari*.db"
action = "drop"
reason = "browsing history; no proportionate forensic value"

[unknown_members] action = "drop"     # §2.4
```

Three shipped profiles:

| Profile | Use | Behaviour |
|---|---|---|
| **`strict`** | Public corpus, untrusted recipient | Acts on `Low`-confidence hits; drops all unknown members; drops logarchive; drops third-party package names; drops free-text log buffers whose content cannot be validated. Maximum privacy, real evidence loss. |
| **`balanced`** *(default)* | Sharing with a researcher or support channel | Everything in §5's defaults. |
| **`research`** | Trusted collaborator, internal use | Keeps location, cell IDs, full logarchive-as-JSONL, URLs with paths stripped only. **Prints a prominent warning** that the output is not safe for public release. |

`--explain` prints, for a given input, the action that will be taken on each detected entity kind and each member, without writing output. Users should be able to see the decisions before trusting them.

---

## 11. Verification and audit

### 11.1 Residual scan

After rewriting, re-run the **full detection pipeline over the output**, with all detectors at their most sensitive. Any `High`- or `Medium`-confidence hit that is not a known pseudonym is a leak:

- `strict`/`balanced`: the run **fails**, the output is deleted, and the finding is reported with its location.
- `research`: warn and continue.

This is the only automated check that addresses false negatives, and it is why detectors must be cheap enough to run twice.

Additionally, maintain a **canary corpus**: archives with known planted PII at known locations, including deliberately awkward placements (an email inside base64 inside a log line inside a gzip member inside the tar). A canary that survives is a release blocker.

### 11.2 Audit report

Emitted as `mobilediag2anon-report.json` plus a human-readable `.md`, alongside the output and **not** inside it.

```json
{
  "tool_version": "0.1.0",
  "profile": "balanced",
  "input":  { "sha256": "…", "bytes": 148000000, "kind": "android_bugreport" },
  "output": { "sha256": "…", "bytes": 131000000 },
  "entities": [ { "kind": "email", "count": 4, "action": "pseudo" },
                { "kind": "gps_coordinate", "count": 312, "action": "drop" } ],
  "members_dropped": [ { "path": "screenshot.png", "bytes": 240000, "reason": "image" } ],
  "members_unhandled": [],
  "declared_divergences": [ "privacy_parser.location.coordinates" ],
  "residual_scan": { "status": "clean", "findings": [] },
  "warnings": [ "3 low-confidence phone-number candidates were not replaced; review manually" ],
  "limitations": [ "Free-text log content is best-effort; see §16.3" ]
}
```

The report must never contain the original values — it is meant to be shared with the archive.

### 11.3 Mapping vault

The mapping (original → pseudonym) is the most sensitive artifact the tool produces. It is written **only** when `--vault <path>` is given, encrypted with AES-256-GCM under a key derived by Argon2id from a passphrase, in a separate file that must never accompany the anonymized archive. Its purpose: the original owner (or an investigator with the passphrase) can de-anonymize a specific finding — "which of my accounts is `user-a3f1`?" — without the recipient ever being able to.

The CLI refuses to write the vault into the same directory as the output without `--i-understand`, and the file is created `0600`.

---

## 12. Interfaces

### 12.1 CLI

```bash
mobilediag2anon --input bugreport-2026-09-16.zip --output bugreport-anon.zip

mobilediag2anon -i sysdiagnose_2026.tar.gz -o sysdiag-anon.tar.gz \
    --profile strict --logarchive jsonl \
    --key-file ~/.m2a/key --vault ./mapping.vault

mobilediag2anon --explain -i bugreport.zip          # dry run, print decisions
mobilediag2anon --verify -i bugreport-anon.zip      # residual scan on an existing output
mobilediag2anon --contract-test -i bugreport.zip    # §3, requires extractor libs
```

Exit codes: `0` clean; `1` residual PII found (output withheld); `2` unhandled member in a fail-closed profile; `3` input parse failure.

### 12.2 Library

```rust
let opts = AnonOptions::builder()
    .profile(Profile::Balanced)
    .key(Key::from_passphrase("…"))
    .logarchive(LogArchivePolicy::Jsonl)
    .build();

let result = mobilediag2anon::anonymize_bytes(&input_bytes, ArchiveKind::Auto, &opts)?;
result.output;   // Vec<u8>
result.report;   // AuditReport
result.mapping;  // Option<Mapping>  (only if requested)
```

### 12.3 WASM

`anonymize(input: Uint8Array, opts: JsValue) -> { output, report }`, with progress callbacks mirroring `bugreport-extractor-library`'s `progress.rs`. This is the deployment that matters most: it lets `ismyphonepwned.github.io` anonymize in the browser, so the raw archive never leaves the device. Memory is the constraint — a 500 MB sysdiagnose cannot be held three times over in a 4 GB WASM heap. Stream per-member: decompress one tar member, process, re-compress, release.

---

## 13. Testing

| Tier | What | Gate |
|---|---|---|
| **Unit** | Every detector against positive and negative fixtures; every generator for format validity, determinism, and injectivity | Always |
| **Format round-trip** | Parse → re-serialize with no changes → assert byte-identical, for plist (both encodings), SQLite, IPS, protobuf, zip, tar.gz | Always |
| **Canary** | Planted PII in adversarial encodings and nestings; assert zero survivors | Release blocker |
| **Contract (§3)** | Extractor-library output over *A* vs *A′*; Sigma matches identical | Release blocker |
| **Residual** | §11.1 over every corpus archive | Release blocker |
| **Differential vs sibling tools** | Compare against any existing sanitizers on the same input; differences reviewed | Advisory |
| **Property** | For random inputs: idempotence (anonymizing twice = once), determinism, key-sensitivity (different key ⇒ different pseudonyms) | Always |
| **Performance** | 200 MB bugreport and 500 MB sysdiagnose within a stated time and memory budget, native and WASM | Release blocker |

**Corpus.** Real archives are themselves PII, so the public test corpus must be synthetic or already-public: the [`sysdiagnose-testdata`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose-testdata) archives (already used by `sysdiagnose-extractor-library`), plus generated bugreports from emulators with planted synthetic identities. Keep any real-device corpus out of the repository, referenced by hash, and run it in a private CI job.

**Idempotence** deserves emphasis: `anonymize(anonymize(x)) == anonymize(x)`. Violations mean a generator is producing output its own detectors re-match — e.g. emitting `user-a3f1@example.invalid` which the email detector then re-pseudonymizes. Pseudonyms must be recognizable to the detectors as already-processed.

---

## 14. Failure modes

| Failure | Consequence | Mitigation |
|---|---|---|
| Missed entity in free text | PII leaks | §11.1 residual scan; canary corpus; explicit limitation statement in the report |
| Over-aggressive replacement | Evidence destroyed, contract fails | §3 contract test; confidence tiers; `--explain` |
| SQLite not vacuumed | Deleted rows recoverable from free pages | Mandatory `VACUUM`; test asserts no plaintext original survives in the output bytes |
| Length change breaks a column-aligned parser | Silent data loss downstream | Prefer length-preserving generators; contract test catches it |
| Pseudonym collision | Two identities merged | ≥32-bit tags, collision detection at mapping build, tag extension on conflict |
| Vault leaked alongside output | Full de-anonymization | Refuse same-directory write without `--i-understand`; `0600`; loud documentation |
| Keyless hashing of low-entropy values | Trivially reversible | HMAC with a secret key, never a bare hash (§8.1) |
| User assumes output is safe for public release | Harm | `research` profile prints a warning; report carries a limitations section; README leads with §16.2 |

---

## 15. Phasing

| Phase | Delivers | Gate |
|---|---|---|
| **P0** | Workspace, core types, HMAC pseudonymizer, generators, policy loader | Unit + property tests green |
| **P1** | Android bugreport: zip container, dumpstate section splitter, text handler, structural + contextual detectors for §5.1 | Contract test green on bugreport corpus; canary clean |
| **P2** | Audit report, residual scan, `--explain`, vault | Residual scan blocking in CI |
| **P3** | Sysdiagnose: tar.gz/xz container, plist handler, SQLite handler + VACUUM, IPS handler; logarchive **dropped** | Contract test green on `sysdiagnose-testdata` |
| **P4** | WASM build; integrate into `ismyphonepwned.github.io` | 500 MB archive within memory budget in-browser |
| **P5** | Logarchive → JSONL (§9.6 option 2); protobuf handler | Logarchive events reach Sigma rules post-anonymization |
| **P6** | Time-shift (§5.4), ordinal pseudonyms, `--pseudo-third-party-packages`, profile tuning from real usage | Shift round-trips every timestamp format in the corpus |

P1–P2 alone are a genuinely useful tool. Do not start P3 before the residual scan blocks in CI, or the sysdiagnose surface will be built on an unverified base.

---

## 16. Open problems

### 16.1 The logarchive

Option 2 in §9.6 is the right design but it is a significant piece of work and depends on `logarchive-decode`'s coverage. If decoding is incomplete, the anonymized JSONL is a lossy view and the tool must say which events were undecodable rather than implying completeness.

### 16.2 Re-identification by behavioural fingerprint

This tool removes identifiers. It does not — and largely cannot — remove the fingerprint formed by *which* apps are installed, *when* they were installed, crash patterns, and usage rhythm. An adversary who suspects a particular person can usually confirm it. Defeating that requires perturbing the install set and the timeline, which destroys exactly the evidence the archive exists to carry.

**The README must lead with this**, in plain language: *this tool makes an archive safe to share with someone who does not already know you; it does not make you anonymous to someone who is already investigating you.* Anything softer is a misrepresentation with real consequences for the people most likely to use it.

### 16.3 Free text

Logcat buffers, crash annotations and app preference plists contain arbitrary application-generated text: a note-taking app may log note titles, a messaging app a contact name. No pattern-based detector catches an arbitrary human name in arbitrary text, and an ML NER model is out of scope for a `no-network`, WASM-capable, deterministic tool — and would be unreliable across languages anyway.

The honest options, all of which should be available:

- `balanced`: pattern detectors only; report the limitation.
- `strict`: drop log buffers from third-party UIDs entirely, keep system UIDs. This preserves most detection value (system logs carry the security events) while removing most free-text risk. **This is the best available trade-off** and should probably become the `balanced` default once measured against the contract.
- A `--drop-text-from-packages <list>` escape hatch.

### 16.4 Cross-archive linkage

Two archives from the same device, anonymized with the same key, are linkable by design (§8.1). Two archives from *different* users anonymized with the same key are also linkable to each other in the sense that a shared Wi-Fi network produces the same pseudonym — which reveals that two people were on the same network. If that matters, per-archive random keys are the answer, at the cost of losing cross-archive joins. Make the trade-off explicit in the CLI (`--key random|file|passphrase`) and default to random.

---

## 17. References

**Formats**
- Android: [Read bug reports](https://source.android.com/docs/core/tests/debug/read-bug-reports); AOSP `frameworks/native/cmds/dumpstate` for section ordering and content
- Apple: sysdiagnose layout as enumerated by [EC-DIGIT-CSIRC/sysdiagnose](https://github.com/EC-DIGIT-CSIRC/sysdiagnose) (SAF); [`sysdiagnose-testdata`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose-testdata)
- RFC 2606 (`.invalid`, `.example`), RFC 5737 (documentation IPv4 ranges), RFC 3849 (documentation IPv6)

**In-tree — read these before implementing**
- `bugreport-extractor-library/docs/SIGMA_FIELDS.md` — **the authoritative preservation list** (§3)
- `bugreport-extractor-library/src/parsers/` — especially `account_parser.rs` (identity extraction), `network_parser.rs` (SSID/BSSID formats and the column-aligned scan table), `privacy_parser.rs` (GPS coordinate grammar), `package_parser.rs` (the fields that must survive)
- `bugreport-extractor-library/src/zip_utils.rs` — dumpstate member discovery, to mirror exactly
- `sysdiagnose-extractor-library/src/archive.rs` — member enumeration and path conventions
- `sysdiagnose-extractor-library/src/parsers/` — the 60+ member paths in §4.2 come from here; it is the map of what a sysdiagnose contains
- `sysdiagnose-extractor-library/logarchive-decode/` — the basis for §9.6 option 2

**Prior art to study** — Google's `bugreport` redaction in AOSP (limited); Apple's own sysdiagnose privacy notices; `mvt` (Mobile Verification Toolkit) for what mobile forensic consumers actually read; k-anonymity literature for why §16.2 is hard.

Where this document and a real archive disagree, the archive wins — and please fix this document.
