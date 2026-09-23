use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Email,
    PhoneNumber,
    Imei,
    Imsi,
    Iccid,
    SerialNumber,
    Udid,
    AndroidId,
    MacAddress,
    Bssid,
    Ssid,
    BluetoothName,
    IpV4Public,
    IpV4Private,
    IpV6,
    DomainName,
    Url,
    Uuid,
    ContainerUuid,
    PersonName,
    UserName,
    OrganizationName,
    GpsCoordinate,
    CellId,
    FilePathLeaf,
    PackageName,
    Timestamp,
    Carrier,
    Other,
}

impl EntityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::PhoneNumber => "phone_number",
            Self::Imei => "imei",
            Self::Imsi => "imsi",
            Self::Iccid => "iccid",
            Self::SerialNumber => "serial_number",
            Self::Udid => "udid",
            Self::AndroidId => "android_id",
            Self::MacAddress => "mac_address",
            Self::Bssid => "bssid",
            Self::Ssid => "ssid",
            Self::BluetoothName => "bluetooth_name",
            Self::IpV4Public => "ipv4_public",
            Self::IpV4Private => "ipv4_private",
            Self::IpV6 => "ipv6",
            Self::DomainName => "domain_name",
            Self::Url => "url",
            Self::Uuid => "uuid",
            Self::ContainerUuid => "container_uuid",
            Self::PersonName => "person_name",
            Self::UserName => "user_name",
            Self::OrganizationName => "organization_name",
            Self::GpsCoordinate => "gps_coordinate",
            Self::CellId => "cell_id",
            Self::FilePathLeaf => "file_path_leaf",
            Self::PackageName => "package_name",
            Self::Timestamp => "timestamp",
            Self::Carrier => "carrier",
            Self::Other => "other",
        }
    }

    pub fn from_str_lossy(s: &str) -> Option<Self> {
        Some(match s {
            "email" | "apple_id" | "google_account" => Self::Email,
            "phone" | "phone_number" | "msisdn" => Self::PhoneNumber,
            "imei" => Self::Imei,
            "imsi" => Self::Imsi,
            "iccid" => Self::Iccid,
            "serial" | "serial_number" => Self::SerialNumber,
            "udid" | "ecid" => Self::Udid,
            "android_id" | "gsf_id" | "advertising_id" => Self::AndroidId,
            "mac" | "mac_address" => Self::MacAddress,
            "bssid" => Self::Bssid,
            "ssid" => Self::Ssid,
            "bluetooth_name" | "bt_name" => Self::BluetoothName,
            "ipv4_public" => Self::IpV4Public,
            "ipv4_private" => Self::IpV4Private,
            "ipv6" => Self::IpV6,
            "domain" | "domain_name" => Self::DomainName,
            "url" => Self::Url,
            "uuid" => Self::Uuid,
            "container_uuid" => Self::ContainerUuid,
            "person_name" => Self::PersonName,
            "user_name" | "username" => Self::UserName,
            "organization_name" | "org" => Self::OrganizationName,
            "gps" | "gps_coordinate" | "location" => Self::GpsCoordinate,
            "cell_id" | "cid" | "lac" => Self::CellId,
            "file_path_leaf" | "path_leaf" => Self::FilePathLeaf,
            "package_name" | "package" => Self::PackageName,
            "timestamp" => Self::Timestamp,
            "carrier" | "mcc_mnc" => Self::Carrier,
            _ => return None,
        })
    }

    /// Kind tag used as HMAC input prefix.
    pub fn kind_tag(self) -> &'static [u8] {
        self.as_str().as_bytes()
    }

    /// Every selectable kind, stable order.
    pub fn all() -> &'static [EntityKind] {
        &[
            Self::Email,
            Self::PhoneNumber,
            Self::Imei,
            Self::Imsi,
            Self::Iccid,
            Self::SerialNumber,
            Self::Udid,
            Self::AndroidId,
            Self::MacAddress,
            Self::Bssid,
            Self::Ssid,
            Self::BluetoothName,
            Self::IpV4Public,
            Self::IpV4Private,
            Self::IpV6,
            Self::DomainName,
            Self::Url,
            Self::Uuid,
            Self::ContainerUuid,
            Self::PersonName,
            Self::UserName,
            Self::OrganizationName,
            Self::GpsCoordinate,
            Self::CellId,
            Self::FilePathLeaf,
            Self::PackageName,
            Self::Timestamp,
            Self::Carrier,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Keep,
    Pseudo,
    Drop,
    Generalize,
    Shift,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Keep => "keep",
            Self::Pseudo => "pseudo",
            Self::Drop => "drop",
            Self::Generalize => "generalize",
            Self::Shift => "shift",
        }
    }

    pub fn from_str_lossy(s: &str) -> Option<Self> {
        Some(match s {
            "keep" => Self::Keep,
            "pseudo" => Self::Pseudo,
            "drop" => Self::Drop,
            "generalize" => Self::Generalize,
            "shift" => Self::Shift,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub member: String,
    pub section: Option<String>,
    pub line: Option<u32>,
    pub key_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entity {
    pub kind: EntityKind,
    pub canonical: String,
    pub surface_forms: Vec<String>,
    pub occurrences: u32,
    pub first_seen: Location,
    pub confidence: Confidence,
    pub action: Action,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub kind: EntityKind,
    pub value: String,
    pub canonical: String,
    pub confidence: Confidence,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Default)]
pub struct EntityTable {
    /// key: (kind, canonical)
    inner: HashMap<(EntityKind, String), Entity>,
}

impl EntityTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_hit(&mut self, hit: Hit, loc: Location, action: Action) {
        let key = (hit.kind, hit.canonical.clone());
        if let Some(ent) = self.inner.get_mut(&key) {
            ent.occurrences += 1;
            if !ent.surface_forms.iter().any(|s| s == &hit.value) {
                ent.surface_forms.push(hit.value);
            }
            if hit.confidence > ent.confidence {
                ent.confidence = hit.confidence;
            }
        } else {
            self.inner.insert(
                key,
                Entity {
                    kind: hit.kind,
                    canonical: hit.canonical,
                    surface_forms: vec![hit.value],
                    occurrences: 1,
                    first_seen: loc,
                    confidence: hit.confidence,
                    action,
                },
            );
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Entity> {
        self.inner.values()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn into_entities(self) -> Vec<Entity> {
        self.inner.into_values().collect()
    }
}
