//! Leaf-format handlers: text, plist, sqlite, ips/json, protobuf.

mod ips;
mod plist_handler;
mod protobuf;
mod restore;
mod sqlite;
mod text;
mod time_shift;

use fm_core::{EntityTable, Mapping, Result};
use fm_core::AnonOptions;

pub use ips::IpsHandler;
pub use plist_handler::PlistHandler;
pub use protobuf::ProtobufHandler;
pub use restore::restore_member;
pub use sqlite::SqliteHandler;
pub use text::TextHandler;
pub use time_shift::{round_trip_self_test, shift_timestamps_in_text, TimeShiftFormats};

pub trait FormatHandler: Send + Sync {
    fn can_handle(&self, path: &str, magic: &[u8]) -> bool;
    fn discover(
        &self,
        path: &str,
        bytes: &[u8],
        table: &mut EntityTable,
        opts: &AnonOptions,
    ) -> Result<()>;
    fn rewrite(
        &self,
        path: &str,
        bytes: &[u8],
        map: &Mapping,
        opts: &AnonOptions,
    ) -> Result<Vec<u8>>;
}

pub struct HandlerSet {
    handlers: Vec<Box<dyn FormatHandler>>,
}

impl Default for HandlerSet {
    fn default() -> Self {
        Self {
            handlers: vec![
                Box::new(PlistHandler),
                Box::new(SqliteHandler),
                Box::new(IpsHandler),
                Box::new(ProtobufHandler),
                Box::new(TextHandler),
            ],
        }
    }
}

impl HandlerSet {
    pub fn find(&self, path: &str, bytes: &[u8]) -> Option<&dyn FormatHandler> {
        let magic = if bytes.len() >= 8 { &bytes[..8] } else { bytes };
        self.handlers
            .iter()
            .find(|h| h.can_handle(path, magic))
            .map(|h| h.as_ref())
    }

    pub fn discover(
        &self,
        path: &str,
        bytes: &[u8],
        table: &mut EntityTable,
        opts: &AnonOptions,
    ) -> Result<()> {
        if let Some(h) = self.find(path, bytes) {
            h.discover(path, bytes, table, opts)
        } else {
            // Unknown leaf: treat as text if utf-8, else leave for container fail-closed
            if std::str::from_utf8(bytes).is_ok() {
                TextHandler.discover(path, bytes, table, opts)
            } else {
                Ok(())
            }
        }
    }

    pub fn rewrite(
        &self,
        path: &str,
        bytes: &[u8],
        map: &Mapping,
        opts: &AnonOptions,
    ) -> Result<Vec<u8>> {
        if let Some(h) = self.find(path, bytes) {
            h.rewrite(path, bytes, map, opts)
        } else if std::str::from_utf8(bytes).is_ok() {
            TextHandler.rewrite(path, bytes, map, opts)
        } else {
            Ok(bytes.to_vec())
        }
    }
}
