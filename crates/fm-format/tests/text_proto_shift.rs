//! Text GPS drop, time-shift, protobuf UTF-8 field rewrite.

use fm_core::{AnonOptions, EntityTable, Key, Mapping};
use fm_format::{
    round_trip_self_test, shift_timestamps_in_text, FormatHandler, ProtobufHandler, TextHandler,
};
use std::time::Duration;

#[test]
fn gps_drop_preserves_accuracy_suffix() {
    let text = "DUMP OF SERVICE location:\n{fused, 52.392128,4.902320±14.69m, Bundle}\n";
    let opts = AnonOptions::builder()
        .key(Key::from_bytes([31u8; 32]))
        .build();
    let mut table = EntityTable::new();
    TextHandler
        .discover("dumpstate.txt", text.as_bytes(), &mut table, &opts)
        .unwrap();
    let map = Mapping::from_entities(
        &table.into_entities(),
        &Key::from_bytes([31u8; 32]),
        false,
    )
    .unwrap();
    let out = TextHandler
        .rewrite("dumpstate.txt", text.as_bytes(), &map, &opts)
        .unwrap();
    let s = String::from_utf8(out).unwrap();
    assert!(!s.contains("52.392128"));
    assert!(!s.contains("4.902320"));
    assert!(s.contains("<redacted>"));
    assert!(s.contains("±14.69m"), "accuracy must survive: {s}");
}

#[test]
fn time_shift_self_test_and_iso_logcat() {
    assert!(round_trip_self_test(Duration::from_secs(3600)));
    let iso = shift_timestamps_in_text("2024-06-01T12:34:56Z", Duration::from_secs(3600));
    assert!(iso.contains("13:34:56"));
    let lc = shift_timestamps_in_text("06-01 12:34:56.789", Duration::from_secs(60));
    assert!(lc.contains("12:35:56"));
}

#[test]
fn protobuf_rewrites_length_delimited_utf8() {
    // Manual protobuf: field 1, wire type 2 (len-delim), length, "hi leak@x.com!!"
    let msg = b"hi leak@x.com!!";
    let mut bytes = Vec::new();
    bytes.push((1 << 3) | 2); // tag
    bytes.push(msg.len() as u8);
    bytes.extend_from_slice(msg);

    let opts = AnonOptions::builder()
        .key(Key::from_bytes([41u8; 32]))
        .build();
    let mut table = EntityTable::new();
    ProtobufHandler
        .discover("proto/window.pb", &bytes, &mut table, &opts)
        .unwrap();
    assert!(table.iter().any(|e| e.kind == fm_core::EntityKind::Email));
    let map = Mapping::from_entities(
        &table.into_entities(),
        &Key::from_bytes([41u8; 32]),
        false,
    )
    .unwrap();
    let out = ProtobufHandler
        .rewrite("proto/window.pb", &bytes, &map, &opts)
        .unwrap();
    let hay = String::from_utf8_lossy(&out);
    assert!(!hay.contains("leak@x.com"));
}

#[test]
fn surfaceflinger_proto_path_is_protobuf_not_text() {
    let path = "proto/SurfaceFlinger_CRITICAL.proto";
    let mut bytes = b"SurfaceF".to_vec();
    bytes.push(0xff);
    bytes.extend_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7]);
    assert!(ProtobufHandler.can_handle(path, &bytes));
    let opts = AnonOptions::default();
    let mut table = EntityTable::new();
    ProtobufHandler
        .discover(path, &bytes, &mut table, &opts)
        .unwrap();
    let map = Mapping::from_entities(&[], &Key::from_bytes([7u8; 32]), false).unwrap();
    ProtobufHandler
        .rewrite(path, &bytes, &map, &opts)
        .expect("binary proto must not abort");
    TextHandler
        .discover(path, &bytes, &mut EntityTable::new(), &opts)
        .expect("invalid utf-8 text member must not abort");
    TextHandler
        .rewrite(path, &bytes, &map, &opts)
        .expect("invalid utf-8 rewrite keeps the member");
}
