use fm_format::{PlistHandler, FormatHandler};
use fm_core::{AnonOptions, EntityTable, Key, Mapping};

#[test]
fn plist_xml_roundtrip_noop() {
    let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>SSID</key>
  <string>HomeNet</string>
  <key>version</key>
  <integer>1</integer>
</dict>
</plist>"#;
    let opts = AnonOptions::builder().key(Key::from_bytes([1u8; 32])).build();
    let mut table = EntityTable::new();
    PlistHandler
        .discover("WiFi/known.plist", xml, &mut table, &opts)
        .unwrap();
    assert!(table.iter().any(|e| e.kind == fm_core::EntityKind::Ssid));
    let entities = table.into_entities();
    let map = Mapping::from_entities(&entities, &Key::from_bytes([1u8; 32]), false).unwrap();
    let out = PlistHandler
        .rewrite("WiFi/known.plist", xml, &map, &opts)
        .unwrap();
    let text = String::from_utf8_lossy(&out);
    assert!(!text.contains("HomeNet"));
    assert!(text.contains("SSID-") || text.contains("<string>"));
}
