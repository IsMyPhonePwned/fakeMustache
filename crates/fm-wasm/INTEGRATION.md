# WASM / browser integration

`fm-wasm` exposes:

```js
import init, { anonymize, version } from "./fakemustache.js";
await init();
const result = anonymize(uint8Array, {
  profile: "balanced",
  passphrase: optionalPassphrase,
  logarchive: "drop", // or "jsonl" when native decode is available
});
// result.output — Uint8Array anonymized archive
// result.report_json — audit JSON (no original values)
```

## Memory

Process **per member**: decompress one tar/zip member, discover/rewrite, re-compress, drop buffers. Do not hold the raw archive, working copy, and output simultaneously for 500 MB inputs.

## Site hook

`ismyphonepwned.github.io` should call this **before** any upload or extractor path so the unanonymized archive never leaves the device. Site integration is a separate PR; this crate is the API contract.
