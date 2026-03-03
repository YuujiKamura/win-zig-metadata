# win-zig-metadata

`win-zig-metadata` will be the low-level WinMD reader layer.

## Initial plan

- Move WinMD table/stream readers from `win-zig-bindgen` into this repo
- Expose reusable APIs for:
  - PE metadata loading
  - table decoding
  - coded index resolution
  - type/namespace enumeration

## Status

Scaffold created. Implementation extraction pending.
