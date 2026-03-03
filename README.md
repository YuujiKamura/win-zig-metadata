# win-zig-metadata

`win-zig-metadata` is the low-level WinMD reader layer.

## Current scope

- `pe.zig`: PE/CLI header parsing
- `metadata.zig`: .NET metadata stream discovery
- `streams.zig`: #Strings/#Blob/#GUID heap access
- `tables.zig`: metadata table row/index decoding
- `coded_index.zig`: coded index helpers

## Build

- `zig build test`
