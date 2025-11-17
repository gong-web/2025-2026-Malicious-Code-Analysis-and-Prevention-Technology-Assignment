# YARA Rule Catalog

This directory is an automatically-generated catalog of every *.yar / *.yara file
sourced from `yara_rules` and `yara_rules_additional`. Originals remain untouched;
only categorized copies live here for easier indexing and database ingestion.

## Layout
- `core-compiled`: combined rule bundles from `yara_rules/compiled`.
- `core-organized`: curated categories under `yara_rules/organized`.
- `core-rules_repo`: upstream source sets under `yara_rules/rules_repo`.
- `additional-*`: community rule packs from `yara_rules_additional/organized`.

Each branch preserves the original relative subdirectories so rule provenance
can be traced directly via the manifest.

## Counts
- **core-compiled**: 2 files, 6637895 bytes
- **core-organized**: 1174 files, 12683262 bytes
- **core-rules_repo**: 553 files, 5904447 bytes
- **additional-bartblaze_Yara-rules-master**: 103 files, 152945 bytes
- **additional-Mandiant_Red_Team_Countermeasures**: 173 files, 431513 bytes
- **additional-Neo23x0_signature-base**: 729 files, 6967392 bytes
- **additional-reversinglabs-yara-rules-develop**: 310 files, 3385106 bytes

Manifest: `manifest.json`
