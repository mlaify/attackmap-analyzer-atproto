# Changelog

All notable changes to `attackmap-analyzer-atproto` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed — AttackMap#253

- **Repo walking now uses `attackmap.sdk.fs`.** `detect()` and `analyze()` walk with `iter_repo_files` and read with `read_source`. Skip dirs are matched by repo-relative name and pruned, so a repo checked out under a `build/`, `dist/` or `out/` directory is analyzed instead of yielding nothing.
- **AttackMap's own output is no longer read.** The analyzer reads every `*.json`; it used to pick up a previous run's `attackmap-report.json` (and `.attackmap-gui/`) and echo old NSIDs back into the new scan.
- **Symlinked files pointing outside the repo are not analyzed**, unreadable files no longer raise out of `detect()`/`analyze()`, and cp1252/latin-1 sources are decoded instead of dropped.
- `detect()` matches `com.atproto` / `app.bsky` in the repo-relative path only, so a checkout under a directory with such a name is no longer detected on that basis alone.

### Changed

- **Priority 35 → 90** (AttackMap#221). Core now runs analyzers in `(priority, name)` order and merges first-seen-wins, so this protocol overlay runs after the broad `node-service` analyzer (25). Still experimental and opt-in: `attackmap analyze <repo> -m atproto`.
- Skip list is now the SDK's `DEFAULT_SKIP_DIRS` (adds `out`, `target`, `vendor`, virtualenvs and caches).
- Signal `file` paths are always POSIX-style, including on Windows.
- Requires an AttackMap core that ships `attackmap.sdk.fs`.

## [0.1.0] - 2026-06-04

### Added

- Initial public release. Thin AT Protocol overlay analyzer plugin for AttackMap
- Registered under the `attackmap.analyzers` entry-point group so the core
  AttackMap CLI auto-discovers this analyzer once installed.
- Emits Signal-v2 records (`file:line` citation, evidence text, and confidence
  score) for every signal.

[Unreleased]: https://github.com/mlaify/attackmap-analyzer-atproto/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mlaify/attackmap-analyzer-atproto/releases/tag/v0.1.0
