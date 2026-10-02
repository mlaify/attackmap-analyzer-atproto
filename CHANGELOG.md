# Changelog

All notable changes to `attackmap-analyzer-atproto` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- XRPC handler routes carry their auth in the core contract (AttackMap#256). `Route.auth` is `required` when an `auth:` verifier is set, and `anonymous` for bare handlers or optional verifiers (`*Optional*`, `nullCreds`). `guards` and `guard_evidence` cite the verifier. The `atproto_auth:route_verifier:*` / `atproto_route_auth:anonymous:*` hints stay for older cores.

### Removed — committed test/bytecode caches

- **Untracked 9 cache files** that had been committed: `.pytest_cache/` (5 files) and `__pycache__/*.pyc` under `src/attackmap_analyzer_atproto/` and `tests/` (4 files). The existing `.gitignore` already lists `__pycache__/`, `.pytest_cache/`, `*.egg-info/`, `.venv/`, `build/` and `dist/`, so running the suite now leaves `git status` clean.

### Fixed — XRPC methods, fake lexicon routes, detect() and pattern scope (#2)

- **Routes only for XRPC endpoints, with their HTTP method.**
  - A lexicon yields a route only when `defs.main.type` is `query` (`GET`), `procedure` (`POST`) or `subscription` (`WS`).
  - `record`, `object` and defs-only lexicons such as `app.bsky.feed.post` and `app.bsky.actor.defs` no longer become `ANY /xrpc/<id>` routes. They are still lexicon `ProtocolHint`s.
  - **Breaking:** procedure/query routes were `ANY` and subscriptions were `SUBSCRIBE`.
- **Handler registrations and their per-endpoint auth.** `server.method('<nsid>', …)` and the generated `server.<nsid>({ auth, handler })` form now emit `/xrpc/<nsid>` routes. The method comes from the repo's lexicon, or is `ANY` when the lexicon isn't in the repo.
  - A configured `auth:` verifier is an `atproto_auth:route_verifier:<nsid>` `AuthHint` citing the `auth:` line. `test_signal_conformance.py` allows that prefix: the verifier is the endpoint's auth control.
  - A handler without one, or with an optional verifier (`*Optional*`, `nullCreds`), gets an `atproto_route_auth:anonymous:<nsid>` `ProtocolHint`. It is not an `AuthHint`, so core never counts it as an auth control.
  - Core's `Route` has no `auth` field on `main`, so per-route auth is carried by these hints.
- **`detect()` is gated on real AT Protocol evidence:**
  - a `lexicons/` dir
  - an `@atproto/*` / `@did-plc/*` dependency in any `package.json`
  - a lexicon document under a `lexicons/` path
  - a quoted NSID under a known authority
  - an `/xrpc/<nsid>` URL in JS/TS

  The `"lexicon"` substring and bare `/xrpc/` checks are gone. `package-lock.json`, `npm-shrinkwrap.json` and AttackMap's own `attackmap-report.json` / `review-context-pack.json` / `defensive-review.json` are never read. Other JSON is only parsed to recognize lexicon documents (`{"lexicon": 1, "id": …}`), anywhere in the repo, instead of being scanned as code.
- **Any NSID authority.** Namespace roots are the NSID's first two segments. `chat.bsky` and `tools.ozone` are built in, and any authority declared by a lexicon `id` in the repo (e.g. `sh.tangled`) is recognized in code. `/xrpc/<nsid>` literals accept any NSID.
- **Secrets are `process.env.*` only.** The quoted-constant pattern reported `'KEY'`, `"TOKEN"` and enum values. `process.env.X` / `process.env['X']` with `SECRET`/`TOKEN`/`KEY`/`PASSWORD`/`SIGNING` still match.
- **Auth cues no longer match prose.**
  - `atproto_identity:plc` needs `did:plc:`, `plc.directory`, `@did-plc/` or `PlcClient`, not the word "plc".
  - `atproto_crypto:signing` needs `@atproto/crypto`, a keypair type, a signing/verification API (`verifySignature`, `verifyJwt`, `createServiceJwt`, …) or `keypair.`/`signingKey.`/`crypto.` `sign(`/`verify(`, not the words "sign"/"verify".

### Changed — typed signals instead of overloaded `AuthHint`s (AttackMap#258)

- **`auth_hints` now carries only auth, identity and signing cues** (`atproto_auth:jwt`, `atproto_auth:service_auth`, `atproto_identity:did_reference`, `atproto_identity:plc`, `atproto_crypto:signing`). Protocol metadata moved to `ProtocolHint` (`protocol_hints`) with the same hint strings, which is where core's AT Protocol chain builder and `_extract_prefixed_hints` read every `atproto_` prefix from:
  - `atproto_lexicon:*`, `atproto_namespace:*`, `atproto_namespace_ref:*`, `atproto_xrpc_ref:*` → `ProtocolHint`
  - `atproto_protocol:xrpc`, `atproto_event_stream:*`, `atproto_repo:commit_flow` → `ProtocolHint`
  - `atproto_service_edge:*`, `atproto_service_note:*` → `ProtocolHint`. These describe services/edges, but core only reads `atproto_service_*` prefixes from `protocol_hints` (it reads `service_hints`/`edge_hints` only for `service_name:`/`edge:`), so they stay protocol hints to keep the AT Protocol chains intact.
- **Every signal now cites a line and quotes it.** Routes, external calls, auth/protocol hints and secret hints carry `line` and (where the model has it) `evidence_text` via `attackmap.sdk.line_of` / `line_snippet`. Lexicon signals point at the document's `"id"` line, the `SUBSCRIBE` route and `atproto_event_stream:subscription_lexicon` at the `"type": "subscription"` line, and `atproto_service_note:*` (derived from a `services/`/`packages/` path) is anchored at line 1 with `evidence_text: "inferred from path <file>"`. Protocol hints set `confidence` (0.9 lexicon documents, 0.8 namespace/XRPC references, 0.7 event streams, 0.6 keyword cues and service notes, 0.5 env-URL service edges).
- **Breaking for direct consumers of `ScanResult.auth_hints`:** code that looked for `atproto_lexicon:`/`atproto_namespace:`/etc. in `auth_hints` must read `protocol_hints`. AttackMap core already does.
- New `tests/test_signal_conformance.py` asserts every emitted `AuthHint.hint` is in an explicit auth allow-list and every signal has an in-range `line` and evidence.

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
