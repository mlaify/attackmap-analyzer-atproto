# AttackMap ATProto Analyzer

> [!IMPORTANT]
> **Active development, slow pace.** AttackMap is under active development, but
> progress may be slow until more contributors or co-maintainers join. Help is
> very welcome with the core engine, an analyzer, the macOS app, or the docs —
> see [CONTRIBUTING.md](CONTRIBUTING.md) or open an issue on
> [mlaify/AttackMap](https://github.com/mlaify/AttackMap/issues) to say hello.
> Security reports are still welcome at [security@mlaify.io](mailto:security@mlaify.io).

`attackmap-analyzer-atproto` is a thin protocol-aware overlay analyzer for AttackMap.

It is designed to enrich Node/TypeScript service scans (such as `node-service`) with
AT Protocol-specific exposure signals:
- protocol namespaces: `com.atproto.*`, `app.bsky.*`, `chat.bsky.*`, `tools.ozone.*`, plus any third-party authority declared by the repo's own lexicon `id`s (e.g. `sh.tangled.*`)
- lexicon-inferred XRPC endpoint surface. Only `defs.main` of type `query` (→ `GET`), `procedure` (→ `POST`) or `subscription` (→ `WS`) is an endpoint; `record`, `object` and defs-only lexicons are not.
- XRPC handler registrations (`server.method(nsid, …)`, generated `server.<nsid>({ auth, handler })`) with their per-endpoint auth:
  - a configured `auth:` verifier is an `atproto_auth:route_verifier:<nsid>` AuthHint
  - a handler with no verifier, or an optional one (`*Optional*`, `nullCreds`), is marked `atproto_route_auth:anonymous:<nsid>` (a ProtocolHint, so core never counts it as an auth control). Core's `Route` model has no auth field yet.
- protocol auth/signing/identity hints (`did:plc` / PLC directory, `@atproto/crypto` and signing/verification APIs; not the bare words "sign", "verify" or "plc")
- `process.env.*` secret references (not arbitrary quoted constants)
- event stream/subscription exposure hints
- service notes that complement service-level analyzers

This module is heuristic and intentionally lightweight.

`detect()` fires on a `lexicons/` directory, an `@atproto/*` (or `@did-plc/*`) dependency in any `package.json`, a lexicon document under a `lexicons/` path, a quoted NSID under a known authority, or an `/xrpc/<nsid>` URL in JS/TS source. Lockfiles (`package-lock.json`, `npm-shrinkwrap.json`) and AttackMap's own report files are never read. Other JSON files are only read to recognize lexicon documents.

## Install

```bash
pip install git+https://github.com/mlaify/attackmap-analyzer-atproto.git
```

## Usage

```bash
attackmap analyze /path/to/repo --module node-service --module atproto
```
