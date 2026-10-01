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
- protocol namespaces (`com.atproto.*`, `app.bsky.*`)
- lexicon-inferred XRPC endpoint surface
- protocol auth/signing/identity hints
- event stream/subscription exposure hints
- service notes that complement service-level analyzers

This module is heuristic and intentionally lightweight.

## Install

```bash
pip install git+https://github.com/mlaify/attackmap-analyzer-atproto.git
```

## Usage

```bash
attackmap analyze /path/to/repo --module node-service --module atproto
```
