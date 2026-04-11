# AttackMap ATProto Analyzer

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
pip install git+https://gitlab.com/matthewd.xyzAI/attackmap-analyzers/attackmap-analyzer-atproto.git
```

## Usage

```bash
attackmap analyze /path/to/repo --module node-service --module atproto
```
