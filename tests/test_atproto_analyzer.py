import json
import shutil
import sys
from pathlib import Path

import pytest
from attackmap.safe_fs import OUTPUT_MARKER

from attackmap.sdk.contracts import AnalyzerMetadata as SharedAnalyzerMetadata
from attackmap.sdk.models import ScanResult as SharedScanResult
from attackmap.sdk import AnalyzerMetadata, ScanResult
from attackmap_analyzer_atproto import AtprotoAnalyzer

FIXTURES = Path(__file__).parent / "fixtures"


def test_contracts_use_shared_sdk_types() -> None:
    assert AnalyzerMetadata is SharedAnalyzerMetadata
    assert ScanResult is SharedScanResult


def test_metadata_contains_required_fields() -> None:
    analyzer = AtprotoAnalyzer()
    metadata = analyzer.metadata

    assert metadata.name == "atproto"
    assert metadata.display_name == "AT Protocol Analyzer"
    assert metadata.version == "0.1.0"
    assert metadata.description
    assert metadata.scope
    assert "atproto" in metadata.targets
    assert "json" in metadata.languages


def test_detect_identifies_atproto_style_repo() -> None:
    analyzer = AtprotoAnalyzer()
    assert analyzer.detect(FIXTURES / "atproto_like_repo") is True


def test_analyze_extracts_protocol_surface_and_hints() -> None:
    analyzer = AtprotoAnalyzer()
    result = analyzer.analyze(FIXTURES / "atproto_like_repo")

    route_keys = {(route.path, route.method) for route in result.routes}
    auth_hints = {hint.hint for hint in result.auth_hints}
    protocol_hints = {hint.hint for hint in result.protocol_hints}
    external_targets = {call.target for call in result.external_calls}
    secret_names = {secret.name for secret in result.secret_hints}

    # XRPC binding (#2): procedure = POST, subscription = WebSocket.
    assert ("/xrpc/com.atproto.server.createSession", "POST") in route_keys
    assert ("/xrpc/com.atproto.sync.subscribeRepos", "WS") in route_keys

    # Protocol metadata is a ProtocolHint (AttackMap#258) ...
    assert "atproto_namespace:com.atproto" in protocol_hints
    assert "atproto_namespace:app.bsky" in protocol_hints
    assert "atproto_lexicon:com.atproto.server.createSession" in protocol_hints
    assert "atproto_protocol:xrpc" in protocol_hints
    assert "atproto_event_stream:subscription_lexicon" in protocol_hints
    assert "atproto_service_edge:relay" in protocol_hints
    assert "atproto_service_note:pds" in protocol_hints
    # ... while auth, identity and signing cues stay AuthHints.
    assert auth_hints == {
        "atproto_auth:jwt",
        "atproto_identity:did_reference",
        "atproto_identity:plc",
        "atproto_crypto:signing",
        # The fixture's `server.add(com.atproto.sync.subscribeRepos, { auth: … })` (#14).
        "atproto_auth:route_verifier:com.atproto.sync.subscribeRepos",
    }

    assert "env://RELAY_URL" in external_targets
    assert "REPO_SIGNING_KEY" in secret_names


def test_analyze_returns_core_compatible_scan_shape() -> None:
    analyzer = AtprotoAnalyzer()
    result = analyzer.analyze(FIXTURES / "atproto_like_repo")

    assert isinstance(result.root, str)
    assert isinstance(result.files_scanned, int)
    assert isinstance(result.languages, list)
    assert hasattr(result, "routes")
    assert hasattr(result, "external_calls")
    assert hasattr(result, "databases")
    assert hasattr(result, "auth_hints")
    assert hasattr(result, "secret_hints")


def test_metadata_priority_and_opt_in() -> None:
    # Core runs analyzers in (priority, name) order and merges first-seen-wins
    # (AttackMap#221): this overlay runs after node-service (25) and stays
    # opt-in via `-m atproto`.
    metadata = AtprotoAnalyzer().metadata
    assert metadata.priority == 90
    assert metadata.enabled_by_default is False


# ---------------------------------------------------------------------------
# Repo walking via attackmap.sdk.fs (AttackMap#253)
# ---------------------------------------------------------------------------


def test_repo_checked_out_under_build_dir_is_still_analyzed(tmp_path: Path) -> None:
    # Skip dirs used to be matched against absolute path parts, so a repo
    # under any `build/` directory yielded nothing at all.
    repo = tmp_path / "build" / "out" / "repo"
    shutil.copytree(FIXTURES / "atproto_like_repo", repo)
    analyzer = AtprotoAnalyzer()
    assert analyzer.detect(repo) is True
    result = analyzer.analyze(repo)
    assert result.files_scanned > 0
    assert ("/xrpc/com.atproto.server.createSession", "POST") in {(r.path, r.method) for r in result.routes}
    assert "atproto_service_note:pds" in {h.hint for h in result.protocol_hints}


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_symlinked_source_outside_repo_is_not_analyzed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.ts").write_text("fetch('/xrpc/app.bsky.outside.secret');\nprocess.env.OUTSIDE_SECRET_KEY;\n")
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURES / "atproto_like_repo", repo)
    (repo / "packages" / "pds" / "src" / "linked.ts").symlink_to(outside / "secret.ts")

    result = AtprotoAnalyzer().analyze(repo)
    assert "/xrpc/app.bsky.outside.secret" not in {r.path for r in result.routes}
    assert "OUTSIDE_SECRET_KEY" not in {s.name for s in result.secret_hints}


def test_attackmap_report_output_is_not_analyzed(tmp_path: Path) -> None:
    # A previous run's JSON report mentions every NSID it found; reading it
    # back would echo old findings into the new scan.
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURES / "atproto_like_repo", repo)
    reports = repo / "reports"
    reports.mkdir()
    (reports / OUTPUT_MARKER).write_text("")
    (reports / "attackmap-report.json").write_text('{"routes": ["/xrpc/app.bsky.stale.fromReport"]}')
    gui = repo / ".attackmap-gui"
    gui.mkdir()
    (gui / "last.json").write_text('{"nsid": "app.bsky.stale.fromGui"}')

    result = AtprotoAnalyzer().analyze(repo)
    hints = [*result.auth_hints, *result.protocol_hints]
    files = {h.file for h in hints} | {r.file for r in result.routes}
    assert not any(f.startswith(("reports/", ".attackmap-gui/")) for f in files)
    assert not any("stale" in h.hint for h in hints)


def test_detect_ignores_atproto_names_above_the_repo(tmp_path: Path) -> None:
    repo = tmp_path / "app.bsky" / "repo"
    repo.mkdir(parents=True)
    (repo / "main.py").write_text("print('hello')\n")
    assert AtprotoAnalyzer().detect(repo) is False


def test_lexicon_signals_cite_the_id_and_subscription_lines() -> None:
    result = AtprotoAnalyzer().analyze(FIXTURES / "atproto_like_repo")
    lexicon = "lexicons/com/atproto/sync/subscribeRepos.json"
    by_hint = {h.hint: h for h in result.protocol_hints if h.file == lexicon}
    assert by_hint["atproto_lexicon:com.atproto.sync.subscribeRepos"].evidence_text.startswith('"id"')
    assert by_hint["atproto_event_stream:subscription_lexicon"].evidence_text == '"type": "subscription"'
    # The lexicon declares the endpoint (#14): a hint at the subscription line, no route.
    declared = by_hint["atproto_xrpc_declared:com.atproto.sync.subscribeRepos"]
    assert declared.line == by_hint["atproto_event_stream:subscription_lexicon"].line
    assert declared.evidence_text.startswith("WS /xrpc/com.atproto.sync.subscribeRepos")
    assert not any(r.file == lexicon for r in result.routes)


# ---------------------------------------------------------------------------
# XRPC methods, record/defs lexicons, detect(), NSIDs, secrets, auth (#2)
# ---------------------------------------------------------------------------

OVERLAY = "atproto_overlay_repo"


def _routes(fixture: str = OVERLAY) -> set[tuple[str, str]]:
    return {(r.path, r.method) for r in AtprotoAnalyzer().analyze(FIXTURES / fixture).routes}


def test_record_and_defs_lexicons_produce_no_routes() -> None:
    paths = {path for path, _method in _routes()}
    assert "/xrpc/app.bsky.feed.post" not in paths  # record
    assert "/xrpc/app.bsky.actor.defs" not in paths  # defs-only
    # They are still lexicon metadata.
    hints = {h.hint for h in AtprotoAnalyzer().analyze(FIXTURES / OVERLAY).protocol_hints}
    assert {"atproto_lexicon:app.bsky.feed.post", "atproto_lexicon:app.bsky.actor.defs"} <= hints


def test_query_procedure_subscription_map_to_get_post_ws() -> None:
    routes = _routes()
    assert ("/xrpc/app.bsky.feed.getTimeline", "GET") in routes  # query
    assert ("/xrpc/sh.tangled.repo.create", "POST") in routes  # procedure
    assert ("/xrpc/com.atproto.sync.subscribeRepos", "WS") in _routes("atproto_like_repo")  # subscription
    assert not any(method in {"ANY", "SUBSCRIBE"} for path, method in routes if path != "/xrpc/app.bsky.feed.getPostThread")


def test_lockfile_mentioning_lexicon_does_not_trigger_detect(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "web", "dependencies": {"react": "^18"}}')
    (tmp_path / "package-lock.json").write_text(
        '{"packages": {"node_modules/lexicon-parser": {"version": "1.0.0", "resolved": "https://x/xrpc/a"}}}'
    )
    (tmp_path / "index.js").write_text("// see the lexicon page in our docs\nconsole.log('hi');\n")
    assert AtprotoAnalyzer().detect(tmp_path) is False


def test_detect_fires_on_atproto_dependency_or_nsid_literal(tmp_path: Path) -> None:
    pkg = tmp_path / "packages" / "client"
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text('{"name": "client", "dependencies": {"@atproto/api": "^0.13.0"}}')
    assert AtprotoAnalyzer().detect(tmp_path) is True

    other = tmp_path / "other"
    other.mkdir()
    (other / "feed.ts").write_text("export const FEED = 'app.bsky.feed.generator';\n")
    assert AtprotoAnalyzer().detect(other) is True


def test_attackmap_report_at_repo_root_is_not_read(tmp_path: Path) -> None:
    (tmp_path / "attackmap-report.json").write_text('{"lexicon": 1, "id": "app.bsky.stale.report", "defs": {}}')
    assert AtprotoAnalyzer().detect(tmp_path) is False
    result = AtprotoAnalyzer().analyze(tmp_path)
    assert result.files_scanned == 0


def test_third_party_nsids_are_recognized() -> None:
    result = AtprotoAnalyzer().analyze(FIXTURES / OVERLAY)
    hints = {h.hint for h in result.protocol_hints}
    assert "atproto_namespace:sh.tangled" in hints
    assert "atproto_lexicon:sh.tangled.repo.create" in hints
    # The code-side handler registration is linked too, with the lexicon's method.
    assert ("/xrpc/sh.tangled.repo.create", "POST", "src/server.ts") in {
        (r.path, r.method, r.file) for r in result.routes
    }


def test_quoted_constants_are_not_secrets_but_env_secrets_are() -> None:
    names = {s.name for s in AtprotoAnalyzer().analyze(FIXTURES / OVERLAY).secret_hints}
    assert "KEY" not in names
    assert "TOKEN" not in names
    assert "PDS_JWT_SECRET" in names


def test_prose_sign_verify_plc_are_not_auth_hints() -> None:
    hints = {h.hint for h in AtprotoAnalyzer().analyze(FIXTURES / OVERLAY).auth_hints}
    assert "atproto_crypto:signing" not in hints
    assert "atproto_identity:plc" not in hints


def test_handlers_without_an_auth_verifier_are_marked_anonymous() -> None:
    result = AtprotoAnalyzer().analyze(FIXTURES / OVERLAY)
    anonymous = {h.hint for h in result.protocol_hints if h.hint.startswith("atproto_route_auth:anonymous:")}
    assert anonymous == {
        "atproto_route_auth:anonymous:sh.tangled.repo.create",  # bare handler function
        "atproto_route_auth:anonymous:app.bsky.feed.getPostThread",  # optional verifier
    }
    verified = [h for h in result.auth_hints if h.hint.startswith("atproto_auth:route_verifier:")]
    assert [h.hint for h in verified] == ["atproto_auth:route_verifier:app.bsky.feed.getTimeline"]
    assert verified[0].evidence_text == "auth: ctx.authVerifier.standard,"
    # The anonymous marker is never an AuthHint (core would count it as a control).
    assert not any("anonymous" in h.hint for h in result.auth_hints)


def test_handler_routes_carry_declared_auth_state() -> None:
    """Route.auth / guards / guard_evidence (AttackMap#256)."""
    result = AtprotoAnalyzer().analyze(FIXTURES / OVERLAY)
    handler_files = {h.file for h in result.auth_hints if h.hint.startswith("atproto_auth:route_verifier:")}
    by_nsid = {r.path.removeprefix("/xrpc/"): r for r in result.routes if r.file in handler_files}
    timeline = by_nsid["app.bsky.feed.getTimeline"]
    assert timeline.auth == "required"
    assert timeline.guards == ["auth: ctx.authVerifier.standard"]
    assert by_nsid["app.bsky.feed.getPostThread"].auth == "anonymous"  # optional verifier
    assert by_nsid["sh.tangled.repo.create"].auth == "anonymous"  # bare handler


# ---------------------------------------------------------------------------
# `server.add(<lexicon>, {auth, handler})` and lexicon-only endpoints (#14)
# ---------------------------------------------------------------------------

_LEXICONS = {
    "lexicons/app/bsky/actor/putPreferences.json": '{"lexicon": 1, "id": "app.bsky.actor.putPreferences", "defs": {"main": {"type": "procedure"}}}',
    "lexicons/app/bsky/actor/getProfile.json": '{"lexicon": 1, "id": "app.bsky.actor.getProfile", "defs": {"main": {"type": "query"}}}',
    "lexicons/com/atproto/server/createSession.json": '{"lexicon": 1, "id": "com.atproto.server.createSession", "defs": {"main": {"type": "procedure"}}}',
    "lexicons/app/bsky/feed/getTimeline.json": '{"lexicon": 1, "id": "app.bsky.feed.getTimeline", "defs": {"main": {"type": "query"}}}',
    "lexicons/app/bsky/feed/getFeed.json": '{"lexicon": 1, "id": "app.bsky.feed.getFeed", "defs": {"main": {"type": "query"}}}',
}


def _repo(tmp_path: Path, handlers: str | None) -> Path:
    for rel_path, text in _LEXICONS.items():
        target = tmp_path / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    if handlers is not None:
        api = tmp_path / "packages" / "pds" / "src" / "api.ts"
        api.parent.mkdir(parents=True, exist_ok=True)
        api.write_text(handlers)
    return tmp_path


_HANDLERS = """export default function (server: Server, ctx: AppContext) {
  server.add(app.bsky.actor.putPreferences, {
    auth: ctx.authVerifier.authorization({ authorize: (p) => p.assertRpc('app.bsky.actor.putPreferences') }),
    handler: async ({ auth, input }) => ctx.prefs.put(auth.credentials.did, input.body),
  })
  server.add(app.bsky.actor.getProfile, {
    auth: ctx.authVerifier.standardOptional,
    handler: async ({ params }) => ctx.views.profile(params.actor),
  })
  server.add(com.atproto.server.createSession, async ({ input }) => ctx.login(input.body))
  server.add(app.bsky.feed.getTimeline, timelineConfig)
  server.add(app.bsky.feed.getFeed, { auth, handler })
}
"""


def _route_map(repo: Path) -> dict[str, object]:
    return {r.path: r for r in AtprotoAnalyzer().analyze(repo).routes}


def test_server_add_registrations_become_routes_with_their_auth(tmp_path: Path) -> None:
    routes = _route_map(_repo(tmp_path, _HANDLERS))
    put = routes["/xrpc/app.bsky.actor.putPreferences"]
    assert (put.method, put.file, put.line, put.auth) == ("POST", "packages/pds/src/api.ts", 2, "required")
    assert put.guards == ["auth: ctx.authVerifier.authorization"]
    assert routes["/xrpc/app.bsky.actor.getProfile"].auth == "anonymous"  # optional verifier
    assert routes["/xrpc/com.atproto.server.createSession"].auth == "anonymous"  # bare handler
    # The verifier isn't visible: a config passed by name, or `{ auth, handler }`.
    assert routes["/xrpc/app.bsky.feed.getTimeline"].auth == "unknown"
    assert routes["/xrpc/app.bsky.feed.getFeed"].auth == "unknown"
    assert all(r.file == "packages/pds/src/api.ts" for r in routes.values())


def test_lexicons_without_a_handler_are_declared_not_served(tmp_path: Path) -> None:
    # A client repo (social-app) vendors the lexicons but serves none of them.
    result = AtprotoAnalyzer().analyze(_repo(tmp_path, None))
    assert result.routes == []
    declared = {h.hint for h in result.protocol_hints if h.hint.startswith("atproto_xrpc_declared:")}
    assert declared == {f"atproto_xrpc_declared:{json.loads(t)['id']}" for t in _LEXICONS.values()}


def test_only_registered_lexicons_become_routes(tmp_path: Path) -> None:
    handlers = "server.add(app.bsky.actor.getProfile, { auth: ctx.authVerifier.standard, handler })\n"
    routes = _route_map(_repo(tmp_path, handlers))
    assert set(routes) == {"/xrpc/app.bsky.actor.getProfile"}
    assert routes["/xrpc/app.bsky.actor.getProfile"].auth == "required"


def test_shorthand_auth_resolves_to_the_declared_verifier(tmp_path: Path) -> None:
    handlers = (
        "export default function (server: Server, ctx: AppContext) {\n"
        "  const auth = ctx.authVerifier.authorization({ authorize: () => {} })\n"
        "  server.add(app.bsky.actor.putPreferences, { auth, handler: async () => ({}) })\n"
        "}\n"
        "export function other(server: Server, ctx: AppContext) {\n"
        "  const auth = ctx.authVerifier.standardOptional\n"
        "  const verifier = ctx.authVerifier.standard\n"
        "  server.add(app.bsky.actor.getProfile, { auth, handler: async () => ({}) })\n"
        "  server.add(app.bsky.feed.getTimeline, { auth: verifier, handler: async () => ({}) })\n"
        "}\n"
    )
    routes = _route_map(_repo(tmp_path, handlers))
    assert routes["/xrpc/app.bsky.actor.putPreferences"].auth == "required"
    assert routes["/xrpc/app.bsky.actor.getProfile"].auth == "anonymous"  # nearest `auth` is optional
    assert routes["/xrpc/app.bsky.feed.getTimeline"].auth == "required"
    assert routes["/xrpc/app.bsky.feed.getTimeline"].guards == ["auth: ctx.authVerifier.standard"]


def test_handler_extraction_never_raises_on_garbage(tmp_path: Path) -> None:
    import random

    rng = random.Random(14)
    alphabet = "server.add(app.bsky.x.y, {auth: handler}) => const auth = ctx;'\"`\n\\"
    analyzer = AtprotoAnalyzer()
    for i in range(300):
        text = "server.add(app.bsky.feed.get, " + "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 300)))
        result = ScanResult(root=str(tmp_path))
        analyzer._extract_xrpc_handlers(text, f"f{i}.ts", result, {})


def test_many_registrations_resolve_declarations_linearly() -> None:
    from attackmap.models import ScanResult

    analyzer = AtprotoAnalyzer()
    decls = "".join(f"const v{i} = ctx.authVerifier.standard\n" for i in range(5000))
    regs = "".join(f"server.add(app.bsky.x.m{i}, {{ auth: v{i}, handler }})\n" for i in range(5000))
    result = ScanResult(root=".")
    analyzer._extract_xrpc_handlers(decls + regs, "big.ts", result, {})
    assert len(result.routes) == 5000
