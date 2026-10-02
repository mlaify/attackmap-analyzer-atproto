import shutil
import sys
from pathlib import Path

import pytest
from attackmap.safe_fs import OUTPUT_MARKER

from attackmap.sdk.contracts import AnalyzerMetadata as SharedAnalyzerMetadata
from attackmap.sdk.models import ScanResult as SharedScanResult
from attackmap_analyzer_atproto.contracts import AnalyzerMetadata, ScanResult
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
    external_targets = {call.target for call in result.external_calls}
    secret_names = {secret.name for secret in result.secret_hints}

    assert ("/xrpc/com.atproto.server.createSession", "ANY") in route_keys
    assert ("/xrpc/com.atproto.sync.subscribeRepos", "SUBSCRIBE") in route_keys

    assert "atproto_namespace:com.atproto" in auth_hints
    assert "atproto_namespace:app.bsky" in auth_hints
    assert "atproto_protocol:xrpc" in auth_hints
    assert "atproto_event_stream:subscription_lexicon" in auth_hints
    assert "atproto_identity:did_reference" in auth_hints
    assert "atproto_crypto:signing" in auth_hints
    assert "atproto_service_note:pds" in auth_hints

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
    assert ("/xrpc/com.atproto.server.createSession", "ANY") in {(r.path, r.method) for r in result.routes}
    assert "atproto_service_note:pds" in {h.hint for h in result.auth_hints}


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
    files = {h.file for h in result.auth_hints} | {r.file for r in result.routes}
    assert not any(f.startswith(("reports/", ".attackmap-gui/")) for f in files)
    assert not any("stale" in h.hint for h in result.auth_hints)


def test_detect_ignores_atproto_names_above_the_repo(tmp_path: Path) -> None:
    repo = tmp_path / "app.bsky" / "repo"
    repo.mkdir(parents=True)
    (repo / "main.py").write_text("print('hello')\n")
    assert AtprotoAnalyzer().detect(repo) is False
