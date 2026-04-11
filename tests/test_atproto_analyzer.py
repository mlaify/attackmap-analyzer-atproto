from pathlib import Path

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
