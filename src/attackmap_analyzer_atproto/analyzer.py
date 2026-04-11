from __future__ import annotations

import json
import re
from pathlib import Path

from .contracts import AnalyzerMetadata, AuthHint, ExternalCall, Route, ScanResult, SecretHint

CODE_SUFFIXES = {".ts", ".tsx", ".js", ".mjs", ".cjs", ".json"}
SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next"}

NAMESPACE_PATTERN = re.compile(r"\b((?:com\.atproto|app\.bsky)(?:\.[a-z0-9_]+){1,})\b", re.IGNORECASE)
XRPC_LITERAL_PATTERN = re.compile(r"['\"](?:https?://[^'\"]+)?/xrpc/((?:com\.atproto|app\.bsky)\.[a-z0-9_.]+)['\"]", re.IGNORECASE)
ENV_URL_PATTERN = re.compile(r"process\.env\.([A-Z0-9_]+_URL)\b")

AUTH_HINT_PATTERNS = [
    (re.compile(r"\bjwt\b|\bjsonwebtoken\b", re.IGNORECASE), "atproto_auth:jwt"),
    (re.compile(r"\bserviceauth\b|\bservice_auth\b", re.IGNORECASE), "atproto_auth:service_auth"),
    (re.compile(r"\bdid:[a-z0-9:._-]+\b", re.IGNORECASE), "atproto_identity:did_reference"),
    (re.compile(r"\bplc\b", re.IGNORECASE), "atproto_identity:plc"),
    (re.compile(r"\bsign(?:ing|ature)?\b|\bverify(?:ing|signature)?\b", re.IGNORECASE), "atproto_crypto:signing"),
    (re.compile(r"\brepo\b.*\bcommit\b|\bcommit\b.*\brepo\b", re.IGNORECASE), "atproto_repo:commit_flow"),
]

EVENT_STREAM_PATTERNS = [
    (re.compile(r"\bsubscriberepos\b", re.IGNORECASE), "atproto_event_stream:subscribe_repos"),
    (re.compile(r"\bwebsocket\b|\bws://\b|\bwss://\b", re.IGNORECASE), "atproto_event_stream:websocket"),
    (re.compile(r"\bfirehose\b", re.IGNORECASE), "atproto_event_stream:firehose"),
]


class AtprotoAnalyzer:
    metadata = AnalyzerMetadata(
        name="atproto",
        display_name="AT Protocol Analyzer",
        version="0.1.0",
        description="Thin protocol-aware overlay analyzer for AT Protocol namespace and XRPC exposure.",
        scope="AT Protocol repositories with lexicons, XRPC namespace usage, and protocol auth/identity cues.",
        targets=["atproto", "bluesky", "xrpc"],
        languages=["typescript", "javascript", "json"],
        priority=35,
        experimental=True,
        enabled_by_default=False,
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    def detect(self, repo_path: str | Path) -> bool:
        root = Path(repo_path).resolve()
        if not root.exists() or not root.is_dir():
            return False

        if (root / "lexicons").is_dir():
            return True

        for file_path in root.rglob("*"):
            if not file_path.is_file():
                continue
            if any(part in SKIP_DIRS for part in file_path.parts):
                continue
            path_text = str(file_path).lower()
            if "com.atproto" in path_text or "app.bsky" in path_text:
                return True
            if file_path.suffix not in CODE_SUFFIXES:
                continue
            content = self._read_text(file_path)
            if not content:
                continue
            if (
                "com.atproto." in content
                or "app.bsky." in content
                or "/xrpc/" in content
                or "lexicon" in content.lower()
            ):
                return True
        return False

    def analyze(self, repo_path: str | Path) -> ScanResult:
        root = Path(repo_path).resolve()
        result = ScanResult(root=str(root))
        if not root.exists() or not root.is_dir():
            return result

        lexicon_files = list(root.rglob("lexicons/**/*.json")) if (root / "lexicons").is_dir() else []
        for lexicon_path in lexicon_files:
            if any(part in SKIP_DIRS for part in lexicon_path.parts):
                continue
            result.files_scanned += 1
            self._append_language(result, "json")
            relative = str(lexicon_path.relative_to(root))
            self._extract_lexicon_signals(lexicon_path, relative, result)

        for file_path in root.rglob("*"):
            if not file_path.is_file():
                continue
            if file_path in lexicon_files:
                continue
            if file_path.suffix not in CODE_SUFFIXES:
                continue
            if any(part in SKIP_DIRS for part in file_path.parts):
                continue

            result.files_scanned += 1
            self._append_language(result, "typescript" if file_path.suffix in {".ts", ".tsx"} else ("javascript" if file_path.suffix in {".js", ".mjs", ".cjs"} else "json"))
            content = self._read_text(file_path)
            if content is None:
                continue
            relative = str(file_path.relative_to(root))

            self._extract_namespace_signals(content, relative, result)
            self._extract_xrpc_literals(content, relative, result)
            self._extract_protocol_hints(content, relative, result)
            self._extract_event_stream_hints(content, relative, result)
            self._extract_env_url_signals(content, relative, result)
            self._extract_service_notes(relative, result)
            self._extract_secret_hints(content, relative, result)

        result.languages.sort()
        return result

    def _extract_lexicon_signals(self, lexicon_path: Path, relative: str, result: ScanResult) -> None:
        try:
            data = json.loads(lexicon_path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return

        lexicon_id = data.get("id")
        if isinstance(lexicon_id, str) and lexicon_id:
            namespace_root = self._namespace_root(lexicon_id)
            if namespace_root:
                self._append_unique_auth(result, f"atproto_namespace:{namespace_root}", relative)
            self._append_unique_auth(result, f"atproto_lexicon:{lexicon_id}", relative)
            self._append_unique_route(result, f"/xrpc/{lexicon_id}", "ANY", relative)

        defs = data.get("defs")
        if isinstance(defs, dict):
            for _, value in defs.items():
                if not isinstance(value, dict):
                    continue
                def_type = str(value.get("type", "")).lower()
                if def_type in {"query", "procedure", "subscription"} and isinstance(lexicon_id, str):
                    method = "SUBSCRIBE" if def_type == "subscription" else "ANY"
                    self._append_unique_route(result, f"/xrpc/{lexicon_id}", method, relative)
                    if def_type == "subscription":
                        self._append_unique_auth(result, "atproto_event_stream:subscription_lexicon", relative)

    def _extract_namespace_signals(self, content: str, relative: str, result: ScanResult) -> None:
        for match in NAMESPACE_PATTERN.finditer(content):
            namespace = match.group(1)
            namespace_root = self._namespace_root(namespace)
            if namespace_root:
                self._append_unique_auth(result, f"atproto_namespace:{namespace_root}", relative)
            self._append_unique_auth(result, f"atproto_namespace_ref:{namespace}", relative)

    def _extract_xrpc_literals(self, content: str, relative: str, result: ScanResult) -> None:
        for match in XRPC_LITERAL_PATTERN.finditer(content):
            ns = match.group(1)
            self._append_unique_route(result, f"/xrpc/{ns}", "ANY", relative)
            self._append_unique_auth(result, f"atproto_xrpc_ref:{ns}", relative)

    def _extract_protocol_hints(self, content: str, relative: str, result: ScanResult) -> None:
        lowered = content.lower()
        if "xrpc" in lowered:
            self._append_unique_auth(result, "atproto_protocol:xrpc", relative)
        for pattern, hint in AUTH_HINT_PATTERNS:
            if pattern.search(content):
                self._append_unique_auth(result, hint, relative)

    def _extract_event_stream_hints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint in EVENT_STREAM_PATTERNS:
            if pattern.search(content):
                self._append_unique_auth(result, hint, relative)

    def _extract_env_url_signals(self, content: str, relative: str, result: ScanResult) -> None:
        for match in ENV_URL_PATTERN.finditer(content):
            env_name = match.group(1)
            self._append_unique_external(result, f"env://{env_name}", relative)
            service_target = self._service_target_from_env(env_name)
            if service_target:
                self._append_unique_auth(result, f"atproto_service_edge:{service_target}", relative)

    def _extract_service_notes(self, relative: str, result: ScanResult) -> None:
        normalized = relative.replace("\\", "/")
        parts = normalized.split("/")
        for root in ("services", "packages"):
            if root in parts:
                idx = parts.index(root)
                if idx + 1 < len(parts):
                    self._append_unique_auth(result, f"atproto_service_note:{parts[idx + 1].lower()}", relative)
                return

    def _extract_secret_hints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in [
            re.compile(r"process\.env\.([A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD|SIGNING)[A-Z0-9_]*)"),
            re.compile(r"['\"]([A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD|SIGNING)[A-Z0-9_]*)['\"]"),
        ]:
            for match in pattern.finditer(content):
                self._append_unique_secret(result, match.group(1), relative)

    @staticmethod
    def _namespace_root(namespace: str) -> str | None:
        lowered = namespace.lower()
        if lowered.startswith("com.atproto"):
            return "com.atproto"
        if lowered.startswith("app.bsky"):
            return "app.bsky"
        return None

    @staticmethod
    def _service_target_from_env(env_name: str) -> str | None:
        token = env_name.upper().removesuffix("_URL")
        token = token.replace("__", "_").strip("_")
        if not token:
            return None
        return token.lower().replace("_", "-")

    @staticmethod
    def _append_language(result: ScanResult, language: str) -> None:
        if language not in result.languages:
            result.languages.append(language)

    @staticmethod
    def _read_text(path: Path) -> str | None:
        try:
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return None

    @staticmethod
    def _append_unique_route(result: ScanResult, path: str, method: str, file: str) -> None:
        key = (path, method, file)
        if any((item.path, item.method, item.file) == key for item in result.routes):
            return
        result.routes.append(Route(path=path, method=method, file=file))

    @staticmethod
    def _append_unique_external(result: ScanResult, target: str, file: str) -> None:
        key = (target, file)
        if any((item.target, item.file) == key for item in result.external_calls):
            return
        result.external_calls.append(ExternalCall(target=target, file=file))

    @staticmethod
    def _append_unique_auth(result: ScanResult, hint: str, file: str) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.auth_hints):
            return
        result.auth_hints.append(AuthHint(hint=hint, file=file))

    @staticmethod
    def _append_unique_secret(result: ScanResult, name: str, file: str) -> None:
        key = (name, file)
        if any((item.name, item.file) == key for item in result.secret_hints):
            return
        result.secret_hints.append(SecretHint(name=name, file=file))
