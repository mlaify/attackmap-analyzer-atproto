from __future__ import annotations

import json
import re
from pathlib import Path

from attackmap.sdk import DEFAULT_SKIP_DIRS, iter_repo_files, line_of, line_snippet, read_source, rel

from .contracts import AnalyzerMetadata, AuthHint, ExternalCall, ProtocolHint, Route, ScanResult, SecretHint

CODE_SUFFIXES = {".ts", ".tsx", ".js", ".mjs", ".cjs", ".json"}
# Pruned by repo-relative directory name; also skips AttackMap's own report
# output, so a previous run's attackmap-report.json isn't re-read (AttackMap#253).
SKIP_DIRS = DEFAULT_SKIP_DIRS

# Lockfiles and AttackMap's own output mention every package / NSID; never
# read them (detect() used to fire on a package-lock.json containing "lexicon").
NON_SOURCE_NAMES = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "attackmap-report.json",
        "review-context-pack.json",
        "defensive-review.json",
    }
)

# Namespace authorities always recognized. Any other authority is learned
# from the repo's own lexicon `id`s (e.g. `sh.tangled`, `blue.linkat`).
BUILTIN_NAMESPACE_ROOTS = ("com.atproto", "app.bsky", "chat.bsky", "tools.ozone")
# An NSID: reverse-DNS authority + name, at least three segments.
NSID = r"[a-zA-Z](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?){2,}"
NSID_PATTERN = re.compile(rf"^{NSID}$")
# `/xrpc/<nsid>` is specific enough to accept any authority.
XRPC_LITERAL_PATTERN = re.compile(rf"['\"`](?:https?://[^'\"`/]+)?/xrpc/({NSID})['\"`?]")
ENV_URL_PATTERN = re.compile(r"process\.env\.([A-Z0-9_]+_URL)\b")

# XRPC method types and their HTTP binding (query = GET, procedure = POST,
# subscription = WebSocket). `record`, `object` and defs-only lexicons are
# schemas, not endpoints.
XRPC_METHODS = {"query": "GET", "procedure": "POST", "subscription": "WS"}

# Handler registration: `server.method('<nsid>', handlerOrConfig)` and the
# generated-API form `server.app.bsky.feed.getTimeline({ auth, handler })`.
XRPC_METHOD_CALL_PATTERN = re.compile(rf"\b(?:server|xrpc|xrpcServer)\.method\(\s*['\"`]({NSID})['\"`]\s*,\s*")
XRPC_GENERATED_CALL_PATTERN = re.compile(rf"\bserver\.({NSID})\(\s*(?=\{{)")
AUTH_KEY_PATTERN = re.compile(r"(?:^|[{,\s])auth\s*:\s*(?P<verifier>[^,}\n]+)")
# Verifiers that let unauthenticated callers through.
OPTIONAL_VERIFIER_PATTERN = re.compile(r"optional|nullCreds|\bnull\b|\bundefined\b", re.IGNORECASE)

# Auth, identity (DID/PLC) and signing cues: genuine auth signals, emitted as AuthHint.
AUTH_HINT_PATTERNS = [
    (re.compile(r"\bjwt\b|\bjsonwebtoken\b", re.IGNORECASE), "atproto_auth:jwt"),
    (re.compile(r"\bserviceauth\b|\bservice_auth\b", re.IGNORECASE), "atproto_auth:service_auth"),
    (re.compile(r"\bdid:[a-z0-9:._-]+\b", re.IGNORECASE), "atproto_identity:did_reference"),
    # The PLC directory / did:plc identifiers, not any word "plc".
    (re.compile(r"did:plc:|\bplc\.directory\b|@did-plc/|\bPlcClient\b"), "atproto_identity:plc"),
    # Signing/verification APIs and key types, not the words "sign"/"verify".
    (
        re.compile(
            r"@atproto/crypto|\b(?:Secp256k1Keypair|P256Keypair|verifySignature|verifyJwt|createServiceJwt"
            r"|createServiceAuthHeaders|signJwt|verifyCommitSig|signCommit)\b"
            r"|\b(?:keypair|signingKey|repoSigningKey|crypto)\.(?:sign|verify)\s*\("
        ),
        "atproto_crypto:signing",
    ),
]
# Protocol data-flow cues: ProtocolHint (AttackMap#258).
PROTOCOL_HINT_PATTERNS = [
    (re.compile(r"xrpc", re.IGNORECASE), "atproto_protocol:xrpc"),
    (re.compile(r"\brepo\b.*\bcommit\b|\bcommit\b.*\brepo\b", re.IGNORECASE), "atproto_repo:commit_flow"),
]
SECRET_ENV_PATTERN = re.compile(
    r"process\.env\.([A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD|SIGNING)[A-Z0-9_]*)"
    r"|process\.env\[\s*['\"]([A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD|SIGNING)[A-Z0-9_]*)['\"]\s*\]"
)
LEXICON_ID_PATTERN = re.compile(r'"id"\s*:')
LEXICON_SUBSCRIPTION_PATTERN = re.compile(r'"type"\s*:\s*"subscription"', re.IGNORECASE)

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
        priority=90,
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

        nsid_literal = self._known_nsid_literal_pattern(BUILTIN_NAMESPACE_ROOTS)
        for file_path in iter_repo_files(root, skip_dirs=SKIP_DIRS):
            # Repo-relative, so a checkout under e.g. ~/src/app.bsky/ doesn't
            # make every repo look like an AT Protocol one.
            relative = rel(file_path, root)
            path_text = relative.lower()
            if any(ns in path_text for ns in BUILTIN_NAMESPACE_ROOTS):
                return True
            if file_path.name in NON_SOURCE_NAMES:
                continue
            suffix = file_path.suffix.lower()
            if file_path.name == "package.json":
                if self._declares_atproto_dependency(read_source(file_path)):
                    return True
                continue
            if suffix == ".json":
                # Only lexicon documents count; other JSON isn't read.
                if "lexicons" in relative.split("/")[:-1] and self._is_lexicon_document(read_source(file_path)):
                    return True
                continue
            if suffix not in CODE_SUFFIXES:
                continue
            content = read_source(file_path)
            if not content:
                continue
            # A quoted NSID under a known authority, or an `/xrpc/<nsid>` URL.
            if nsid_literal.search(content) or XRPC_LITERAL_PATTERN.search(content):
                return True
        return False

    @staticmethod
    def _declares_atproto_dependency(text: str | None) -> bool:
        if not text:
            return False
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return False
        if not isinstance(data, dict):
            return False
        for field in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            deps = data.get(field)
            if isinstance(deps, dict) and any(
                isinstance(name, str) and (name.startswith("@atproto/") or name.startswith("@did-plc/"))
                for name in deps
            ):
                return True
        return False

    @staticmethod
    def _is_lexicon_document(text: str | None) -> bool:
        if not text:
            return False
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return False
        return (
            isinstance(data, dict)
            and isinstance(data.get("lexicon"), int)
            and isinstance(data.get("id"), str)
            and bool(NSID_PATTERN.match(data["id"]))
        )

    @staticmethod
    def _known_nsid_literal_pattern(roots) -> re.Pattern:
        alternation = "|".join(re.escape(root) for root in sorted(set(roots), key=len, reverse=True))
        return re.compile(rf"['\"`](?:{alternation})(?:\.[A-Za-z0-9-]+)+['\"`]")

    def analyze(self, repo_path: str | Path) -> ScanResult:
        root = Path(repo_path).resolve()
        result = ScanResult(root=str(root))
        if not root.exists() or not root.is_dir():
            return result

        lexicon_files: list[tuple[Path, str]] = []
        code_files: list[Path] = []
        for file_path in iter_repo_files(root, suffixes=CODE_SUFFIXES, skip_dirs=SKIP_DIRS):
            if file_path.name in NON_SOURCE_NAMES:
                continue
            if file_path.suffix.lower() != ".json":
                code_files.append(file_path)
                continue
            # JSON is only read for lexicon documents (`{"lexicon": 1, "id": ...}`);
            # tsconfig, fixtures and data files aren't protocol surface.
            content = read_source(file_path)
            if content is not None and self._is_lexicon_document(content):
                lexicon_files.append((file_path, content))

        # Lexicons first: they define each NSID's method type and teach the
        # code pass which namespace authorities this repo uses.
        lexicon_types: dict[str, str] = {}
        namespace_roots: set[str] = set(BUILTIN_NAMESPACE_ROOTS)
        for lexicon_path, content in lexicon_files:
            result.files_scanned += 1
            self._append_language(result, "json")
            self._extract_lexicon_signals(content, rel(lexicon_path, root), result, lexicon_types, namespace_roots)

        namespace_pattern = re.compile(
            r"\b((?:"
            + "|".join(re.escape(r) for r in sorted(namespace_roots, key=len, reverse=True))
            + r")(?:\.[A-Za-z0-9_-]+)+)\b"
        )
        for file_path in code_files:
            suffix = file_path.suffix.lower()
            result.files_scanned += 1
            self._append_language(result, "typescript" if suffix in {".ts", ".tsx"} else "javascript")
            content = read_source(file_path)
            if content is None:
                continue
            relative = rel(file_path, root)

            self._extract_namespace_signals(content, relative, result, namespace_pattern)
            self._extract_xrpc_literals(content, relative, result, lexicon_types)
            self._extract_xrpc_handlers(content, relative, result, lexicon_types)
            self._extract_protocol_hints(content, relative, result)
            self._extract_event_stream_hints(content, relative, result)
            self._extract_env_url_signals(content, relative, result)
            self._extract_service_notes(relative, result)
            self._extract_secret_hints(content, relative, result)

        result.languages.sort()
        return result

    def _extract_lexicon_signals(
        self,
        content: str,
        relative: str,
        result: ScanResult,
        lexicon_types: dict[str, str],
        namespace_roots: set[str],
    ) -> None:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return
        if not isinstance(data, dict):
            return

        id_match = LEXICON_ID_PATTERN.search(content)
        id_offset = id_match.start() if id_match else 0
        sub_match = LEXICON_SUBSCRIPTION_PATTERN.search(content)
        sub_offset = sub_match.start() if sub_match else id_offset

        lexicon_id = data.get("id")
        if not isinstance(lexicon_id, str) or not lexicon_id:
            return
        namespace_root = self._namespace_root(lexicon_id)
        if namespace_root:
            namespace_roots.add(namespace_root)
            self._append_protocol(result, f"atproto_namespace:{namespace_root}", relative, content, id_offset, 0.9)
        self._append_protocol(result, f"atproto_lexicon:{lexicon_id}", relative, content, id_offset, 0.9)

        # Only `defs.main` of type query/procedure/subscription is an
        # endpoint; record, object and defs-only lexicons are schemas.
        defs = data.get("defs")
        main = defs.get("main") if isinstance(defs, dict) else None
        def_type = str(main.get("type", "")).lower() if isinstance(main, dict) else ""
        method = XRPC_METHODS.get(def_type)
        if method is None:
            return
        lexicon_types[lexicon_id] = method
        offset = sub_offset if def_type == "subscription" else id_offset
        self._append_unique_route(result, f"/xrpc/{lexicon_id}", method, relative, line_of(content, offset))
        if def_type == "subscription":
            self._append_protocol(
                result, "atproto_event_stream:subscription_lexicon", relative, content, sub_offset, 0.9
            )

    def _extract_namespace_signals(
        self, content: str, relative: str, result: ScanResult, namespace_pattern: re.Pattern
    ) -> None:
        for match in namespace_pattern.finditer(content):
            namespace = match.group(1)
            namespace_root = self._namespace_root(namespace)
            if namespace_root:
                self._append_protocol(result, f"atproto_namespace:{namespace_root}", relative, content, match.start(), 0.8)
            self._append_protocol(result, f"atproto_namespace_ref:{namespace}", relative, content, match.start(), 0.8)

    def _extract_xrpc_literals(
        self, content: str, relative: str, result: ScanResult, lexicon_types: dict[str, str]
    ) -> None:
        for match in XRPC_LITERAL_PATTERN.finditer(content):
            ns = match.group(1)
            method = lexicon_types.get(ns, "ANY")
            self._append_unique_route(result, f"/xrpc/{ns}", method, relative, line_of(content, match.start()))
            self._append_protocol(result, f"atproto_xrpc_ref:{ns}", relative, content, match.start(), 0.8)

    def _extract_xrpc_handlers(
        self, content: str, relative: str, result: ScanResult, lexicon_types: dict[str, str]
    ) -> None:
        """Server-side handler registrations and their per-endpoint auth.

        `server.method(nsid, { auth: ctx.authVerifier.standard, handler })`
        (and the generated `server.<nsid>({ auth, handler })` form) registers
        an XRPC endpoint. The `auth:` verifier, if any, is recorded per
        endpoint: an `atproto_auth:route_verifier:<nsid>` AuthHint when one is
        set, an `atproto_route_auth:anonymous:<nsid>` ProtocolHint when there
        is none (a bare handler function, a config without `auth:`) or the
        verifier admits unauthenticated callers (`*Optional*`, `nullCreds`).
        The anonymous marker is deliberately not an AuthHint, so core never
        counts it as an auth control.
        """
        calls = [(m, m.group(1)) for m in XRPC_METHOD_CALL_PATTERN.finditer(content)]
        calls += [
            (m, m.group(1))
            for m in XRPC_GENERATED_CALL_PATTERN.finditer(content)
            if m.group(1).split(".", 1)[0] != "method"
        ]
        for match, nsid in sorted(calls, key=lambda item: item[0].start()):
            offset = match.start()
            line = line_of(content, offset)
            method = lexicon_types.get(nsid, "ANY")
            self._append_unique_route(result, f"/xrpc/{nsid}", method, relative, line)
            literal = self._object_literal_top_level(content, match.end())
            verifier_match = AUTH_KEY_PATTERN.search(literal[1]) if literal is not None else None
            verifier = verifier_match.group("verifier").strip() if verifier_match else None
            if literal is not None and verifier_match and verifier and not OPTIONAL_VERIFIER_PATTERN.search(verifier):
                # Cite the `auth: <verifier>` line itself.
                verifier_offset = literal[0] + verifier_match.start("verifier")
                self._append_unique_auth(
                    result, f"atproto_auth:route_verifier:{nsid}", relative, content, verifier_offset
                )
            else:
                self._append_protocol(
                    result, f"atproto_route_auth:anonymous:{nsid}", relative, content, offset, 0.7
                )

    @staticmethod
    def _object_literal_top_level(content: str, start: int, limit: int = 20000) -> tuple[int, str] | None:
        """The `{...}` literal at ``start`` with everything below its top level blanked.

        Returns ``(offset, masked)`` where ``masked[i]`` corresponds to
        ``content[offset + i]`` (nested blocks become spaces, so offsets still
        line up), or None when ``start`` isn't an object literal (e.g. a bare
        handler function). Strings and template literals are skipped so braces
        inside them don't unbalance the scan.
        """
        index = start
        while index < len(content) and content[index].isspace():
            index += 1
        if index >= len(content) or content[index] != "{":
            return None
        end = min(len(content), index + limit)
        masked = list(content[index:end])
        depth = 0
        i = index
        while i < end:
            ch = content[i]
            if ch in "'\"`":
                close = i + 1
                while close < end and content[close] != ch:
                    close += 2 if content[close] == "\\" else 1
                if depth > 1:
                    for j in range(i, min(close + 1, end)):
                        masked[j - index] = " "
                i = close + 1
                continue
            if ch in "{([":
                depth += 1
            elif ch in "})]":
                depth -= 1
                if depth == 0:
                    return index, "".join(masked[: i - index + 1])
            if depth > 1 or (depth == 1 and ch in "})]"):
                masked[i - index] = " " if ch != "\n" else "\n"
            i += 1
        return index, "".join(masked)

    def _extract_protocol_hints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint in PROTOCOL_HINT_PATTERNS:
            match = pattern.search(content)
            if match:
                self._append_protocol(result, hint, relative, content, match.start(), 0.6)
        for pattern, hint in AUTH_HINT_PATTERNS:
            match = pattern.search(content)
            if match:
                self._append_unique_auth(result, hint, relative, content, match.start())

    def _extract_event_stream_hints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint in EVENT_STREAM_PATTERNS:
            match = pattern.search(content)
            if match:
                self._append_protocol(result, hint, relative, content, match.start(), 0.7)

    def _extract_env_url_signals(self, content: str, relative: str, result: ScanResult) -> None:
        for match in ENV_URL_PATTERN.finditer(content):
            env_name = match.group(1)
            self._append_unique_external(result, f"env://{env_name}", relative, content, match.start())
            service_target = self._service_target_from_env(env_name)
            if service_target:
                self._append_protocol(
                    result, f"atproto_service_edge:{service_target}", relative, content, match.start(), 0.5
                )

    def _extract_service_notes(self, relative: str, result: ScanResult) -> None:
        normalized = relative.replace("\\", "/")
        parts = normalized.split("/")
        for root in ("services", "packages"):
            if root in parts:
                idx = parts.index(root)
                if idx + 1 < len(parts):
                    # Derived from the file's location, not a source line: anchor at line 1.
                    self._append_protocol(
                        result,
                        f"atproto_service_note:{parts[idx + 1].lower()}",
                        relative,
                        None,
                        None,
                        0.6,
                        evidence=f"inferred from path {relative}",
                    )
                return

    def _extract_secret_hints(self, content: str, relative: str, result: ScanResult) -> None:
        # Env-sourced secrets only: any quoted upper-case constant containing
        # KEY/TOKEN (`'KEY'`, `"TOKEN"`, enum values) used to be reported.
        for match in SECRET_ENV_PATTERN.finditer(content):
            self._append_unique_secret(result, match.group(1) or match.group(2), relative, content, match.start())

    @staticmethod
    def _namespace_root(namespace: str) -> str | None:
        """The NSID's authority root: its first two segments (`sh.tangled`)."""
        if not NSID_PATTERN.match(namespace):
            return None
        return ".".join(namespace.lower().split(".")[:2])

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
    def _append_unique_route(result: ScanResult, path: str, method: str, file: str, line: int) -> None:
        key = (path, method, file)
        if any((item.path, item.method, item.file) == key for item in result.routes):
            return
        result.routes.append(Route(path=path, method=method, file=file, line=line))

    @staticmethod
    def _append_unique_external(result: ScanResult, target: str, file: str, content: str, offset: int) -> None:
        key = (target, file)
        if any((item.target, item.file) == key for item in result.external_calls):
            return
        line = line_of(content, offset)
        result.external_calls.append(
            ExternalCall(target=target, file=file, line=line, evidence_text=line_snippet(content, line) or target)
        )

    @staticmethod
    def _append_unique_auth(result: ScanResult, hint: str, file: str, content: str, offset: int) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.auth_hints):
            return
        line = line_of(content, offset)
        result.auth_hints.append(
            AuthHint(hint=hint, file=file, line=line, evidence_text=line_snippet(content, line) or hint)
        )

    @staticmethod
    def _append_protocol(
        result: ScanResult,
        hint: str,
        file: str,
        content: str | None,
        offset: int | None,
        confidence: float,
        *,
        evidence: str | None = None,
    ) -> None:
        """Append a ProtocolHint once per (hint, file).

        Located at ``offset`` when given; path-derived hints pass
        ``content=None`` and are anchored at line 1 with ``evidence``.
        """
        if any((item.hint, item.file) == (hint, file) for item in result.protocol_hints):
            return
        if content is not None and offset is not None:
            line = line_of(content, offset)
            evidence_text = line_snippet(content, line) or hint
        else:
            line = 1
            evidence_text = evidence or hint
        result.protocol_hints.append(
            ProtocolHint(hint=hint, file=file, line=line, evidence_text=evidence_text, confidence=confidence)
        )

    @staticmethod
    def _append_unique_secret(result: ScanResult, name: str, file: str, content: str, offset: int) -> None:
        key = (name, file)
        if any((item.name, item.file) == key for item in result.secret_hints):
            return
        line = line_of(content, offset)
        result.secret_hints.append(
            SecretHint(name=name, file=file, line=line, evidence_text=line_snippet(content, line) or name)
        )
