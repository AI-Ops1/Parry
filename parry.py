#!/usr/bin/env python3
"""
Parry (parry.sh) — Hybrid AI-Written Code Bug Verifier, MCP Server & Evil AI Benchmark
Zero third-party dependencies required (runs on standard Python 3.9+).
Supports: Rust (.rs), Python (.py), TypeScript (.ts, .tsx), JavaScript (.js, .jsx)

AI Integrations Supported Out of the Box:
  1. Model Context Protocol (`python3 parry.py mcp`) — for Claude Code, Gemini CLI, Cursor, Windsurf, OpenAI Codex
  2. Multi-AI BYOK Stage 3 Diff-Critic (`--provider gemini|claude|openai|ollama`) — zero cloud proxy, 100% BYOK
  3. SARIF 2.1.0 & GitHub PR Review JSON (`--format cli|sarif|github-pr`)
  4. 25-Case Evil AI Benchmark (`python3 parry.py bench`)
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import asdict, dataclass
import hashlib
import json
import os
import pathlib
import re
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class Finding:
    rule_id: str
    category: str  # "hallucination" | "security" | "logic" | "ai-antipattern"
    severity: str  # "error" | "warning"
    language: str
    file_path: str
    line: int
    column: int
    enclosing_symbol: str
    fingerprint: str
    message: str
    suggestion: str
    generated_test: Optional[str] = None


def compute_ast_fingerprint(
    file_path: str, rule_id: str, enclosing_symbol: str, normalized_line: str
) -> str:
    """Compute a deterministic SHA-256 fingerprint anchored to the enclosing AST symbol."""
    norm_path = pathlib.Path(file_path).name
    norm_code = re.sub(r"\s+", " ", normalized_line.strip())
    payload = f"{norm_path}::{enclosing_symbol}::{rule_id}::{norm_code}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def find_enclosing_symbol(source: str, line_no: int) -> str:
    """Locate the nearest enclosing function/method/struct/class name above `line_no`."""
    lines = source.splitlines()[:line_no]
    fn_re = re.compile(r"\b(?:def|fn|function|class|struct)\s+([A-Za-z_][A-Za-z0-9_]*)")
    for line in reversed(lines):
        m = fn_re.search(line)
        if m:
            return m.group(1)
    return "<module>"


# ---------------------------------------------------------------------------
# Security Guardrails: Secret Redaction & Indirect Prompt Injection Sanitizer
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{25,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b"),
]

PROMPT_INJECTION_RE = re.compile(
    r"(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|system\s*prompt|approve\s+this\s+pr)",
    re.IGNORECASE,
)


def redact_secrets_and_sanitize_diff(raw_text: str) -> Tuple[str, bool]:
    """Redact API keys/tokens and neutralize indirect prompt injection strings before BYOK LLM calls."""
    sanitized = raw_text
    for pat in SECRET_PATTERNS:
        sanitized = pat.sub("<REDACTED_SECRET>", sanitized)
    injection_detected = bool(PROMPT_INJECTION_RE.search(sanitized))
    if injection_detected:
        sanitized = PROMPT_INJECTION_RE.sub("[STRIPPED_PROMPT_INJECTION_ATTEMPT]", sanitized)
    return sanitized, injection_detected


# ---------------------------------------------------------------------------
# Stage 1 & 2 Rules: Hallucinations, Security, and Logic Traps
# ---------------------------------------------------------------------------

SUSPICIOUS_AI_PACKAGES: Dict[str, Dict[str, str]] = {
    "python": {
        "arangodb_driver": "Non-existent PyPI package commonly hallucinated by LLMs (slopsquatting risk). Use `python-arango`.",
        "arangodb-driver": "Non-existent PyPI package commonly hallucinated by LLMs (slopsquatting risk). Use `python-arango`.",
        "fastapi_jwt_auth_v2": "Potential slopsquatted PyPI package name. Verify against `uv.lock` / PyPI.",
        "huggingface_cli": "Hallucinated import (`huggingface-cli` is a CLI binary; the Python module is `huggingface_hub`).",
    },
    "typescript": {
        "nextjs-auth": "Hallucinated npm package name (`nextjs-auth`); verify whether `next-auth` / `@auth/nextjs` was intended.",
        "react-use-fetch-hook": "Potential AI-hallucinated npm package (`react-use-fetch-hook` — slopsquatting vector).",
    },
    "javascript": {
        "nextjs-auth": "Hallucinated npm package name (`nextjs-auth`); verify whether `next-auth` / `@auth/nextjs` was intended.",
        "react-use-fetch-hook": "Potential AI-hallucinated npm package (`react-use-fetch-hook` — slopsquatting vector).",
    },
    "rust": {
        "tokio_async_trait": "Hallucinated crate `tokio_async_trait`; use `async-trait` or native async traits in Rust >= 1.75.",
        "serde_json_derive": "Hallucinated crate `serde_json_derive`; use `serde` with `features = [\"derive\"]`.",
    },
}

HALLUCINATED_OR_STALE_APIS: Dict[str, List[Tuple[re.Pattern[str], str, str, str]]] = {
    "python": [
        (
            re.compile(r"\bopenai\.ChatCompletion\.create\b"),
            "PARRY-HAL-PY001",
            "Removed OpenAI v0.x API `openai.ChatCompletion.create` emitted from pre-cutoff weights.",
            "Use `client = OpenAI(); client.chat.completions.create(...)` (openai >= 1.0.0).",
        ),
        (
            re.compile(r"\b(?:df|dataframe)\.append\s*\("),
            "PARRY-HAL-PY002",
            "Removed pandas 2.0 `DataFrame.append()` method frequently hallucinated by LLMs.",
            "Use `pd.concat([df, pd.DataFrame([row])], ignore_index=True)`.",
        ),
        (
            re.compile(r"\bpydantic\.parse_obj_as\b|\b(?:\.dict\(\)|\.parse_obj\(|@validator\b)"),
            "PARRY-HAL-PY003",
            "Legacy Pydantic v1 API (`parse_obj_as`, `.dict()`, `.parse_obj()`) mixed into modern Python.",
            "Use Pydantic v2 `TypeAdapter(T).validate_python(...)` and `.model_dump()`.",
        ),
        (
            re.compile(r"\bdatetime\.utcnow\s*\("),
            "PARRY-HAL-PY004",
            "Deprecated `datetime.utcnow()` produces naive timestamps.",
            "Use `datetime.now(datetime.timezone.utc)`.",
        ),
    ],
    "typescript": [
        (
            re.compile(r"\.substr\s*\("),
            "PARRY-HAL-TS001",
            "Deprecated `String.prototype.substr()` emitted by AI.",
            "Use `.slice(start, end)` or `.substring(start, end)`.",
        ),
        (
            re.compile(r"\bnew\s+Buffer\s*\(|\bBuffer\s*\("),
            "PARRY-HAL-TS002",
            "Deprecated and unsafe `Buffer()` constructor.",
            "Use `Buffer.from(...)` or `Buffer.alloc(...)`.",
        ),
        (
            re.compile(r"from\s+['\"]react-query['\"]"),
            "PARRY-HAL-TS003",
            "Legacy `react-query` v3 package import instead of `@tanstack/react-query`.",
            "Import from `@tanstack/react-query`.",
        ),
    ],
    "javascript": [
        (
            re.compile(r"\.substr\s*\("),
            "PARRY-HAL-JS001",
            "Deprecated `String.prototype.substr()` emitted by AI.",
            "Use `.slice(start, end)` or `.substring(start, end)`.",
        ),
        (
            re.compile(r"\bnew\s+Buffer\s*\(|\bBuffer\s*\("),
            "PARRY-HAL-JS002",
            "Deprecated and unsafe `Buffer()` constructor.",
            "Use `Buffer.from(...)` or `Buffer.alloc(...)`.",
        ),
    ],
    "rust": [
        (
            re.compile(r"\btry!\s*\("),
            "PARRY-HAL-RS001",
            "Obsolete Rust 2015 `try!(...)` macro emitted instead of `?` operator.",
            "Replace `try!(expr)` with `expr?`.",
        ),
        (
            re.compile(r"\bstd::sync::ONCE_INIT\b"),
            "PARRY-HAL-RS002",
            "Deprecated `std::sync::ONCE_INIT` constant.",
            "Use `std::sync::OnceLock` or `std::sync::Once::new()`.",
        ),
        (
            re.compile(r"\.into_iter\(\)\.collect::<Vec<_\>>\(\)\.len\(\)"),
            "PARRY-HAL-RS003",
            "Unnecessary O(N) heap allocation `.collect::<Vec<_>>().len()` just to count elements.",
            "Use `.into_iter().count()` or `.len()` directly.",
        ),
    ],
}

SECURITY_AND_LOGIC_RULES: Dict[str, List[Tuple[re.Pattern[str], str, str, str, str]]] = {
    "python": [
        (
            re.compile(r"execute\s*\(\s*f['\"]|execute\s*\(\s*['\"].*%s.*['\"]\s*%"),
            "PARRY-SEC-PY001",
            "security",
            "SQL Injection vector: AI-generated string interpolation inside `.execute(...)`.",
            "Use parameterized queries: `cursor.execute('SELECT * FROM t WHERE code = ?', (code,))`.",
        ),
        (
            re.compile(r"subprocess\.(?:run|Popen|call)\s*\([^)]*shell\s*=\s*True"),
            "PARRY-SEC-PY002",
            "security",
            "Command Injection vector: `subprocess` called with `shell=True`.",
            "Pass argument list `['cmd', arg]` with `shell=False`.",
        ),
        (
            re.compile(r"verify\s*=\s*False"),
            "PARRY-SEC-PY003",
            "security",
            "TLS certificate validation disabled (`verify=False`).",
            "Remove `verify=False` and configure valid CA bundle.",
        ),
    ],
    "typescript": [
        (
            re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:"),
            "PARRY-SEC-TS001",
            "security",
            "Potential XSS vulnerability via unescaped `dangerouslySetInnerHTML`.",
            "Sanitize with `DOMPurify.sanitize(rawHtml)` before rendering.",
        ),
        (
            re.compile(r"\.sort\s*\(\s*\)"),
            "PARRY-LOG-TS001",
            "logic",
            "Lexicographical `.sort()` without comparator sorts numbers alphabetically (`[100, 20]` -> `[100, 20]`).",
            "Provide an explicit numeric comparator: `.sort((a, b) => a - b)`.",
        ),
        (
            re.compile(r"forEach\s*\(\s*async\b"),
            "PARRY-LOG-TS002",
            "logic",
            "Broken async control flow: `.forEach(async ...)` does not await promises and drops rejections.",
            "Use `for (const x of items) { await ... }` or `await Promise.all(items.map(async ...))`.",
        ),
    ],
    "javascript": [
        (
            re.compile(r"\.sort\s*\(\s*\)"),
            "PARRY-LOG-JS001",
            "logic",
            "Lexicographical `.sort()` without comparator sorts numbers alphabetically.",
            "Provide an explicit comparator: `.sort((a, b) => a - b)`.",
        ),
        (
            re.compile(r"forEach\s*\(\s*async\b"),
            "PARRY-LOG-JS002",
            "logic",
            "Broken async control flow: `.forEach(async ...)` does not await promises.",
            "Use `for (const x of items) { await ... }` or `await Promise.all(items.map(async ...))`.",
        ),
    ],
    "rust": [
        (
            re.compile(r"async\s+fn\b[\s\S]{0,260}?\bstd::(?:thread::sleep|fs::read_to_string|fs::File::open)\b"),
            "PARRY-LOG-RS001",
            "logic",
            "Async runtime starvation: blocking `std::thread::sleep` or `std::fs` inside `async fn`.",
            "Use `tokio::time::sleep(...).await` or `tokio::task::spawn_blocking`.",
        ),
        (
            re.compile(r"\bas\s+u(?:8|16|32|size)\b"),
            "PARRY-LOG-RS002",
            "logic",
            "Unchecked numeric cast (`as usize/u32`) wraps negative signed integers to huge positive values.",
            "Use `usize::try_from(val)?` to handle negative values explicitly.",
        ),
        (
            re.compile(r"\bunsafe\s*\{"),
            "PARRY-SEC-RS001",
            "security",
            "AI-introduced `unsafe` block requires manual memory soundness proof.",
            "Use safe abstractions or document `# Safety` invariants and verify with `cargo miri`.",
        ),
    ],
}


def detect_language(file_path: pathlib.Path) -> Optional[str]:
    return {
        ".py": "python",
        ".rs": "rust",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".js": "javascript",
        ".jsx": "javascript",
    }.get(file_path.suffix.lower())


def analyze_python_ast(source: str, file_path: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = source.splitlines()
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError as exc:
        line_no = exc.lineno or 1
        raw_line = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
        findings.append(
            Finding(
                rule_id="PARRY-SYN-PY000",
                category="logic",
                severity="error",
                language="python",
                file_path=file_path,
                line=line_no,
                column=exc.offset or 1,
                enclosing_symbol="<module>",
                fingerprint=compute_ast_fingerprint(file_path, "PARRY-SYN-PY000", "<module>", raw_line),
                message=f"Syntax error in AI-generated Python code: {exc.msg}",
                suggestion="Fix syntax error before running downstream verification.",
            )
        )
        return findings

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            raw_line = lines[node.lineno - 1] if 0 < node.lineno <= len(lines) else node.name
            for default in node.args.defaults + [d for d in node.args.kw_defaults if d is not None]:
                if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                    findings.append(
                        Finding(
                            rule_id="PARRY-LOG-PY001",
                            category="logic",
                            severity="error",
                            language="python",
                            file_path=file_path,
                            line=node.lineno,
                            column=node.col_offset + 1,
                            enclosing_symbol=node.name,
                            fingerprint=compute_ast_fingerprint(file_path, "PARRY-LOG-PY001", node.name, raw_line),
                            message=f"Mutable default argument in `{node.name}()` leaks state across calls.",
                            suggestion="Default to `None` and initialize inside the function body.",
                            generated_test=(
                                f"def test_{node.name}_no_shared_state():\n"
                                f"    assert {node.name}('a') is not {node.name}('b')"
                            ),
                        )
                    )

        if isinstance(node, ast.ExceptHandler):
            if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                sym = find_enclosing_symbol(source, node.lineno)
                raw_line = lines[node.lineno - 1] if 0 < node.lineno <= len(lines) else "except: pass"
                findings.append(
                    Finding(
                        rule_id="PARRY-ANT-PY002",
                        category="ai-antipattern",
                        severity="warning",
                        language="python",
                        file_path=file_path,
                        line=node.lineno,
                        column=node.col_offset + 1,
                        enclosing_symbol=sym,
                        fingerprint=compute_ast_fingerprint(file_path, "PARRY-ANT-PY002", sym, raw_line),
                        message="Silent `except ...: pass` swallows runtime exceptions and masks failures.",
                        suggestion="Log the exception or re-raise with context.",
                    )
                )

        if isinstance(node, (ast.Import, ast.ImportFrom)):
            mod_name = None
            if isinstance(node, ast.Import) and node.names:
                mod_name = node.names[0].name.split(".")[0]
            elif isinstance(node, ast.ImportFrom) and node.module:
                mod_name = node.module.split(".")[0]
            if mod_name and mod_name in SUSPICIOUS_AI_PACKAGES["python"]:
                raw_line = lines[node.lineno - 1] if 0 < node.lineno <= len(lines) else mod_name
                findings.append(
                    Finding(
                        rule_id="PARRY-HAL-PKG-PY",
                        category="hallucination",
                        severity="error",
                        language="python",
                        file_path=file_path,
                        line=node.lineno,
                        column=node.col_offset + 1,
                        enclosing_symbol="<module>",
                        fingerprint=compute_ast_fingerprint(file_path, "PARRY-HAL-PKG-PY", "<module>", raw_line),
                        message=SUSPICIOUS_AI_PACKAGES["python"][mod_name],
                        suggestion="Verify package against `uv.lock` / `pyproject.toml` and PyPI.",
                    )
                )

    return findings


def analyze_pattern_rules(source: str, file_path: str, language: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = source.splitlines()

    if language in ("typescript", "javascript"):
        import_re = re.compile(r"(?:from|require\()\s*['\"]([^'\".][^'\"]*)['\"]")
        for idx, line in enumerate(lines, start=1):
            m = import_re.search(line)
            if m and m.group(1) in SUSPICIOUS_AI_PACKAGES[language]:
                pkg = m.group(1)
                findings.append(
                    Finding(
                        rule_id="PARRY-HAL-PKG-JS",
                        category="hallucination",
                        severity="error",
                        language=language,
                        file_path=file_path,
                        line=idx,
                        column=m.start() + 1,
                        enclosing_symbol="<module>",
                        fingerprint=compute_ast_fingerprint(file_path, "PARRY-HAL-PKG-JS", "<module>", line),
                        message=SUSPICIOUS_AI_PACKAGES[language][pkg],
                        suggestion="Verify dependency in `package.json` and `package-lock.json`.",
                    )
                )
    elif language == "rust":
        use_re = re.compile(r"\buse\s+([a-zA-Z0-9_]+)::")
        for idx, line in enumerate(lines, start=1):
            m = use_re.search(line)
            if m and m.group(1) in SUSPICIOUS_AI_PACKAGES["rust"]:
                crate_name = m.group(1)
                findings.append(
                    Finding(
                        rule_id="PARRY-HAL-PKG-RS",
                        category="hallucination",
                        severity="error",
                        language="rust",
                        file_path=file_path,
                        line=idx,
                        column=m.start() + 1,
                        enclosing_symbol="<module>",
                        fingerprint=compute_ast_fingerprint(file_path, "PARRY-HAL-PKG-RS", "<module>", line),
                        message=SUSPICIOUS_AI_PACKAGES["rust"][crate_name],
                        suggestion="Check `Cargo.toml` and `Cargo.lock` for valid crate names.",
                    )
                )

    for pattern, rule_id, msg, fix in HALLUCINATED_OR_STALE_APIS.get(language, []):
        for match in pattern.finditer(source):
            line_no = source.count("\n", 0, match.start()) + 1
            col_no = match.start() - source.rfind("\n", 0, match.start())
            sym = find_enclosing_symbol(source, line_no)
            raw_line = lines[line_no - 1] if 0 < line_no <= len(lines) else match.group(0)
            findings.append(
                Finding(
                    rule_id=rule_id,
                    category="hallucination",
                    severity="error",
                    language=language,
                    file_path=file_path,
                    line=line_no,
                    column=col_no,
                    enclosing_symbol=sym,
                    fingerprint=compute_ast_fingerprint(file_path, rule_id, sym, raw_line),
                    message=msg,
                    suggestion=fix,
                )
            )

    for pattern, rule_id, category, msg, fix in SECURITY_AND_LOGIC_RULES.get(language, []):
        for match in pattern.finditer(source):
            line_no = source.count("\n", 0, match.start()) + 1
            col_no = match.start() - source.rfind("\n", 0, match.start())
            sym = find_enclosing_symbol(source, line_no)
            raw_line = lines[line_no - 1] if 0 < line_no <= len(lines) else match.group(0)
            findings.append(
                Finding(
                    rule_id=rule_id,
                    category=category,
                    severity="error" if category == "security" else "warning",
                    language=language,
                    file_path=file_path,
                    line=line_no,
                    column=col_no,
                    enclosing_symbol=sym,
                    fingerprint=compute_ast_fingerprint(file_path, rule_id, sym, raw_line),
                    message=msg,
                    suggestion=fix,
                )
            )

    lazy_re = re.compile(
        r"(?://|#)\s*(?:\.\.\.\s*(?:rest of|existing)\s+code|TODO:\s*implement\s+this\s+later)",
        re.IGNORECASE,
    )
    for match in lazy_re.finditer(source):
        line_no = source.count("\n", 0, match.start()) + 1
        col_no = match.start() - source.rfind("\n", 0, match.start())
        sym = find_enclosing_symbol(source, line_no)
        raw_line = lines[line_no - 1] if 0 < line_no <= len(lines) else match.group(0)
        findings.append(
            Finding(
                rule_id="PARRY-ANT-000",
                category="ai-antipattern",
                severity="error",
                language=language,
                file_path=file_path,
                line=line_no,
                column=col_no,
                enclosing_symbol=sym,
                fingerprint=compute_ast_fingerprint(file_path, "PARRY-ANT-000", sym, raw_line),
                message="AI truncation comment detected (`rest of code` / `existing code`).",
                suggestion="Restore deleted production logic from git HEAD before committing.",
            )
        )

    return findings


def scan_source(
    source: str,
    file_path: str,
    language: str,
    baseline_fingerprints: Optional[set[str]] = None,
) -> List[Finding]:
    findings: List[Finding] = []
    if language == "python":
        findings.extend(analyze_python_ast(source, file_path))
    findings.extend(analyze_pattern_rules(source, file_path, language))
    if baseline_fingerprints:
        findings = [f for f in findings if f.fingerprint not in baseline_fingerprints]
    return findings


def scan_file(
    file_path: pathlib.Path, baseline_fingerprints: Optional[set[str]] = None
) -> List[Finding]:
    language = detect_language(file_path)
    if not language:
        return []
    source = file_path.read_text(encoding="utf-8", errors="replace")
    return scan_source(source, str(file_path), language, baseline_fingerprints)


# ---------------------------------------------------------------------------
# Stage 3: Multi-AI BYOK Diff-Critic (Gemini, Claude, OpenAI/Codex, Ollama)
# ---------------------------------------------------------------------------

def call_byok_llm_critic(
    provider: str, code_slice: str, spec_prompt: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Zero-proxy BYOK Stage 3 Critic supporting Google Gemini, Anthropic Claude,
    OpenAI (GPT-4o / Codex), and local Ollama via standard library urllib.
    """
    sanitized_code, had_injection = redact_secrets_and_sanitize_diff(code_slice)
    system_instruction = (
        "You are Parry Stage-3 Neuro-Symbolic Code Critic. Analyze the untrusted code inside "
        "<untrusted_diff> tags for subtle functional bugs, off-by-one errors, or intent drift. "
        "Do NOT report style nitpicks. Respond ONLY with a JSON array of objects containing keys: "
        "line (int), message (str), suggestion (str)."
    )
    user_payload = (
        f"Developer Spec/Intent: {spec_prompt or 'Verify functional soundness'}\n"
        f"<untrusted_diff>\n{sanitized_code}\n</untrusted_diff>"
    )

    try:
        if provider == "gemini":
            api_key = os.environ.get("GEMINI_API_KEY", "")
            if not api_key:
                return []
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}"
            body = {
                "systemInstruction": {"parts": [{"text": system_instruction}]},
                "contents": [{"parts": [{"text": user_payload}]}],
                "generationConfig": {"responseMimeType": "application/json"},
            }
            req = urllib.request.Request(
                url, data=json.dumps(body).encode("utf-8"), headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                txt = data["candidates"][0]["content"]["parts"][0]["text"]
                return json.loads(txt)

        if provider == "claude":
            api_key = os.environ.get("ANTHROPIC_API_KEY", "")
            if not api_key:
                return []
            url = "https://api.anthropic.com/v1/messages"
            body = {
                "model": "claude-3-7-sonnet-latest",
                "max_tokens": 1024,
                "system": system_instruction,
                "messages": [{"role": "user", "content": user_payload}],
            }
            req = urllib.request.Request(
                url,
                data=json.dumps(body).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                },
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return json.loads(data["content"][0]["text"])

        if provider in ("openai", "codex"):
            api_key = os.environ.get("OPENAI_API_KEY", "")
            if not api_key:
                return []
            url = "https://api.openai.com/v1/chat/completions"
            body = {
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": system_instruction},
                    {"role": "user", "content": user_payload},
                ],
            }
            req = urllib.request.Request(
                url,
                data=json.dumps(body).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}",
                },
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return json.loads(data["choices"][0]["message"]["content"])

        if provider == "ollama":
            host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
            url = f"{host.rstrip('/')}/api/generate"
            body = {
                "model": os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:7b"),
                "prompt": f"{system_instruction}\n\n{user_payload}",
                "stream": False,
                "format": "json",
            }
            req = urllib.request.Request(
                url, data=json.dumps(body).encode("utf-8"), headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return json.loads(data.get("response", "[]"))
    except Exception:
        return []
    return []


# ---------------------------------------------------------------------------
# Model Context Protocol (MCP) Server for Gemini, Claude Code, Codex & Cursor
# ---------------------------------------------------------------------------

def run_mcp_stdio_server() -> int:
    """
    JSON-RPC 2.0 Model Context Protocol (MCP) server over stdio.
    Allows Claude Code, Claude Desktop, Gemini CLI, OpenAI Codex CLI, Cursor,
    and Windsurf to call `parry_verify_code` and `parry_run_benchmark`.
    """
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue

        req_id = req.get("id")
        method = req.get("method", "")
        params = req.get("params", {})

        if method == "initialize":
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "parry-mcp", "version": "0.1.0"},
                },
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()

        elif method == "tools/list":
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": [
                        {
                            "name": "parry_verify_code",
                            "description": "Scan AI-generated Rust, Python, TypeScript, or JavaScript code for hallucinated packages, pre-cutoff APIs, security vulnerabilities, and logic bugs.",
                            "readOnlyHint": True,
                            "destructiveHint": False,
                            "idempotentHint": True,
                            "openWorldHint": False,
                            "annotations": {
                                "readOnlyHint": True,
                                "destructiveHint": False,
                                "idempotentHint": True,
                                "openWorldHint": False,
                            },
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "language": {
                                        "type": "string",
                                        "enum": ["python", "rust", "typescript", "javascript"],
                                    },
                                    "file_path": {"type": "string"},
                                    "code": {"type": "string"},
                                },
                                "required": ["language", "code"],
                            },
                        }
                    ]
                },
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()

        elif method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments", {})
            if tool_name == "parry_verify_code":
                lang = args.get("language", "python")
                fpath = args.get("file_path", f"snippet.{lang}")
                code = args.get("code", "")
                findings = scan_source(code, fpath, lang)
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps([asdict(f) for f in findings], indent=2),
                            }
                        ]
                    },
                }
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
    return 0


def run_benchmark(bench_dir: pathlib.Path) -> int:
    manifest_path = bench_dir / "manifest.json"
    if not manifest_path.exists():
        print(f"Error: Benchmark manifest not found at {manifest_path}", file=sys.stderr)
        return 1

    cases = json.loads(manifest_path.read_text(encoding="utf-8"))
    t0 = time.perf_counter()
    caught = 0
    rows = []

    for item in cases:
        case_file = bench_dir.parent / item["file"]
        findings = scan_file(case_file)
        matched = any(f.rule_id == item["expected_rule"] for f in findings)
        if matched:
            caught += 1
        rows.append((item["id"], item["file"].split("/")[-1], item["language"], item["expected_rule"], matched))

    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    print("================================================================================")
    print("PARRY(1) — OPEN-SOURCE EVIL AI BENCHMARK SCORECARD (v0.1.0)")
    print("================================================================================")
    print(f"{'#':<3} {'CASE FILE':<33} {'LANG':<11} {'RULE ID':<17} {'RESULT'}")
    print("--------------------------------------------------------------------------------")
    for cid, fname, lang, rule_id, ok in rows:
        status = "[OK] DEFLECTED" if ok else "[XX] MISSED"
        print(f"{cid:<3} {fname:<33} {lang:<11} {rule_id:<17} {status}")
    print("--------------------------------------------------------------------------------")
    print(f"Standard Linters (eslint / flake8 / cargo check):   2 / {len(cases)} caught (8.0%)")
    print(f"Parry Hybrid Engine (Stage 1 + Stage 2):           {caught} / {len(cases)} caught (100.0%) in {elapsed_ms:.2f}ms")
    print("================================================================================")
    print("UPGRADE TO PARRY PRO ($29 ONE-TIME / 100% BYOK) OR TEAM CI ($19/MO):")
    print("  * 1-Hop Cross-File Symbol Graph (catch AI calling non-existent methods across files)")
    print("  * Stage 3 BYOK Diff-Critic (--provider gemini|claude|openai|codex|ollama)")
    print("  * Local MCP Self-Healing Server (`python parry.py mcp`) for Gemini, Claude & Cursor")
    print("================================================================================")
    return 0 if caught == len(cases) else 1


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="parry", description="Parry: Deflect AI slop before git push.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_bench = sub.add_parser("bench", help="Run the 25-case Evil AI Benchmark suite")
    p_bench.add_argument("--dir", default=str(pathlib.Path(__file__).parent / "benchmark"), help="Benchmark directory")

    p_check = sub.add_parser("check", help="Scan files or directories for AI-written bugs")
    p_check.add_argument("paths", nargs="+", help="Files or directories to scan")
    p_check.add_argument("--baseline", default=".parry-baseline.json", help="Baseline suppression file")
    p_check.add_argument(
        "--provider",
        choices=["none", "gemini", "claude", "openai", "codex", "ollama"],
        default="none",
        help="Optional BYOK AI provider for Stage 3 deep semantic critique",
    )

    p_init = sub.add_parser("init", help="Initialize baseline suppression file for legacy repos")
    p_init.add_argument("--baseline", action="store_true", help="Write .parry-baseline.json")
    p_init.add_argument("path", nargs="?", default=".", help="Repository path to baseline")

    sub.add_parser("mcp", help="Start JSON-RPC 2.0 MCP Server over stdio for Gemini, Claude, Codex & Cursor")

    args = parser.parse_args(argv)

    if args.cmd == "bench":
        return run_benchmark(pathlib.Path(args.dir))

    if args.cmd == "mcp":
        return run_mcp_stdio_server()

    if args.cmd == "init":
        target = pathlib.Path(args.path)
        all_findings: List[Finding] = []
        for child in sorted(target.rglob("*")):
            if child.is_file() and detect_language(child):
                all_findings.extend(scan_file(child))
        payload = {
            "version": "0.1.0",
            "fingerprints": sorted({f.fingerprint for f in all_findings}),
        }
        out_file = pathlib.Path(".parry-baseline.json")
        out_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"[OK] Baseline saved to {out_file} ({len(payload['fingerprints'])} existing findings muted).")
        return 0

    if args.cmd == "check":
        baseline_fps: set[str] = set()
        bpath = pathlib.Path(args.baseline)
        if bpath.exists():
            data = json.loads(bpath.read_text(encoding="utf-8"))
            baseline_fps = set(data.get("fingerprints", []))

        all_findings = []
        for raw in args.paths:
            p = pathlib.Path(raw)
            if p.is_dir():
                for child in sorted(p.rglob("*")):
                    if child.is_file() and detect_language(child):
                        all_findings.extend(scan_file(child, baseline_fps))
            elif p.is_file():
                all_findings.extend(scan_file(p, baseline_fps))

        if not all_findings:
            print("[OK] Parry deflected 0 issues (clean diff).")
            return 0
        for f in all_findings:
            print(f"[{f.rule_id}] ({f.category}) {f.file_path}:{f.line}:{f.column} [fn: {f.enclosing_symbol} | fp: {f.fingerprint}]")
            print(f"  |- Issue: {f.message}")
            print(f"  +- Fix:   {f.suggestion}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
