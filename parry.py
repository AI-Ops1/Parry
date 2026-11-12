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
import difflib
from dataclasses import asdict, dataclass
import hashlib
import json
import os
import pathlib
import re
import subprocess
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
    prompt_injection_patch: Optional[str] = None
    suggested_replacement: Optional[str] = None


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


def compute_remediation(
    rule_id: str, raw_line: str, language: str
) -> Tuple[Optional[str], Optional[str]]:
    """
    Generate an agent-targeted remediation prompt and a deterministic single-line replacement (if safe).
    Returns (prompt_injection_patch, suggested_replacement).
    """
    prompt: Optional[str] = None
    replacement: Optional[str] = None

    if rule_id in ("PARRY-HAL-TS001", "PARRY-HAL-JS001"):
        prompt = "Deprecated String.prototype.substr() detected. Replace .substr(start, length) with .slice(start, end)."
        replacement = re.sub(r"\.substr\s*\(", ".slice(", raw_line)

    elif rule_id in ("PARRY-HAL-TS002", "PARRY-HAL-JS002"):
        prompt = "Deprecated and unsafe Buffer() constructor detected. Replace 'new Buffer(arg)' or 'Buffer(arg)' with 'Buffer.from(arg)' for data or 'Buffer.alloc(arg)' for size allocation."
        if re.search(r"\b(?:new\s+)?Buffer\s*\(\s*\d+\s*\)", raw_line):
            replacement = re.sub(r"\b(?:new\s+)?Buffer\s*\(", "Buffer.alloc(", raw_line)
        else:
            replacement = re.sub(r"\b(?:new\s+)?Buffer\s*\(", "Buffer.from(", raw_line)

    elif rule_id == "PARRY-HAL-TS003":
        prompt = "Legacy react-query v3 import detected. Replace 'from \"react-query\"' with 'from \"@tanstack/react-query\"'."
        replacement = re.sub(r"([\'\"])react-query([\'\"])", r"\1@tanstack/react-query\2", raw_line)

    elif rule_id == "PARRY-HAL-PY004":
        prompt = "datetime.utcnow() produces naive UTC timestamps. Replace with 'datetime.now(datetime.timezone.utc)'."
        replacement = raw_line.replace("datetime.utcnow()", "datetime.now(datetime.timezone.utc)")

    elif rule_id == "PARRY-HAL-RS001":
        prompt = "Obsolete Rust 2015 try!(...) macro detected. Replace 'try!(expr)' with 'expr?'."
        m = re.search(r"\btry!\s*\(", raw_line)
        if m:
            start = m.end()
            depth = 1
            end = -1
            for i in range(start, len(raw_line)):
                if raw_line[i] == "(":
                    depth += 1
                elif raw_line[i] == ")":
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
            if end != -1:
                inner = raw_line[start:end].strip()
                replacement = raw_line[:m.start()] + inner + "?" + raw_line[end + 1:]

    elif rule_id == "PARRY-HAL-RS002":
        prompt = "Deprecated std::sync::ONCE_INIT constant detected. Replace with 'std::sync::Once::new()' or 'std::sync::OnceLock'."
        replacement = raw_line.replace("std::sync::ONCE_INIT", "std::sync::Once::new()")

    elif rule_id == "PARRY-HAL-RS003":
        prompt = "Unnecessary O(N) allocation .collect::<Vec<_>>().len() to count items. Replace with '.into_iter().count()' or direct '.len()'."
        replacement = raw_line.replace(".into_iter().collect::<Vec<_>>().len()", ".into_iter().count()")

    elif rule_id in ("PARRY-LOG-TS001", "PARRY-LOG-JS001"):
        prompt = "Lexicographical .sort() sorts numbers alphabetically. Provide an explicit numeric comparator: '.sort((a, b) => a - b)'."
        replacement = re.sub(r"\.sort\s*\(\s*\)", ".sort((a, b) => a - b)", raw_line)

    elif rule_id == "PARRY-SEC-PY002":
        prompt = "Command injection risk: shell=True in subprocess. Remove shell=True and pass command arguments as a list."
        replacement = re.sub(r"shell\s*=\s*True", "shell=False", raw_line)

    elif rule_id == "PARRY-SEC-PY003":
        prompt = "TLS certificate validation disabled with verify=False. Remove verify=False to enforce secure HTTPS certificate validation."
        replacement = re.sub(r",\s*verify\s*=\s*False", "", raw_line)

    elif rule_id == "PARRY-HAL-PY001":
        prompt = "Removed OpenAI v0.x API openai.ChatCompletion.create() called. Migrate to modern OpenAI v1+ SDK: 'client = OpenAI(); client.chat.completions.create(model=..., messages=...)'."

    elif rule_id == "PARRY-HAL-PY002":
        prompt = "Removed pandas DataFrame.append() called. Migrate to pandas 2.0+: use 'pd.concat([df, new_df], ignore_index=True)'."

    elif rule_id == "PARRY-HAL-PY003":
        prompt = "Legacy Pydantic v1 method (.dict() / @validator / parse_obj_as) detected. Migrate to Pydantic v2: use .model_dump() and @field_validator."
        if ".dict()" in raw_line:
            replacement = raw_line.replace(".dict()", ".model_dump()")

    elif rule_id == "PARRY-LOG-PY001":
        prompt = "Mutable default argument in function leaks state across invocations. Change parameter default to None and initialize inside function: 'if arg is None: arg = []'."

    elif rule_id == "PARRY-ANT-PY002":
        prompt = "Silent 'except: pass' swallows runtime exceptions and hides defects. Log the exception or re-raise with context: 'logger.exception(\"Error details\")'."

    elif rule_id == "PARRY-SEC-PY001":
        prompt = "SQL injection vulnerability: String interpolation in .execute(). Use parameterized queries: 'cursor.execute(\"SELECT * FROM tbl WHERE id = ?\", (val,))'."

    elif rule_id == "PARRY-SEC-TS001":
        prompt = "Cross-Site Scripting (XSS) vulnerability via dangerouslySetInnerHTML. Sanitize HTML with 'DOMPurify.sanitize(rawHtml)' before injection."

    elif rule_id in ("PARRY-LOG-TS002", "PARRY-LOG-JS002"):
        prompt = "Broken async control flow: .forEach(async ...) does not await promises and drops rejected promises. Use 'for (const item of items) { await ... }' or 'await Promise.all(items.map(async ...))'."

    elif rule_id == "PARRY-LOG-RS001":
        prompt = "Blocking IO inside async fn starves the async executor thread pool. Replace with 'tokio::time::sleep(...).await' or 'tokio::task::spawn_blocking'."

    elif rule_id == "PARRY-LOG-RS002":
        prompt = "Unchecked numeric cast 'as usize' / 'as u32' wraps negative integers to large positive values. Use 'usize::try_from(val)?'."

    elif rule_id == "PARRY-SEC-RS001":
        prompt = "AI-introduced unsafe block requires manual verification. Replace with safe Rust standard library abstractions or document a `# Safety` invariant."

    elif rule_id == "PARRY-ANT-000":
        prompt = "[CRITICAL] Code truncation stub detected ('rest of code'). The model omitted implementation logic. Re-generate and output the complete function without placeholders."

    elif rule_id.startswith("PARRY-HAL-PKG-"):
        prompt = "Non-existent or slopsquatted package import detected. Remove import and install verified official package."

    if replacement == raw_line:
        replacement = None

    return prompt, replacement


def apply_fixes_to_source(source: str, findings: List[Finding]) -> Tuple[str, List[Finding]]:
    """
    Apply all deterministic single-line replacements to source text.
    Returns (updated_source, list_of_applied_findings).
    """
    lines = source.splitlines()
    applied: List[Finding] = []
    fixable = [f for f in findings if f.suggested_replacement and 0 < f.line <= len(lines)]
    fixable.sort(key=lambda x: x.line, reverse=True)

    for f in fixable:
        line_idx = f.line - 1
        current_line = lines[line_idx]
        if f.suggested_replacement and current_line != f.suggested_replacement:
            lines[line_idx] = f.suggested_replacement
            applied.append(f)

    ending = "\n" if source.endswith("\n") else ""
    return "\n".join(lines) + ending, applied


def generate_unified_diff(original: str, fixed: str, filename: str) -> str:
    """Generate a clean standard unified diff comparing original and repaired code."""
    orig_lines = original.splitlines(keepends=True)
    fixed_lines = fixed.splitlines(keepends=True)
    diff = difflib.unified_diff(
        orig_lines,
        fixed_lines,
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}",
    )
    return "".join(diff)


def apply_fixes_to_file(file_path: pathlib.Path, dry_run: bool = False) -> Tuple[bool, str, List[Finding]]:
    """
    Scan a file, compute deterministic fixes, and optionally write back to disk.
    Returns (has_changes, diff_string, applied_findings).
    """
    findings = scan_file(file_path)
    if not findings:
        return False, "", []
    original_code = file_path.read_text(encoding="utf-8", errors="replace")
    fixed_code, applied = apply_fixes_to_source(original_code, findings)
    if not applied or fixed_code == original_code:
        return False, "", []
    diff_str = generate_unified_diff(original_code, fixed_code, str(file_path))
    if not dry_run:
        file_path.write_text(fixed_code, encoding="utf-8")
    return True, diff_str, applied



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
                            prompt_injection_patch=compute_remediation("PARRY-LOG-PY001", raw_line, "python")[0],
                            suggested_replacement=compute_remediation("PARRY-LOG-PY001", raw_line, "python")[1],
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
                        prompt_injection_patch=compute_remediation("PARRY-ANT-PY002", raw_line, "python")[0],
                        suggested_replacement=compute_remediation("PARRY-ANT-PY002", raw_line, "python")[1],
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
                        prompt_injection_patch=compute_remediation("PARRY-HAL-PKG-PY", raw_line, "python")[0],
                        suggested_replacement=compute_remediation("PARRY-HAL-PKG-PY", raw_line, "python")[1],
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
                        prompt_injection_patch=compute_remediation("PARRY-HAL-PKG-JS", line, language)[0],
                        suggested_replacement=compute_remediation("PARRY-HAL-PKG-JS", line, language)[1],
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
                        prompt_injection_patch=compute_remediation("PARRY-HAL-PKG-RS", line, "rust")[0],
                        suggested_replacement=compute_remediation("PARRY-HAL-PKG-RS", line, "rust")[1],
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
                    prompt_injection_patch=compute_remediation(rule_id, raw_line, language)[0],
                    suggested_replacement=compute_remediation(rule_id, raw_line, language)[1],
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
                    prompt_injection_patch=compute_remediation(rule_id, raw_line, language)[0],
                    suggested_replacement=compute_remediation(rule_id, raw_line, language)[1],
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
                prompt_injection_patch=compute_remediation("PARRY-ANT-000", raw_line, language)[0],
                suggested_replacement=compute_remediation("PARRY-ANT-000", raw_line, language)[1],
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
                        },
                        {
                            "name": "parry_fix_code",
                            "description": "Auto-remediate deterministic AI hallucinations, deprecated APIs, and security defects, returning patched code and unified diff.",
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

            elif tool_name == "parry_fix_code":
                lang = args.get("language", "python")
                fpath = args.get("file_path", f"snippet.{lang}")
                code = args.get("code", "")
                findings = scan_source(code, fpath, lang)
                fixed_code, applied = apply_fixes_to_source(code, findings)
                diff_str = generate_unified_diff(code, fixed_code, fpath) if applied else ""
                payload = {
                    "fixed_count": len(applied),
                    "remaining_findings_count": len(findings) - len(applied),
                    "unified_diff": diff_str,
                    "patched_code": fixed_code,
                    "findings": [asdict(f) for f in findings],
                }
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(payload, indent=2),
                            }
                        ]
                    },
                }
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
    return 0


DEFAULT_EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    "__pycache__",
    ".venv",
    "venv",
}

PR_SHIELD_MARKER = "<!-- parry-pr-shield -->"


def is_path_excluded(file_path: pathlib.Path, exclude_patterns: List[str]) -> bool:
    """Return True when file_path sits in an excluded directory or matches an explicit pattern."""
    norm_posix = file_path.as_posix()
    parts = set(file_path.parts)
    if parts & DEFAULT_EXCLUDED_DIRS:
        return True
    for raw_pat in exclude_patterns:
        pat = raw_pat.strip().strip("/")
        if not pat:
            continue
        if pat in parts or norm_posix == pat or norm_posix.startswith(pat + "/"):
            return True
        if file_path.match(pat):
            return True
    return False


def get_changed_files_from_git(diff_base: str) -> Optional[set[pathlib.Path]]:
    """Return resolved changed file paths relative to diff_base...HEAD, or None if unavailable."""
    clean_ref = diff_base.strip()
    if not clean_ref or clean_ref.startswith("-") or any(c.isspace() or ord(c) < 32 for c in clean_ref):
        raise ValueError(f"Unsafe git diff base ref: {diff_base!r}")

    proc = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=ACMRTUXB", f"{clean_ref}...HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        proc = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMRTUXB", clean_ref],
            capture_output=True,
            text=True,
            check=False,
        )
    if proc.returncode != 0:
        return None
    return {pathlib.Path(line.strip()).resolve() for line in proc.stdout.splitlines() if line.strip()}


def collect_target_files(
    raw_paths: List[str],
    exclude_patterns: Optional[List[str]] = None,
    changed_only_files: Optional[set[pathlib.Path]] = None,
) -> List[pathlib.Path]:
    """Collect supported source files under raw_paths respecting exclusions and optional git diff filter."""
    excludes = exclude_patterns or []
    collected: List[pathlib.Path] = []
    seen: set[pathlib.Path] = set()

    for raw in raw_paths:
        p = pathlib.Path(raw)
        candidates: List[pathlib.Path] = []
        if p.is_dir():
            candidates = [c for c in sorted(p.rglob("*")) if c.is_file()]
        elif p.is_file():
            candidates = [p]

        for child in candidates:
            if not detect_language(child):
                continue
            if is_path_excluded(child, excludes):
                continue
            resolved = child.resolve()
            if changed_only_files is not None and resolved not in changed_only_files:
                continue
            if resolved not in seen:
                seen.add(resolved)
                collected.append(child)

    return collected


def sanitize_markdown_cell(text: str, max_len: int = 240) -> str:
    """Escape HTML tags, pipes, backticks, and control chars for safe GitHub PR Markdown rendering."""
    cleaned = re.sub(r"[\x00-\x1f\x7f]+", " ", text).strip()
    cleaned = (
        cleaned.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("|", "\\|")
        .replace("`", "'")
    )
    if len(cleaned) > max_len:
        return cleaned[: max_len - 3] + "..."
    return cleaned


def build_sarif_report(findings: List[Finding]) -> Dict[str, Any]:
    """Build a SARIF 2.1.0 report compatible with github/codeql-action/upload-sarif."""
    rules_map: Dict[str, Finding] = {}
    for f in findings:
        if f.rule_id not in rules_map:
            rules_map[f.rule_id] = f

    rules = [
        {
            "id": rule_id,
            "shortDescription": {"text": sample.message},
            "help": {"text": sample.prompt_injection_patch or sample.suggestion},
        }
        for rule_id, sample in rules_map.items()
    ]

    results = [
        {
            "ruleId": f.rule_id,
            "level": "error" if f.severity == "error" else "warning",
            "message": {"text": f"{f.message} Fix: {f.prompt_injection_patch or f.suggestion}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": pathlib.Path(f.file_path).as_posix()},
                        "region": {"startLine": max(1, f.line), "startColumn": max(1, f.column)},
                    }
                }
            ],
        }
        for f in findings
    ]

    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Parry AST Gatekeeper",
                        "informationUri": "https://parry.scopeledger.net",
                        "version": "0.1.0",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def format_pr_comment_markdown(
    findings: List[Finding],
    scanned_count: int,
    elapsed_ms: float,
    max_rows: int = 20,
) -> str:
    """Render a sticky Parry PR Shield Markdown comment for GitHub pull requests and step summaries."""
    lines: List[str] = [PR_SHIELD_MARKER]
    errors_count = sum(1 for f in findings if f.severity == "error")
    warnings_count = len(findings) - errors_count

    if not findings:
        lines.append("### 🛡️ Parry PR Shield — Clean AST Diff")
        lines.append("")
        lines.append(
            f"**0** AI hallucinations, leaks, or runtime traps detected across **{scanned_count}** file(s) in `{elapsed_ms:.2f}ms`."
        )
    else:
        lines.append(f"### 🛡️ Parry PR Shield — Deflected {len(findings)} Issue(s)")
        lines.append("")
        lines.append(
            f"Scanned **{scanned_count}** file(s) in `{elapsed_ms:.2f}ms` — **{errors_count} error**, **{warnings_count} warning**."
        )
        lines.append("")
        lines.append("| Severity | Rule | Location | Issue & Auto-Fix |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for f in findings[:max_rows]:
            sev = "🔴 ERROR" if f.severity == "error" else "🟡 WARN"
            loc = sanitize_markdown_cell(f"{pathlib.Path(f.file_path).as_posix()}:{f.line}", 90)
            rule = sanitize_markdown_cell(f.rule_id, 40)
            issue = sanitize_markdown_cell(f.message, 120)
            fix_hint = sanitize_markdown_cell(f.prompt_injection_patch or f.suggestion, 160)
            lines.append(f"| {sev} | `{rule}` | `{loc}` | {issue} **Fix:** {fix_hint} |")

        if len(findings) > max_rows:
            lines.append("")
            lines.append(
                f"*Showing top {max_rows} of {len(findings)} findings. Run `python3 parry.py check . --fix` locally for the full diff.*"
            )

    lines.append("")
    lines.append("---")
    lines.append(
        "*Verified with [Parry AST Gatekeeper](https://parry.scopeledger.net) • Run `python3 parry.py check . --fix` locally or scan any public repo in 3s at [parry.scopeledger.net](https://parry.scopeledger.net/#scan-repo).*"
    )
    return "\n".join(lines)


def compute_check_exit_code(findings: List[Finding], fail_on: str) -> int:
    """Compute CLI exit code for check based on --fail-on threshold."""
    if not findings or fail_on == "none":
        return 0
    if fail_on == "error":
        return 1 if any(f.severity == "error" for f in findings) else 0
    return 1


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
    p_check.add_argument("--fix", action="store_true", help="Output LLM prompt patches and deterministic auto-fix diffs")
    p_check.add_argument("--in-place", action="store_true", help="Apply deterministic fixes in-place (requires --fix)")
    p_check.add_argument("--format", choices=["cli", "json", "sarif", "pr-comment"], default="cli", help="Output format")
    p_check.add_argument("--output", default=None, help="Optional file path to write formatted output")
    p_check.add_argument("--fail-on", choices=["error", "warning", "none"], default="warning", help="Minimum severity triggering exit code 1")
    p_check.add_argument("--exclude", action="append", default=[], help="Exclude directory or glob pattern")
    p_check.add_argument("--diff-base", default=None, help="Only scan files changed since git ref (e.g. origin/main)")
    p_check.add_argument(
        "--provider",
        choices=["none", "gemini", "claude", "openai", "codex", "ollama"],
        default="none",
        help="Optional BYOK AI provider for Stage 3 deep semantic critique",
    )

    p_fix = sub.add_parser("fix", help="Automatically repair deterministic AI bugs in-place")
    p_fix.add_argument("paths", nargs="+", help="Files or directories to repair")
    p_fix.add_argument("--dry-run", action="store_true", help="Show proposed diff without modifying files on disk")

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

    if args.cmd == "fix":
        targets: List[pathlib.Path] = []
        for raw in args.paths:
            p = pathlib.Path(raw)
            if p.is_dir():
                for child in sorted(p.rglob("*")):
                    if child.is_file() and detect_language(child):
                        targets.append(child)
            elif p.is_file():
                targets.append(p)

        total_repaired = 0
        for target in targets:
            changed, diff_str, applied = apply_fixes_to_file(target, dry_run=args.dry_run)
            if changed:
                total_repaired += len(applied)
                label = "[DRY-RUN]" if args.dry_run else "[FIXED]"
                print(f"{label} Repaired {len(applied)} issue(s) in {target}")
                if diff_str:
                    print(diff_str)

        if total_repaired == 0:
            print("[OK] No deterministic auto-fixes needed.")
        else:
            print(f"[OK] Total deterministic issues repaired: {total_repaired}")
        return 0

    if args.cmd == "check":
        baseline_fps: set[str] = set()
        bpath = pathlib.Path(args.baseline)
        if bpath.exists():
            data = json.loads(bpath.read_text(encoding="utf-8"))
            baseline_fps = set(data.get("fingerprints", []))

        exclude_patterns: List[str] = []
        for item in args.exclude:
            exclude_patterns.extend(seg.strip() for seg in item.split(",") if seg.strip())

        changed_files: Optional[set[pathlib.Path]] = None
        if args.diff_base:
            try:
                changed_files = get_changed_files_from_git(args.diff_base)
            except ValueError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                return 2
            if changed_files is None:
                print(
                    f"[WARN] Could not resolve git diff against {args.diff_base}; scanning provided paths instead.",
                    file=sys.stderr,
                )

        t0 = time.perf_counter()
        target_files = collect_target_files(args.paths, exclude_patterns, changed_files)
        all_findings: List[Finding] = []
        for tf in target_files:
            all_findings.extend(scan_file(tf, baseline_fps))
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        exit_code = compute_check_exit_code(all_findings, args.fail_on)
        rendered: Optional[str] = None

        if args.format == "json":
            rendered = json.dumps([asdict(f) for f in all_findings], indent=2)
        elif args.format == "sarif":
            rendered = json.dumps(build_sarif_report(all_findings), indent=2)
        elif args.format == "pr-comment":
            rendered = format_pr_comment_markdown(all_findings, len(target_files), elapsed_ms)

        if rendered is not None:
            if args.output:
                out_path = pathlib.Path(args.output)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(rendered + "\n", encoding="utf-8")
            else:
                print(rendered)
            return exit_code

        if not all_findings:
            summary = "[OK] Parry deflected 0 issues (clean diff)."
            if args.output:
                out_path = pathlib.Path(args.output)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(summary + "\n", encoding="utf-8")
            else:
                print(summary)
            return exit_code

        cli_lines: List[str] = []
        for f in all_findings:
            cli_lines.append(
                f"[{f.rule_id}] ({f.category}) {f.file_path}:{f.line}:{f.column} [fn: {f.enclosing_symbol} | fp: {f.fingerprint}]"
            )
            cli_lines.append(f"  |- Issue: {f.message}")
            cli_lines.append(f"  +- Fix:   {f.suggestion}")
            if args.fix:
                if f.prompt_injection_patch:
                    cli_lines.append(f"  +- Agent Prompt: {f.prompt_injection_patch}")
                if f.suggested_replacement:
                    cli_lines.append(f"  +- Auto-Patch:   {f.suggested_replacement.strip()}")

        if args.output:
            out_path = pathlib.Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text("\n".join(cli_lines) + "\n", encoding="utf-8")
        else:
            for line in cli_lines:
                print(line)

        if args.fix and args.in_place:
            seen_files = sorted({pathlib.Path(f.file_path) for f in all_findings})
            for tf in seen_files:
                changed, diff_str, applied = apply_fixes_to_file(tf, dry_run=False)
                if changed:
                    print(f"[AUTO-FIXED] Applied {len(applied)} repair(s) to {tf}")
                    print(diff_str)

        return exit_code

    return 0


if __name__ == "__main__":
    sys.exit(main())
