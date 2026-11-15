# Parry Agent Security & Guardrail Upgrades Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend Parry's deterministic AST verification engine, pre-commit/pre-push hooks, and CLI to protect against IDOR vulnerabilities, enforce one-way door guardrails for coding agents, provide sub-second agent feedback loops, audit context/secret isolation, and handle canary tokens.

**Architecture:** Pure standard-library Python (3.9+) with zero third-party runtime dependencies. The core AST engine in `parry.py` is augmented with dedicated rule matchers for IDOR ownership scoping and schema enumeration traps; `ide_hooks.py` is updated with pre-push one-way door hooks and context file hygiene validators; a specialized `--agent` CLI mode is added for machine-parsable instant repair loops.

**Tech Stack:** Python 3.9+, `ast`, `re`, `argparse`, `dataclasses`, `unittest`.

**Spec:** Direct requirements derived from the 4 X/Twitter bookmarks review on AI coding agent bottlenecks, OWASP API #1 IDOR vulnerabilities, `AGENTS.md` one-way doors, canary tokens, and sub-second CI feedback.

## Global Constraints

- Zero third-party runtime dependencies (runs entirely on standard Python 3.9+).
- Sub-millisecond to sub-second deterministic execution speed (<250ms full suite, <15ms single file check).
- Backward compatibility: all existing 41 tests across all gates must continue to pass 100%.
- Non-breaking CLI interface: existing flags (`check`, `bench`, `mcp`, `fix`, `ide-hook`) retain current behavior.
- Every rule must emit a deterministic `rule_id`, `category`, `severity`, `fingerprint`, and actionable `prompt_injection_patch` / `suggested_replacement`.

## Review Focus

1. False positives on legitimate public or unauthenticated endpoints (e.g., `/health`, `/metrics`, public blog posts).
2. Edge cases in regex/AST detection of Express `req.params.id` and Next.js dynamic routes `[id]` where authorization middleware or helper functions are used.
3. Windows vs Linux path normalization in `.cursorignore` and context file audits.
4. Distinguishing intentional Canary tokens from accidental credential leaks without allowing real keys to bypass.
5. Handling git `--no-verify` or missing git binary gracefully in pre-push hook installations.

---

### Task 1: IDOR & Object-Level Authorization AST Rule (`PARRY-SEC-API001`)

**Files:**
- Modify: `D:\Parry\parry_evil_ai_benchmark_repo\parry.py:600-650` (pattern rules & remediation mapping)
- Test: `D:\Parry\parry_evil_ai_benchmark_repo\test_parry_api_security.py`

**Interfaces:**
- Consumes: `analyze_pattern_rules`, `compute_remediation`, `Finding`
- Produces: `PARRY-SEC-API001` finding when route handlers query database by ID parameter without referencing user/session ownership context.

- [ ] **Step 1: Write the failing test**

```python
# test_parry_api_security.py
import unittest
from parry import scan_source

class TestApiSecurityIdor(unittest.TestCase):
    def test_idor_unscoped_db_query_flagged(self):
        vulnerable_code = """
        app.get('/api/invoices/:id', async (req, res) => {
            const invoice = await prisma.invoice.findUnique({
                where: { id: req.params.id }
            });
            res.json(invoice);
        });
        """
        findings = scan_source(vulnerable_code, "invoice_route.ts")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("PARRY-SEC-API001", rule_ids)

    def test_idor_scoped_db_query_passes(self):
        secure_code = """
        app.get('/api/invoices/:id', async (req, res) => {
            const invoice = await prisma.invoice.findFirst({
                where: { id: req.params.id, userId: req.user.id }
            });
            res.json(invoice);
        });
        """
        findings = scan_source(secure_code, "invoice_route.ts")
        rule_ids = [f.rule_id for f in findings]
        self.assertNotIn("PARRY-SEC-API001", rule_ids)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest test_parry_api_security.py -v`
Expected: FAIL with `PARRY-SEC-API001 not found in findings`

- [ ] **Step 3: Implement `PARRY-SEC-API001` in `parry.py`**

Add rule regex and remediation for TypeScript/JavaScript in `analyze_pattern_rules`:
Detect queries using `req.params.id` / `params.id` in `where: { id: ... }` / `findById(...)` that lack `userId`, `user_id`, `owner_id`, or `req.user` in the enclosing query block. Add remediation prompt: "OWASP API #1 IDOR detected: Scoped database query to session user (`WHERE id = :id AND user_id = :userId`)."

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest test_parry_api_security.py -v`
Expected: PASS (both tests pass)

- [ ] **Step 5: Commit**

```bash
git add parry.py test_parry_api_security.py
git commit -m "feat(security): add PARRY-SEC-API001 IDOR and object authorization AST rule"
```

---

### Task 2: "One-Way Door" Destructive Action Blocker (`PARRY-GATE-ONEWAY`)

**Files:**
- Modify: `D:\Parry\parry_evil_ai_benchmark_repo\parry.py` (add one-way door rule checks)
- Modify: `D:\Parry\parry_evil_ai_benchmark_repo\ide_hooks.py` (add pre-push git hook installation)
- Test: `D:\Parry\parry_evil_ai_benchmark_repo\test_parry_oneway_doors.py`

**Interfaces:**
- Consumes: `analyze_pattern_rules`, `install_git_pre_commit_hook`
- Produces: `PARRY-GATE-ONEWAY` finding; `install_git_pre_push_hook` function in `ide_hooks.py`

- [ ] **Step 1: Write the failing test**

```python
# test_parry_oneway_doors.py
import unittest
from parry import scan_source
from ide_hooks import install_git_pre_push_hook

class TestOneWayDoors(unittest.TestCase):
    def test_detect_force_push_script(self):
        code = "git push --force origin main"
        findings = scan_source(code, "deploy.sh")
        self.assertIn("PARRY-GATE-ONEWAY", [f.rule_id for f in findings])

    def test_detect_destructive_sql_drop(self):
        code = "DROP TABLE users CASCADE;"
        findings = scan_source(code, "cleanup.sql")
        self.assertIn("PARRY-GATE-ONEWAY", [f.rule_id for f in findings])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest test_parry_oneway_doors.py -v`
Expected: FAIL (cannot import `install_git_pre_push_hook`, `PARRY-GATE-ONEWAY` not defined)

- [ ] **Step 3: Implement `PARRY-GATE-ONEWAY` and `install_git_pre_push_hook`**

- In `parry.py`, add rule `PARRY-GATE-ONEWAY` checking for `git push (?:--force|-f)`, `git reset --hard`, `DROP TABLE`, `DROP DATABASE`, and `TRUNCATE TABLE`.
- In `ide_hooks.py`, implement `install_git_pre_push_hook(repo_root)` creating `.git/hooks/pre-push` that runs `python parry.py check --staged` or branch protection checks.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest test_parry_oneway_doors.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add parry.py ide_hooks.py test_parry_oneway_doors.py
git commit -m "feat(guardrails): add one-way door destructive command blocker and pre-push hook"
```

---

### Task 3: Sub-Second AI Agent Feedback Mode (`parry check --agent`)

**Files:**
- Modify: `D:\Parry\parry_evil_ai_benchmark_repo\parry.py` (CLI argument `--agent`, format output)
- Test: `D:\Parry\parry_evil_ai_benchmark_repo\test_parry_agent_mode.py`

**Interfaces:**
- Consumes: `main()`, `Finding`
- Produces: Single-line per finding formatted as `PARRY_AGENT_REPAIR | <file>:<line>:<col> | <rule_id> | <message> | REMEDY: <patch>`

- [ ] **Step 1: Write the failing test**

```python
# test_parry_agent_mode.py
import io
import unittest
from unittest.mock import patch
from parry import format_agent_feedback, Finding

class TestParryAgentMode(unittest.TestCase):
    def test_format_agent_feedback(self):
        finding = Finding(
            rule_id="PARRY-HAL-JS001",
            category="hallucination",
            severity="error",
            language="javascript",
            file_path="src/index.js",
            line=12,
            column=5,
            enclosing_symbol="getData",
            fingerprint="abc1234",
            message="Deprecated substr() used",
            suggestion="Use .slice()",
            prompt_injection_patch="Replace .substr() with .slice()"
        )
        output = format_agent_feedback([finding])
        self.assertIn("PARRY_AGENT_REPAIR", output)
        self.assertIn("src/index.js:12:5", output)
        self.assertIn("PARRY-HAL-JS001", output)
        self.assertIn("Replace .substr() with .slice()", output)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest test_parry_agent_mode.py -v`
Expected: FAIL (cannot import `format_agent_feedback`)

- [ ] **Step 3: Implement `format_agent_feedback` and CLI flag `--agent`**

- Add `format_agent_feedback(findings: List[Finding]) -> str` in `parry.py`.
- Add `--agent` flag to `argparse` in `main()`: outputs compact remediation lines with zero terminal ANSI escape codes and exits with standard code.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest test_parry_agent_mode.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add parry.py test_parry_agent_mode.py
git commit -m "feat(cli): add --agent mode for sub-second machine-parsable AI repair loops"
```

---

### Task 4: Context & Secret Isolation Gate (`.cursorignore` & Context File Leak Audit)

**Files:**
- Modify: `D:\Parry\parry_evil_ai_benchmark_repo\parry.py` (extend `discover_and_sanitize_repo_context`)
- Test: `D:\Parry\parry_evil_ai_benchmark_repo\test_parry_context_isolation.py`

**Interfaces:**
- Consumes: `discover_and_sanitize_repo_context`
- Produces: Audit findings for unignored `.env` or credential files in `.cursorignore` / `.gitignore`.

- [ ] **Step 1: Write the failing test**

```python
# test_parry_context_isolation.py
import tempfile
import pathlib
import unittest
from parry import audit_context_isolation

class TestContextIsolation(unittest.TestCase):
    def test_missing_env_in_cursorignore_flagged(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = pathlib.Path(tmpdir)
            tmp.joinpath(".env").write_text("SECRET=123", encoding="utf-8")
            # No .cursorignore exists
            issues = audit_context_isolation(tmp)
            self.assertTrue(any("cursorignore" in i.lower() for i in issues))

    def test_properly_ignored_env_passes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = pathlib.Path(tmpdir)
            tmp.joinpath(".env").write_text("SECRET=123", encoding="utf-8")
            tmp.joinpath(".cursorignore").write_text(".env*\n", encoding="utf-8")
            issues = audit_context_isolation(tmp)
            self.assertEqual(len(issues), 0)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest test_parry_context_isolation.py -v`
Expected: FAIL (cannot import `audit_context_isolation`)

- [ ] **Step 3: Implement `audit_context_isolation(target_dir: pathlib.Path) -> List[str]`**

In `parry.py`, implement audit checking whether sensitive patterns (`.env`, `*.pem`, `*.key`, `id_rsa`) present in the directory tree are omitted from `.cursorignore` and `.gitignore`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest test_parry_context_isolation.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add parry.py test_parry_context_isolation.py
git commit -m "feat(audit): add context and secret isolation audit for .cursorignore"
```

---

### Task 5: Canary Token Detection & Whitelisting in Secrets Engine

**Files:**
- Modify: `D:\Parry\parry_evil_ai_benchmark_repo\parry.py` (`redact_secrets_and_sanitize_diff` / pattern rules)
- Test: `D:\Parry\parry_evil_ai_benchmark_repo\test_parry_canary_tokens.py`

**Interfaces:**
- Consumes: `redact_secrets_and_sanitize_diff`, `analyze_pattern_rules`
- Produces: `is_canary_token(value: str) -> bool`, with `PARRY-SEC-CANARY` classification.

- [ ] **Step 1: Write the failing test**

```python
# test_parry_canary_tokens.py
import unittest
from parry import is_canary_token, scan_source

class TestCanaryTokens(unittest.TestCase):
    def test_identify_canary_aws_key(self):
        canary = "AKIACANARYTOKENEXAMPLE1"
        self.assertTrue(is_canary_token(canary))

    def test_identify_canary_domain_webhook(self):
        canary_url = "http://canarytokens.com/traffic/tags/sample/contact.php"
        self.assertTrue(is_canary_token(canary_url))

    def test_canary_tagged_separately_from_real_leak(self):
        code = 'AWS_KEY = "AKIACANARYTOKENEXAMPLE1"  # canary-token'
        findings = scan_source(code, "config.py")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("PARRY-SEC-CANARY", rule_ids)
        self.assertNotIn("PARRY-SEC-PY005", rule_ids)  # Real AWS leak rule
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest test_parry_canary_tokens.py -v`
Expected: FAIL (cannot import `is_canary_token`)

- [ ] **Step 3: Implement `is_canary_token` and `PARRY-SEC-CANARY` rule**

In `parry.py`, implement Canary token signature matching (`canarytokens.com`, `canarytokens.org`, `AKIACANARY`, `# canary-token`). Route matches to `PARRY-SEC-CANARY` with informational severity, preventing false alarm hard failures on intentional canary tripwires.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest test_parry_canary_tokens.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add parry.py test_parry_canary_tokens.py
git commit -m "feat(secrets): add canary token detection and whitelist classification"
```

---

### Task 6 (Tangential): Anti-Enumeration Sequential ID Detection (`PARRY-SEC-API002`)

**Files:**
- Modify: `D:\Parry\parry_evil_ai_benchmark_repo\parry.py`
- Test: `D:\Parry\parry_evil_ai_benchmark_repo\test_parry_anti_enumeration.py`

**Interfaces:**
- Consumes: `analyze_pattern_rules`
- Produces: `PARRY-SEC-API002` warning on auto-incrementing integer IDs in Prisma / SQL schemas.

- [ ] **Step 1: Write failing test**

```python
# test_parry_anti_enumeration.py
import unittest
from parry import scan_source

class TestAntiEnumeration(unittest.TestCase):
    def test_flag_autoincrement_integer_pk(self):
        prisma_schema = """
        model Invoice {
            id Int @id @default(autoincrement())
            amount Float
        }
        """
        findings = scan_source(prisma_schema, "schema.prisma")
        self.assertIn("PARRY-SEC-API002", [f.rule_id for f in findings])
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Implement `PARRY-SEC-API002` rule in `parry.py`**
- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit**

---

### Task 7 (Tangential): Sub-Second Agent CI Workflow Template

**Files:**
- Create: `D:\Parry\parry_evil_ai_benchmark_repo\.github\workflows\parry-fast-ci.yml`
- Test: Manual validation via `act` or schema validation script

**Interfaces:**
- Consumes: `parry.py check --agent`
- Produces: Reusable GitHub Action running in <1s for PR feedback.

- [ ] **Step 1: Create `.github/workflows/parry-fast-ci.yml`**
- [ ] **Step 2: Verify action syntax and invocation**
- [ ] **Step 3: Commit**

---

## Complete Verification & Regression Testing

- [ ] **Run complete test suite across all 41 existing + 7 new test files**

Run: `python -m unittest discover -p "test_*.py"`
Expected: All tests pass with 0 failures, 0 errors.

---

## Saved Deferred Tasks (Non-Parry — To Be Reminded Later)

*The following 6 tasks are non-Parry tasks saved for future execution once all Parry tasks are completed:*
1. **Infrastructure SecOps:** Deploy real Canary intrusion tokens on private cloud infrastructure / servers.
2. **Production Web Middleware:** Implement runtime consecutive 403/404 rate-limiting and sequential probing detection in production web servers.
3. **Bot Orchestration:** Set up an autonomous GitHub Issue-to-branch agent resolver workflow.
4. **Agent Prompt Tuning:** Configure personal agent prompt decision protocol for interactive question tools.
5. **Cross-Platform Evaluation:** Set up and evaluate Expo Exact for cross-platform apps (Web, Mac, iOS, Linux).
6. **Agent Runtime Tooling:** Set up and benchmark Cloudflare Kitesurf (Rust/WASM) for lightweight agent scraping and browser tasks.
