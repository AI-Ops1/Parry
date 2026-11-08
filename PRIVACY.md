# Privacy Policy — Parry CLI & MCP Server

**Last updated:** November 8, 2026  
**Website:** [https://parry.scopeledger.net](https://parry.scopeledger.net)  
**Publisher:** Scopeledger ([shahbaz@scopeledger.net](mailto:shahbaz@scopeledger.net))

---

## 1. Zero-Telemetry Architecture

Parry operates under a strict **Zero-Telemetry, Local-First** guarantee:

* **Zero Code Uploads:** All static code analysis, AST parsing, lockfile inspection, and secret scans execute 100% locally on your machine or CI runner.
* **Zero Network Calls During Scans:** The `parry` CLI and `parry_verify_code` stdio MCP server make zero external network requests during code verification.
* **Zero LLM Token Transmission:** Parry uses deterministic, rule-based neuro-symbolic AST checks. Your code is never sent to external LLM providers or third-party training pipelines.

---

## 2. MCP Server Privacy & Permissions

The Parry MCP server (`parry.py mcp`) is configured with the following declarative safety hints:

* **`readOnlyHint: true`** — Parry only reads the code submitted to its verification handler. It does not alter your filesystem or execute modified files.
* **`destructiveHint: false`** — Parry never modifies, deletes, or truncates any files.
* **`idempotentHint: true`** — Scanning the same snippet repeatedly produces the exact same findings with no cumulative state.
* **`openWorldHint: false`** — Operates entirely in a closed sandbox with zero uncontrolled external internet calls.

---

## 3. Data Collection & Analytics

* **Source Code:** Neither the open-source CLI nor the stdio MCP server logs, stores, or transmits your source code.
* **Telemetry:** Parry does not collect user analytics, crash telemetry, device identifiers, or tracking cookies.

For complete disclosures regarding Scopeledger services, visit [https://parry.scopeledger.net/#privacy](https://parry.scopeledger.net/#privacy).
