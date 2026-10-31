# Parry Verification Guardrail for AI Coding Agents (Gemini, Claude Code, OpenAI Codex, Cursor)

Whenever you write or modify Rust (`.rs`), Python (`.py`), TypeScript (`.ts`, `.tsx`), or JavaScript (`.js`, `.jsx`) files in this repository, you MUST run Parry before declaring the task complete:

```bash
python parry.py check .
```

## Rules for AI Agents
1. **Zero Hallucinated Imports**: Never import packages not present in `Cargo.lock`, `uv.lock`, `pyproject.toml`, or `package-lock.json`.
2. **Zero Truncation Comments**: Never leave `// ... rest of code` or `# ... existing code` placeholders.
3. **Self-Heal Before Responding**: If `python parry.py check .` or the `parry_verify_code` MCP tool returns any findings, fix every reported line and re-run `python parry.py check .` until it exits with `0`.
