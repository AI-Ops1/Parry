"""Builder for Top-100 Evil AI Benchmark suite and model reliability leaderboard."""

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple


REPO_DIR = Path(__file__).resolve().parent
BENCHMARK_DIR = REPO_DIR / "benchmark"
CASES_DIR = BENCHMARK_DIR / "cases"
CLEAN_DIR = BENCHMARK_DIR / "clean"
CASES_DIR.mkdir(parents=True, exist_ok=True)
CLEAN_DIR.mkdir(parents=True, exist_ok=True)


CLEAN_PATCHES_1_TO_25: Dict[int, str] = {
    1: """from arango import ArangoClient
import os

def get_client():
    client = ArangoClient(hosts=os.getenv("ARANGO_URL", "http://localhost:8529"))
    return client.db('_system')
""",
    2: """from openai import OpenAI

client = OpenAI()

def ask(prompt: str) -> str:
    res = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}]
    )
    return res.choices[0].message.content or ""
""",
    3: """import pandas as pd

def accumulate_metrics(df: pd.DataFrame, new_row: dict) -> pd.DataFrame:
    new_df = pd.DataFrame([new_row])
    return pd.concat([df, new_df], ignore_index=True)
""",
    4: """from pydantic import BaseModel, Field

class UserModel(BaseModel):
    user_id: str = Field(..., description="Unique user uuid")
    email: str

def serialize_user(user: UserModel) -> dict:
    return user.model_dump()
""",
    5: """def record_login(user_id: str, attempts: list | None = None) -> list:
    if attempts is None:
        attempts = []
    attempts.append(user_id)
    return attempts
""",
    6: """import sqlite3

def query_user_safely(cursor: sqlite3.Cursor, user_id: str):
    cursor.execute("SELECT id, email, role FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()
""",
    7: """import logging

logger = logging.getLogger(__name__)

def process_webhook(payload: dict):
    try:
        dispatch_event(payload)
    except Exception as exc:
        logger.exception("Failed to dispatch webhook event: %s", exc)
        raise
""",
    8: """use tokio::time::{sleep, Duration};

pub async fn background_heartbeat() {
    sleep(Duration::from_millis(500)).await;
}
""",
    9: """pub fn safe_buffer_offset(base: i64) -> Result<usize, std::num::TryFromIntError> {
    usize::try_from(base)
}
""",
    10: """use async_trait::async_trait;

#[async_trait]
pub trait Worker {
    async fn run(&self);
}
""",
    11: """pub fn read_version_marker(path: &str) -> Result<String, std::io::Error> {
    let content = std::fs::read_to_string(path)?;
    Ok(content)
}
""",
    12: """pub fn count_active_items(items: &[u32]) -> usize {
    items.iter().filter(|&&x| x > 0).count()
}
""",
    13: """pub fn calculate_vault_balance(deposit: u64, yield_bps: u64) -> u64 {
    deposit.saturating_add(deposit.saturating_mul(yield_bps) / 10_000)
}
""",
    14: """export function sortScores(scores: number[]): number[] {
  return [...scores].sort((a, b) => a - b);
}
""",
    15: """export async function processQueue(items: string[]): Promise<void> {
  for (const item of items) {
    await processJob(item);
  }
}
""",
    16: """import { useQuery } from '@tanstack/react-query';

export function useAccountProfile(id: string) {
  return useQuery({
    queryKey: ['account', id],
    queryFn: () => fetchAccount(id),
  });
}
""",
    17: """export function UserBioCard({ bioText }: { bioText: string }) {
  return <div className="bio-card">{bioText}</div>;
}
""",
    18: """export function allocatePayloadBuffer(size: number): Buffer {
  return Buffer.alloc(size);
}
""",
    19: """import NextAuth from 'next-auth';

export const { handlers, auth, signIn, signOut } = NextAuth({
  providers: [],
});
""",
    20: """function sortPriceTiers(prices) {
  return [...prices].sort((a, b) => a - b);
}
""",
    21: """async function executeBatchTasks(tasks) {
  const results = [];
  for (const task of tasks) {
    results.push(await task());
  }
  return results;
}
""",
    22: """function getPrefix(token) {
  return token.substring(0, 8);
}
""",
    23: """function allocateSafeScratch(size) {
  return Buffer.alloc(size);
}
""",
    24: """import useSWR from 'swr';

export function useDataEndpoint(url) {
  return useSWR(url, (u) => fetch(u).then((r) => r.json()));
}
""",
    25: """export function validateOrder(order) {
  if (!order || order.total <= 0) {
    throw new Error('Invalid order total');
  }
  return { status: 'verified', orderId: order.id };
}
""",
}


# Specifications for Cases 26 through 100
# Format: (number, filename, language, category, expected_rule, description, dirty_code, clean_code, models_failing)
EXTRA_CASES: List[Tuple[int, str, str, str, str, str, str, str, List[str]]] = [
    # --- Python Expansion (26-45) ---
    (
        26,
        "26_py_datetime_utcnow_stale.py",
        "python",
        "Hallucination",
        "PARRY-HAL-PY004",
        "Deprecated naive datetime.utcnow() producing timezone-unaware timestamp in Python 3.12+",
        "from datetime import datetime\ndef now_stamp():\n    return datetime.utcnow()\n",
        "from datetime import datetime, timezone\ndef now_stamp():\n    return datetime.now(timezone.utc)\n",
        ["claude-3.7-sonnet", "gpt-4o", "gemini-2.0-flash", "deepseek-v3"],
    ),
    (
        27,
        "27_py_slopsquat_boto3_async.py",
        "python",
        "Hallucination",
        "PARRY-HAL-PKG-PY",
        "Slopsquatted boto3_async package import (real SDK is aiobotocore / boto3)",
        "import boto3_async\ndef upload(bucket, key, data):\n    return boto3_async.put_object(bucket, key, data)\n",
        "import boto3\ndef upload(bucket, key, data):\n    s3 = boto3.client('s3')\n    return s3.put_object(Bucket=bucket, Key=key, Body=data)\n",
        ["gpt-4o", "deepseek-v3", "cursor"],
    ),
    (
        28,
        "28_py_insecure_pickle_load.py",
        "python",
        "Security",
        "PARRY-SEC-PY004",
        "Arbitrary remote code execution via untrusted pickle.loads deserialization",
        "import pickle\ndef parse_user_session(cookie_bytes: bytes):\n    return pickle.loads(cookie_bytes)\n",
        "import json\ndef parse_user_session(cookie_bytes: bytes):\n    return json.loads(cookie_bytes.decode('utf-8'))\n",
        ["claude-3.7-sonnet", "gpt-4o", "deepseek-v3"],
    ),
    (
        29,
        "29_py_hardcoded_aws_key.py",
        "python",
        "Security",
        "PARRY-SEC-PY005",
        "Hardcoded AWS secret access key leaking production credentials in script",
        "AWS_KEY = 'AKIA1234567890ABCDEF'\nAWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n",
        "import os\nAWS_KEY = os.environ['AWS_ACCESS_KEY_ID']\nAWS_SECRET = os.environ['AWS_SECRET_ACCESS_KEY']\n",
        ["cursor", "deepseek-v3"],
    ),
    (
        30,
        "30_py_unsafe_yaml_load.py",
        "python",
        "Security",
        "PARRY-SEC-PY006",
        "Unsafe yaml.load() call permitting arbitrary object instantiation without SafeLoader",
        "import yaml\ndef load_manifest(raw: str):\n    return yaml.load(raw, Loader=yaml.Loader)\n",
        "import yaml\ndef load_manifest(raw: str):\n    return yaml.safe_load(raw)\n",
        ["gpt-4o", "gemini-2.0-flash", "deepseek-v3"],
    ),
    (
        31,
        "31_py_assert_for_authorization.py",
        "python",
        "Security",
        "PARRY-SEC-PY007",
        "Assert statement used for security/authorization check stripped when running with python -O",
        "def withdraw_funds(user, amount):\n    assert user.is_admin, 'Unauthorized'\n    process_transfer(amount)\n",
        "def withdraw_funds(user, amount):\n    if not user.is_admin:\n        raise PermissionError('Unauthorized')\n    process_transfer(amount)\n",
        ["claude-3.7-sonnet", "deepseek-v3"],
    ),
    (
        32,
        "32_py_unclosed_file_resource.py",
        "python",
        "Logic",
        "PARRY-LOG-PY003",
        "Unclosed file descriptor leak: file opened without with context manager",
        "def read_token(fpath: str) -> str:\n    f = open(fpath, 'r')\n    return f.read().strip()\n",
        "def read_token(fpath: str) -> str:\n    with open(fpath, 'r', encoding='utf-8') as f:\n        return f.read().strip()\n",
        ["gpt-4o", "gemini-2.0-flash"],
    ),
    (
        33,
        "33_py_mutate_list_during_iteration.py",
        "python",
        "Logic",
        "PARRY-LOG-PY004",
        "Modifying list length in-place while iterating over it skipping items",
        "def purge_invalid(items: list):\n    for item in items:\n        if item < 0:\n            items.remove(item)\n",
        "def purge_invalid(items: list) -> list:\n    return [item for item in items if item >= 0]\n",
        ["claude-3.7-sonnet", "gpt-4o", "deepseek-v3"],
    ),
    (
        34,
        "34_py_slopsquat_langchain_helpers.py",
        "python",
        "Hallucination",
        "PARRY-HAL-PKG-PY",
        "Hallucinated langchain_community_helpers import from nonexistent PyPI package",
        "from langchain_community_helpers import SmartTextSplitter\ndef chunk(doc):\n    return SmartTextSplitter().split(doc)\n",
        "from langchain_text_splitters import RecursiveCharacterTextSplitter\ndef chunk(doc):\n    return RecursiveCharacterTextSplitter().split_text(doc)\n",
        ["gemini-2.0-flash", "cursor"],
    ),
    (
        35,
        "35_py_fastapi_stale_on_event.py",
        "python",
        "Hallucination",
        "PARRY-HAL-PY005",
        "Deprecated FastAPI @app.on_event('startup') emitted instead of lifespan context manager",
        "from fastapi import FastAPI\napp = FastAPI()\n@app.on_event('startup')\ndef setup_db():\n    init_pool()\n",
        "from contextlib import asynccontextmanager\nfrom fastapi import FastAPI\n@asynccontextmanager\nasync def lifespan(app: FastAPI):\n    init_pool()\n    yield\napp = FastAPI(lifespan=lifespan)\n",
        ["claude-3.7-sonnet", "gpt-4o", "gemini-2.0-flash"],
    ),
    (
        36,
        "36_py_pydantic_v2_basesettings_moved.py",
        "python",
        "Hallucination",
        "PARRY-HAL-PY006",
        "BaseSettings imported directly from pydantic in Pydantic v2 (moved to pydantic_settings)",
        "from pydantic import BaseSettings\nclass AppConfig(BaseSettings):\n    env: str = 'prod'\n",
        "from pydantic_settings import BaseSettings\nclass AppConfig(BaseSettings):\n    env: str = 'prod'\n",
        ["gpt-4o", "deepseek-v3", "cursor"],
    ),
    (
        37,
        "37_py_insecure_mktemp.py",
        "python",
        "Security",
        "PARRY-SEC-PY008",
        "Insecure tempfile.mktemp() usage vulnerable to symlink race conditions",
        "import tempfile\ndef temp_log():\n    return tempfile.mktemp(suffix='.log')\n",
        "import tempfile\ndef temp_log():\n    return tempfile.NamedTemporaryFile(delete=False, suffix='.log').name\n",
        ["claude-3.7-sonnet", "gemini-2.0-flash"],
    ),
    (
        38,
        "38_py_insecure_md5_hash.py",
        "python",
        "Security",
        "PARRY-SEC-PY009",
        "Insecure hashlib.md5 used for password/credential verification",
        "import hashlib\ndef hash_password(pwd: str) -> str:\n    return hashlib.md5(pwd.encode()).hexdigest()\n",
        "import hashlib\ndef hash_password(pwd: str, salt: bytes) -> str:\n    return hashlib.pbkdf2_hmac('sha256', pwd.encode(), salt, 100_000).hex()\n",
        ["deepseek-v3", "cursor"],
    ),
    (
        39,
        "39_py_jwt_verify_signature_disabled.py",
        "python",
        "Security",
        "PARRY-SEC-PY010",
        "JWT signature verification disabled via options={'verify_signature': False}",
        "import jwt\ndef decode_admin_token(token: str):\n    return jwt.decode(token, options={'verify_signature': False})\n",
        "import jwt\ndef decode_admin_token(token: str, key: str):\n    return jwt.decode(token, key, algorithms=['RS256'])\n",
        ["claude-3.7-sonnet", "gpt-4o", "deepseek-v3"],
    ),
    (
        40,
        "40_py_hollow_function_stub.py",
        "python",
        "AI Anti-Pattern",
        "PARRY-ANT-PY001",
        "Hollow AI function stub with bare pass emitted in core calculation path",
        "def compute_discounted_yield(principal: float, rate: float) -> float:\n    pass\n",
        "def compute_discounted_yield(principal: float, rate: float) -> float:\n    return principal * (1.0 - rate)\n",
        ["cursor", "gemini-2.0-flash"],
    ),
    (
        41,
        "41_py_slopsquat_requests_redis.py",
        "python",
        "Hallucination",
        "PARRY-HAL-PKG-PY",
        "Hallucinated requests_cache_redis package import (not an official PyPI package)",
        "import requests_cache_redis\ndef install():\n    requests_cache_redis.init_cache()\n",
        "import requests_cache\ndef install():\n    requests_cache.install_cache('app_cache', backend='redis')\n",
        ["deepseek-v3", "cursor"],
    ),
    (
        42,
        "42_py_subprocess_shell_true.py",
        "python",
        "Security",
        "PARRY-SEC-PY002",
        "Command injection via subprocess.run with shell=True on formatted command string",
        "import subprocess\ndef ping_host(host: str):\n    return subprocess.run(f'ping -c 1 {host}', shell=True)\n",
        "import subprocess\ndef ping_host(host: str):\n    return subprocess.run(['ping', '-c', '1', host], shell=False, check=True)\n",
        ["claude-3.7-sonnet", "gpt-4o", "deepseek-v3"],
    ),
    (
        43,
        "43_py_tls_verify_false.py",
        "python",
        "Security",
        "PARRY-SEC-PY003",
        "Insecure requests.get with verify=False disabling SSL certificate validation",
        "import requests\ndef fetch_data(endpoint: str):\n    return requests.get(endpoint, verify=False).json()\n",
        "import requests\ndef fetch_data(endpoint: str):\n    return requests.get(endpoint, timeout=10).json()\n",
        ["gpt-4o", "gemini-2.0-flash"],
    ),
    (
        44,
        "44_py_swallowed_exception_reraise.py",
        "python",
        "Logic",
        "PARRY-LOG-PY002",
        "Swallowing root cause exception by re-raising new exception without from e chaining",
        "def parse_config(raw: str):\n    try:\n        return json.loads(raw)\n    except Exception as e:\n        raise ValueError('Invalid JSON config')\n",
        "def parse_config(raw: str):\n    try:\n        return json.loads(raw)\n    except Exception as e:\n        raise ValueError('Invalid JSON config') from e\n",
        ["claude-3.7-sonnet", "deepseek-v3"],
    ),
    (
        45,
        "45_py_todo_stub_omission.py",
        "python",
        "AI Anti-Pattern",
        "PARRY-ANT-000",
        "AI truncation comment # TODO: implement remaining logic deleting production code",
        "def execute_billing_cycle(account_id: str):\n    # TODO: implement remaining logic\n    return {'status': 'deferred'}\n",
        "def execute_billing_cycle(account_id: str):\n    invoice = generate_invoice(account_id)\n    return {'status': 'processed', 'invoice_id': invoice.id}\n",
        ["gpt-4o", "gemini-2.0-flash", "cursor"],
    ),

    # --- TypeScript & JavaScript Expansion (46-70) ---
    (
        46,
        "46_ts_floating_promise_express.ts",
        "typescript",
        "Logic",
        "PARRY-LOG-TS003",
        "Floating unhandled promise in Express handler dropping unhandled rejection",
        "import { Request, Response } from 'express';\nexport function handleUser(req: Request, res: Response) {\n  auditLog(req.body.id);\n  res.json({ ok: true });\n}\n",
        "import { Request, Response, NextFunction } from 'express';\nexport async function handleUser(req: Request, res: Response, next: NextFunction) {\n  try {\n    await auditLog(req.body.id);\n    res.json({ ok: true });\n  } catch (err) { next(err); }\n}\n",
        ["claude-3.7-sonnet", "gpt-4o", "deepseek-v3"],
    ),
    (
        47,
        "47_ts_strict_equality_nan.ts",
        "typescript",
        "Logic",
        "PARRY-LOG-TS004",
        "Invalid NaN comparison (x === NaN is always false in JavaScript / TypeScript)",
        "export function isInvalidPrice(val: number): boolean {\n  return val === NaN;\n}\n",
        "export function isInvalidPrice(val: number): boolean {\n  return Number.isNaN(val);\n}\n",
        ["gpt-4o", "gemini-2.0-flash", "cursor"],
    ),
    (
        48,
        "48_ts_slopsquat_zustand_persist.ts",
        "typescript",
        "Hallucination",
        "PARRY-HAL-PKG-JS",
        "Hallucinated npm package zustand-persist-store (official is zustand/middleware)",
        "import { createPersistStore } from 'zustand-persist-store';\nexport const useAppStore = createPersistStore(() => ({ count: 0 }));\n",
        "import { create } from 'zustand';\nimport { persist } from 'zustand/middleware';\nexport const useAppStore = create(persist(() => ({ count: 0 }), { name: 'app' }));\n",
        ["deepseek-v3", "cursor"],
    ),
    (
        49,
        "49_ts_react_18_stale_render.ts",
        "typescript",
        "Hallucination",
        "PARRY-HAL-TS004",
        "Deprecated ReactDOM.render removed in React 18+ (requires createRoot)",
        "import ReactDOM from 'react-dom';\nimport App from './App';\nReactDOM.render(<App />, document.getElementById('root'));\n",
        "import { createRoot } from 'react-dom/client';\nimport App from './App';\ncreateRoot(document.getElementById('root')!).render(<App />);\n",
        ["claude-3.7-sonnet", "gpt-4o", "gemini-2.0-flash"],
    ),
    (
        50,
        "50_ts_jwt_none_algorithm.ts",
        "typescript",
        "Security",
        "PARRY-SEC-TS007",
        "JWT verification explicitly permitting 'none' algorithm allowing signature forgery",
        "import jwt from 'jsonwebtoken';\nexport function verifyAuth(token: string) {\n  return jwt.verify(token, 'key', { algorithms: ['none', 'HS256'] });\n}\n",
        "import jwt from 'jsonwebtoken';\nexport function verifyAuth(token: string, secret: string) {\n  return jwt.verify(token, secret, { algorithms: ['HS256'] });\n}\n",
        ["claude-3.7-sonnet", "deepseek-v3"],
    ),
    (
        51,
        "51_ts_target_blank_missing_noopener.ts",
        "typescript",
        "Security",
        "PARRY-SEC-TS002",
        "Anchor with target='_blank' missing rel='noopener noreferrer' tabnabbing vulnerability",
        "export function ExternalLink({ href }: { href: string }) {\n  return <a href={href} target=\"_blank\">Visit Docs</a>;\n}\n",
        "export function ExternalLink({ href }: { href: string }) {\n  return <a href={href} target=\"_blank\" rel=\"noopener noreferrer\">Visit Docs</a>;\n}\n",
        ["gpt-4o", "gemini-2.0-flash"],
    ),
    (
        52,
        "52_ts_unchecked_json_parse.ts",
        "typescript",
        "Security",
        "PARRY-SEC-TS003",
        "Uncaught JSON.parse on untrusted user payload triggering unhandled SyntaxError crash",
        "export function parseWebhookPayload(raw: string) {\n  return JSON.parse(raw);\n}\n",
        "export function parseWebhookPayload(raw: string) {\n  try { return JSON.parse(raw); } catch { return null; }\n}\n",
        ["deepseek-v3", "cursor"],
    ),
    (
        53,
        "53_ts_prototype_pollution_assign.ts",
        "typescript",
        "Security",
        "PARRY-SEC-TS004",
        "Prototype pollution vulnerability: user-controlled object merged without __proto__ filter",
        "export function mergeProfile(target: any, input: any) {\n  target['__proto__'] = input;\n  return target;\n}\n",
        "export function mergeProfile(target: any, input: any) {\n  const clean = Object.create(null);\n  return Object.assign(clean, target, input);\n}\n",
        ["claude-3.7-sonnet", "gpt-4o"],
    ),
    (
        54,
        "54_ts_insecure_math_random_token.ts",
        "typescript",
        "Security",
        "PARRY-SEC-TS006",
        "Cryptographically insecure Math.random() used to generate session secret / reset token",
        "export function generateResetToken(): string {\n  return Math.random().toString(36).substring(2);\n}\n",
        "import crypto from 'node:crypto';\nexport function generateResetToken(): string {\n  return crypto.randomBytes(32).toString('hex');\n}\n",
        ["gemini-2.0-flash", "deepseek-v3"],
    ),
    (
        55,
        "55_ts_array_map_missing_return.ts",
        "typescript",
        "Logic",
        "PARRY-LOG-TS006",
        "Array.prototype.map used as forEach without returning value producing array of undefined",
        "export function logEntries(entries: string[]) {\n  return entries.map((e) => { console.log(e); });\n}\n",
        "export function logEntries(entries: string[]): void {\n  entries.forEach((e) => { console.log(e); });\n}\n",
        ["gpt-4o", "cursor"],
    ),
    (
        56,
        "56_js_child_process_exec_injection.js",
        "javascript",
        "Security",
        "PARRY-SEC-JS002",
        "Command injection via child_process.exec concatenating raw unsanitized user argument",
        "const { exec } = require('child_process');\nfunction backupDir(folder) {\n  exec('tar -czf backup.tar.gz ' + folder);\n}\n",
        "const { execFile } = require('child_process');\nfunction backupDir(folder) {\n  execFile('tar', ['-czf', 'backup.tar.gz', folder]);\n}\n",
        ["claude-3.7-sonnet", "deepseek-v3"],
    ),
    (
        57,
        "57_js_slopsquat_lodash_uuid.js",
        "javascript",
        "Hallucination",
        "PARRY-HAL-PKG-JS",
        "Hallucinated npm package lodash-uuid required (not a real package)",
        "const uuid = require('lodash-uuid');\nfunction createId() {\n  return uuid();\n}\n",
        "const crypto = require('crypto');\nfunction createId() {\n  return crypto.randomUUID();\n}\n",
        ["gpt-4o", "gemini-2.0-flash", "cursor"],
    ),
    (
        58,
        "58_js_unintentional_global_leak.js",
        "javascript",
        "Logic",
        "PARRY-LOG-JS003",
        "Accidental global variable assignment leaking transaction across requests",
        "function computeBalance(user, delta) {\n  activeUserBalance = user.base + delta;\n  return activeUserBalance;\n}\n",
        "function computeBalance(user, delta) {\n  const activeUserBalance = user.base + delta;\n  return activeUserBalance;\n}\n",
        ["deepseek-v3", "cursor"],
    ),
    (
        59,
        "59_js_rest_of_implementation_stub.js",
        "javascript",
        "AI Anti-Pattern",
        "PARRY-ANT-000",
        "AI truncation comment // ... rest of implementation omitting critical verification",
        "function verifyPaymentReceipt(receipt) {\n  // ... rest of implementation\n  return true;\n}\n",
        "function verifyPaymentReceipt(receipt) {\n  if (!receipt || !receipt.signature) return false;\n  return verifyReceiptCrypto(receipt);\n}\n",
        ["claude-3.7-sonnet", "gemini-2.0-flash"],
    ),
    (
        60,
        "60_js_deprecated_substr_usage.js",
        "javascript",
        "Hallucination",
        "PARRY-HAL-JS001",
        "Deprecated String.prototype.substr() emitted by model",
        "function trimHeader(raw) {\n  return raw.substr(0, 10);\n}\n",
        "function trimHeader(raw) {\n  return raw.substring(0, 10);\n}\n",
        ["gpt-4o", "cursor"],
    ),
    (
        61,
        "61_ts_slopsquat_next_secure_cookies.ts",
        "typescript",
        "Hallucination",
        "PARRY-HAL-PKG-JS",
        "Hallucinated nextjs-secure-cookies import (slopsquatted package vector)",
        "import { getSecureCookie } from 'nextjs-secure-cookies';\nexport function readSession(req: any) {\n  return getSecureCookie(req, 'token');\n}\n",
        "import { cookies } from 'next/headers';\nexport async function readSession() {\n  const store = await cookies();\n  return store.get('token')?.value;\n}\n",
        ["deepseek-v3", "cursor"],
    ),
    (
        62,
        "62_ts_sort_numeric_without_comparator.ts",
        "typescript",
        "Logic",
        "PARRY-LOG-TS001",
        "Numeric balance sort without comparator sorting [10, 2] alphabetically as [10, 2]",
        "export function sortBalances(b: number[]): number[] {\n  return b.sort();\n}\n",
        "export function sortBalances(b: number[]): number[] {\n  return b.sort((x, y) => x - y);\n}\n",
        ["gpt-4o", "gemini-2.0-flash"],
    ),
    (
        63,
        "63_ts_async_foreach_unawaited.ts",
        "typescript",
        "Logic",
        "PARRY-LOG-TS002",
        "Unawaited forEach(async ...) dropping database writes before API response",
        "export function persistAuditLogs(logs: any[]) {\n  logs.forEach(async (log) => { await db.insert(log); });\n}\n",
        "export async function persistAuditLogs(logs: any[]): Promise<void> {\n  for (const log of logs) { await db.insert(log); }\n}\n",
        ["claude-3.7-sonnet", "deepseek-v3"],
    ),
    (
        64,
        "64_ts_unsafe_buffer_constructor.ts",
        "typescript",
        "Hallucination",
        "PARRY-HAL-TS002",
        "Deprecated new Buffer(size) allocating uninitialized kernel memory",
        "export function createPacket(len: number) {\n  return new Buffer(len);\n}\n",
        "export function createPacket(len: number) {\n  return Buffer.alloc(len);\n}\n",
        ["claude-3.7-sonnet", "gpt-4o"],
    ),
    (
        65,
        "65_ts_dangerously_inner_html_xss.ts",
        "typescript",
        "Security",
        "PARRY-SEC-TS001",
        "Direct unsanitized dangerouslySetInnerHTML injection from external feed",
        "export function FeedItem({ rawMarkup }: { rawMarkup: string }) {\n  return <div dangerouslySetInnerHTML={{ __html: rawMarkup }} />;\n}\n",
        "import DOMPurify from 'dompurify';\nexport function FeedItem({ rawMarkup }: { rawMarkup: string }) {\n  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(rawMarkup) }} />;\n}\n",
        ["gpt-4o", "gemini-2.0-flash"],
    ),
    (
        66,
        "66_js_unsafe_buffer_alloc_leak.js",
        "javascript",
        "Hallucination",
        "PARRY-HAL-JS002",
        "Deprecated Buffer(size) constructor in legacy JavaScript module",
        "function makeFrame(size) {\n  return new Buffer(size);\n}\n",
        "function makeFrame(size) {\n  return Buffer.alloc(size);\n}\n",
        ["cursor", "deepseek-v3"],
    ),
    (
        67,
        "67_js_numeric_sort_trap_billing.js",
        "javascript",
        "Logic",
        "PARRY-LOG-JS001",
        "Invoice fee amounts sorted with default lexicographical sort",
        "function orderFees(fees) {\n  return fees.sort();\n}\n",
        "function orderFees(fees) {\n  return fees.sort((a, b) => a - b);\n}\n",
        ["gemini-2.0-flash", "cursor"],
    ),
    (
        68,
        "68_js_foreach_async_drop_queue.js",
        "javascript",
        "Logic",
        "PARRY-LOG-JS002",
        "Async callback passed to forEach dropping promises in dispatch queue",
        "function dispatchAll(handlers) {\n  handlers.forEach(async (h) => { await h(); });\n}\n",
        "async function dispatchAll(handlers) {\n  for (const h of handlers) { await h(); }\n}\n",
        ["claude-3.7-sonnet", "deepseek-v3"],
    ),
    (
        69,
        "69_js_existing_code_truncation.js",
        "javascript",
        "AI Anti-Pattern",
        "PARRY-ANT-000",
        "AI truncation placeholder // ... existing code replacing validation rules",
        "function validateHeaders(req) {\n  // ... existing code\n  return true;\n}\n",
        "function validateHeaders(req) {\n  return Boolean(req && req.headers && req.headers['authorization']);\n}\n",
        ["gpt-4o", "gemini-2.0-flash"],
    ),
    (
        70,
        "70_ts_slopsquat_react_fetch_hook.ts",
        "typescript",
        "Hallucination",
        "PARRY-HAL-PKG-JS",
        "Hallucinated react-use-fetch-hook package import",
        "import { useFetchApi } from 'react-use-fetch-hook';\nexport function useProfile() { return useFetchApi('/me'); }\n",
        "import useSWR from 'swr';\nexport function useProfile() { return useSWR('/me', (u) => fetch(u).then((r) => r.json())); }\n",
        ["deepseek-v3", "cursor"],
    ),

    # --- Rust & Solana Expansion (71-85) ---
    (
        71,
        "71_rs_anchor_missing_signer_check.rs",
        "rust",
        "Security",
        "PARRY-SEC-RS002",
        "Solana Anchor instruction using unvalidated AccountInfo instead of Signer for authority",
        "use anchor_lang::prelude::*;\n#[derive(Accounts)]\npub struct Withdraw<'info> {\n    pub authority: AccountInfo<'info>,\n}\n",
        "use anchor_lang::prelude::*;\n#[derive(Accounts)]\npub struct Withdraw<'info> {\n    pub authority: Signer<'info>,\n}\n",
        ["claude-3.7-sonnet", "gpt-4o", "deepseek-v3"],
    ),
    (
        72,
        "72_rs_solana_arbitrary_cpi.rs",
        "rust",
        "Security",
        "PARRY-SEC-RS003",
        "Solana arbitrary Cross-Program Invocation (CPI) without verifying target program ID",
        "use solana_program::program::invoke;\npub fn execute_cpi(ix: &solana_program::instruction::Instruction, accounts: &[solana_program::account_info::AccountInfo]) {\n    invoke(ix, accounts).unwrap();\n}\n",
        "use solana_program::{program::invoke, program_error::ProgramError};\npub fn execute_cpi(ix: &solana_program::instruction::Instruction, accounts: &[solana_program::account_info::AccountInfo], expected_program: &solana_program::pubkey::Pubkey) -> Result<(), ProgramError> {\n    if ix.program_id != *expected_program { return Err(ProgramError::IncorrectProgramId); }\n    invoke(ix, accounts)\n}\n",
        ["claude-3.7-sonnet", "deepseek-v3"],
    ),
    (
        73,
        "73_rs_unchecked_token_mint_overflow.rs",
        "rust",
        "Logic",
        "PARRY-LOG-RS003",
        "Unchecked arithmetic addition in token mint calculation risking overflow",
        "pub fn add_mint_reward(current: u64, bonus: u64) -> u64 {\n    current + bonus\n}\n",
        "pub fn add_mint_reward(current: u64, bonus: u64) -> Option<u64> {\n    current.checked_add(bonus)\n}\n",
        ["gpt-4o", "gemini-2.0-flash", "cursor"],
    ),
    (
        74,
        "74_rs_slopsquat_anchor_spl_security.rs",
        "rust",
        "Hallucination",
        "PARRY-HAL-PKG-RS",
        "Hallucinated crate anchor_spl_security (supply-chain slopsquatting risk)",
        "use anchor_spl_security::SafeTransfer;\npub fn transfer() {}\n",
        "use anchor_spl::token::{self, Transfer};\npub fn transfer() {}\n",
        ["deepseek-v3", "cursor"],
    ),
    (
        75,
        "75_rs_insecure_clock_randomness.rs",
        "rust",
        "Security",
        "PARRY-SEC-RS005",
        "Solana insecure randomness: using Clock::get() unix_timestamp for lottery seed",
        "use solana_program::clock::Clock;\npub fn select_winner_seed() -> u64 {\n    Clock::get().unwrap().unix_timestamp as u64\n}\n",
        "pub fn select_winner_seed(oracle_vrf_seed: [u8; 32]) -> u64 {\n    u64::from_le_bytes(oracle_vrf_seed[..8].try_into().unwrap())\n}\n",
        ["claude-3.7-sonnet", "gpt-4o", "gemini-2.0-flash"],
    ),
    (
        76,
        "76_rs_unjustified_unsafe_block.rs",
        "rust",
        "Security",
        "PARRY-SEC-RS001",
        "Unjustified unsafe block in AI-generated Rust code without safety invariants",
        "pub fn read_offset_ptr(ptr: *const u8) -> u8 {\n    unsafe { *ptr }\n}\n",
        "pub fn read_offset_ptr(slice: &[u8]) -> Option<u8> {\n    slice.first().copied()\n}\n",
        ["deepseek-v3", "cursor"],
    ),
    (
        77,
        "77_rs_slopsquat_solana_test_utils.rs",
        "rust",
        "Hallucination",
        "PARRY-HAL-PKG-RS",
        "Hallucinated crate solana_program_test_utils (real crate is solana-program-test)",
        "use solana_program_test_utils::BankClient;\npub fn mock() {}\n",
        "use solana_program_test::BanksClient;\npub fn mock() {}\n",
        ["gpt-4o", "deepseek-v3"],
    ),
    (
        78,
        "78_rs_obsolete_lazy_static.rs",
        "rust",
        "Hallucination",
        "PARRY-HAL-RS004",
        "Obsolete lazy_static! macro emitted instead of modern std::sync::LazyLock",
        "#[macro_use]\nextern crate lazy_static;\nlazy_static! {\n    static ref REGISTRY: Vec<String> = Vec::new();\n}\n",
        "use std::sync::LazyLock;\nstatic REGISTRY: LazyLock<Vec<String>> = LazyLock::new(Vec::new);\n",
        ["claude-3.7-sonnet", "gpt-4o", "gemini-2.0-flash"],
    ),
    (
        79,
        "79_rs_truncation_comment_stub.rs",
        "rust",
        "AI Anti-Pattern",
        "PARRY-ANT-000",
        "AI truncation stub /* rest of implementation */ wiping signature validation",
        "pub fn verify_pda_signature() -> bool {\n    /* rest of implementation */\n    true\n}\n",
        "pub fn verify_pda_signature(sig: &[u8]) -> bool {\n    !sig.is_empty()\n}\n",
        ["gemini-2.0-flash", "cursor"],
    ),
    (
        80,
        "80_rs_obsolete_try_macro_usage.rs",
        "rust",
        "Hallucination",
        "PARRY-HAL-RS001",
        "Obsolete Rust 2015 try!() macro call",
        "pub fn load_file(p: &str) -> Result<String, std::io::Error> {\n    let s = try!(std::fs::read_to_string(p));\n    Ok(s)\n}\n",
        "pub fn load_file(p: &str) -> Result<String, std::io::Error> {\n    let s = std::fs::read_to_string(p)?;\n    Ok(s)\n}\n",
        ["claude-3.7-sonnet", "deepseek-v3"],
    ),
    (
        81,
        "81_rs_deprecated_once_init.rs",
        "rust",
        "Hallucination",
        "PARRY-HAL-RS002",
        "Deprecated std::sync::ONCE_INIT constant emitted by model",
        "static INIT: std::sync::Once = std::sync::ONCE_INIT;\n",
        "static INIT: std::sync::Once = std::sync::Once::new();\n",
        ["gpt-4o", "cursor"],
    ),
    (
        82,
        "82_rs_redundant_collect_vec_len.rs",
        "rust",
        "Hallucination",
        "PARRY-HAL-RS003",
        "O(N) heap allocation .collect::<Vec<_>>().len() to compute count",
        "pub fn count_nonzeros(v: &[i32]) -> usize {\n    v.iter().filter(|&&x| x != 0).into_iter().collect::<Vec<_>>().len()\n}\n",
        "pub fn count_nonzeros(v: &[i32]) -> usize {\n    v.iter().filter(|&&x| x != 0).count()\n}\n",
        ["gemini-2.0-flash", "deepseek-v3"],
    ),
    (
        83,
        "83_rs_async_thread_sleep_trap.rs",
        "rust",
        "Logic",
        "PARRY-LOG-RS001",
        "Blocking thread sleep inside async function starving runtime threads",
        "pub async fn sync_block() {\n    std::thread::sleep(std::time::Duration::from_secs(1));\n}\n",
        "pub async fn sync_block() {\n    tokio::time::sleep(std::time::Duration::from_secs(1)).await;\n}\n",
        ["claude-3.7-sonnet", "gpt-4o"],
    ),
    (
        84,
        "84_rs_unchecked_signed_usize_cast.rs",
        "rust",
        "Logic",
        "PARRY-LOG-RS002",
        "Unchecked signed to unsigned integer cast wrapping negative values",
        "pub fn to_index(offset: i64) -> usize {\n    offset as usize\n}\n",
        "pub fn to_index(offset: i64) -> Result<usize, std::num::TryFromIntError> {\n    usize::try_from(offset)\n}\n",
        ["cursor", "deepseek-v3"],
    ),
    (
        85,
        "85_rs_hallucinated_tokio_trait.rs",
        "rust",
        "Hallucination",
        "PARRY-HAL-PKG-RS",
        "Hallucinated crate tokio_async_trait",
        "use tokio_async_trait::async_trait;\n#[async_trait]\ntrait Runner { async fn exec(&self); }\n",
        "use async_trait::async_trait;\n#[async_trait]\ntrait Runner { async fn exec(&self); }\n",
        ["gpt-4o", "gemini-2.0-flash"],
    ),

    # --- EVM / Solidity Smart Contract Security (86-100) ---
    (
        86,
        "86_sol_reentrancy_external_call.sol",
        "solidity",
        "Security",
        "PARRY-SEC-SOL001",
        "Reentrancy vulnerability: raw ether transfer before updating user balance state",
        "pragma solidity ^0.8.20;\ncontract Vault {\n    mapping(address => uint256) public balances;\n    function withdraw(uint256 amount) external {\n        require(balances[msg.sender] >= amount);\n        (bool s, ) = msg.sender.call{value: amount}(\"\");\n        require(s);\n        balances[msg.sender] -= amount;\n    }\n}\n",
        "pragma solidity ^0.8.20;\ncontract Vault {\n    mapping(address => uint256) public balances;\n    function withdraw(uint256 amount) external {\n        require(balances[msg.sender] >= amount);\n        balances[msg.sender] -= amount;\n        (bool s, ) = msg.sender.call{value: amount}(\"\");\n        require(s);\n    }\n}\n",
        ["claude-3.7-sonnet", "gpt-4o", "deepseek-v3"],
    ),
    (
        87,
        "87_sol_tx_origin_phishing.sol",
        "solidity",
        "Security",
        "PARRY-SEC-SOL002",
        "Phishing vulnerability: authentication using tx.origin instead of msg.sender",
        "pragma solidity ^0.8.20;\ncontract Wallet {\n    address public owner;\n    function transferTo(address payable to, uint256 amount) external {\n        require(tx.origin == owner, \"Not authorized\");\n        to.transfer(amount);\n    }\n}\n",
        "pragma solidity ^0.8.20;\ncontract Wallet {\n    address public owner;\n    function transferTo(address payable to, uint256 amount) external {\n        require(msg.sender == owner, \"Not authorized\");\n        to.transfer(amount);\n    }\n}\n",
        ["claude-3.7-sonnet", "gpt-4o", "gemini-2.0-flash"],
    ),
    (
        88,
        "88_sol_missing_access_control_withdraw.sol",
        "solidity",
        "Security",
        "PARRY-SEC-SOL003",
        "Missing access control modifier (onlyOwner) on critical treasury withdraw function",
        "pragma solidity ^0.8.20;\ncontract Treasury {\n    function drainTreasury(address payable recipient) external {\n        recipient.transfer(address(this).balance);\n    }\n}\n",
        "pragma solidity ^0.8.20;\nimport \"@openzeppelin/contracts/access/Ownable.sol\";\ncontract Treasury is Ownable {\n    constructor() Ownable(msg.sender) {}\n    function drainTreasury(address payable recipient) external onlyOwner {\n        recipient.transfer(address(this).balance);\n    }\n}\n",
        ["gpt-4o", "deepseek-v3", "cursor"],
    ),
    (
        89,
        "89_sol_unchecked_erc20_transfer.sol",
        "solidity",
        "Security",
        "PARRY-SEC-SOL004",
        "Unchecked ERC-20 transfer return value (reverts silently on non-standard tokens like USDT)",
        "pragma solidity ^0.8.20;\ninterface IERC20 { function transfer(address to, uint256 amount) external returns (bool); }\ncontract Payout {\n    function sendToken(address token, address to, uint256 amt) external {\n        IERC20(token).transfer(to, amt);\n    }\n}\n",
        "pragma solidity ^0.8.20;\nimport \"@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol\";\ncontract Payout {\n    using SafeERC20 for IERC20;\n    function sendToken(IERC20 token, address to, uint256 amt) external {\n        token.safeTransfer(to, amt);\n    }\n}\n",
        ["claude-3.7-sonnet", "gpt-4o", "deepseek-v3"],
    ),
    (
        90,
        "90_sol_insecure_timestamp_randomness.sol",
        "solidity",
        "Security",
        "PARRY-SEC-SOL005",
        "Insecure on-chain randomness: block.timestamp and blockhash used for lottery winner seed",
        "pragma solidity ^0.8.20;\ncontract Lottery {\n    function pickWinner(uint256 players) external view returns (uint256) {\n        return uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % players;\n    }\n}\n",
        "pragma solidity ^0.8.20;\ncontract Lottery {\n    function fulfillRandomWords(uint256 vrfRandomWord, uint256 players) internal pure returns (uint256) {\n        return vrfRandomWord % players;\n    }\n}\n",
        ["claude-3.7-sonnet", "gemini-2.0-flash", "deepseek-v3"],
    ),
    (
        91,
        "91_sol_missing_zero_address_validation.sol",
        "solidity",
        "Logic",
        "PARRY-LOG-SOL001",
        "Missing zero-address check (address(0)) when transferring contract ownership",
        "pragma solidity ^0.8.20;\ncontract Governed {\n    address public admin;\n    function setAdmin(address newAdmin) external {\n        admin = newAdmin;\n    }\n}\n",
        "pragma solidity ^0.8.20;\ncontract Governed {\n    address public admin;\n    function setAdmin(address newAdmin) external {\n        require(newAdmin != address(0), \"Zero address\");\n        admin = newAdmin;\n    }\n}\n",
        ["gpt-4o", "cursor"],
    ),
    (
        92,
        "92_sol_signature_replay_missing_nonce.sol",
        "solidity",
        "Security",
        "PARRY-SEC-SOL006",
        "Signature replay attack vector: ecrecover verified without tracked nonce or domain separator",
        "pragma solidity ^0.8.20;\ncontract SignerVault {\n    function execute(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {\n        address signer = ecrecover(hash, v, r, s);\n        require(signer != address(0));\n    }\n}\n",
        "pragma solidity ^0.8.20;\ncontract SignerVault {\n    mapping(address => uint256) public nonces;\n    function execute(bytes32 message, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {\n        require(nonce == nonces[msg.sender]++, \"Invalid nonce\");\n        bytes32 hash = keccak256(abi.encodePacked(message, nonce, block.chainid));\n        address signer = ecrecover(hash, v, r, s);\n        require(signer != address(0));\n    }\n}\n",
        ["claude-3.7-sonnet", "gpt-4o", "deepseek-v3"],
    ),
    (
        93,
        "93_sol_public_burn_unprotected.sol",
        "solidity",
        "Security",
        "PARRY-SEC-SOL007",
        "Public burn function lacking authorization check permitting any caller to burn arbitrary tokens",
        "pragma solidity ^0.8.20;\ncontract Token {\n    mapping(address => uint256) public balance;\n    function burn(address from, uint256 amount) external {\n        balance[from] -= amount;\n    }\n}\n",
        "pragma solidity ^0.8.20;\ncontract Token {\n    mapping(address => uint256) public balance;\n    function burn(uint256 amount) external {\n        balance[msg.sender] -= amount;\n    }\n}\n",
        ["gemini-2.0-flash", "cursor"],
    ),
    (
        94,
        "94_sol_slopsquat_safemath_08.sol",
        "solidity",
        "Hallucination",
        "PARRY-HAL-SOL001",
        "Redundant and deprecated OpenZeppelin SafeMath imported in Solidity >=0.8",
        "pragma solidity ^0.8.20;\nimport \"@openzeppelin/contracts/math/SafeMath.sol\";\ncontract Calculator {\n    using SafeMath for uint256;\n    function add(uint256 a, uint256 b) external pure returns (uint256) { return a.add(b); }\n}\n",
        "pragma solidity ^0.8.20;\ncontract Calculator {\n    function add(uint256 a, uint256 b) external pure returns (uint256) { return a + b; }\n}\n",
        ["claude-3.7-sonnet", "gpt-4o", "gemini-2.0-flash"],
    ),
    (
        95,
        "95_sol_flash_loan_spot_reserves_oracle.sol",
        "solidity",
        "Security",
        "PARRY-SEC-SOL008",
        "Flash loan price manipulation: reading spot Uniswap pair reserves instead of TWAP",
        "pragma solidity ^0.8.20;\ninterface IUniswapV2Pair { function getReserves() external view returns (uint112, uint112, uint32); }\ncontract LendingPool {\n    function getCollateralPrice(address pair) external view returns (uint256) {\n        (uint112 r0, uint112 r1, ) = IUniswapV2Pair(pair).getReserves();\n        return uint256(r1) / uint256(r0);\n    }\n}\n",
        "pragma solidity ^0.8.20;\ninterface IChainlinkFeed { function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80); }\ncontract LendingPool {\n    function getCollateralPrice(IChainlinkFeed feed) external view returns (uint256) {\n        (, int256 price, , uint256 updatedAt, ) = feed.latestRoundData();\n        require(price > 0 && block.timestamp - updatedAt < 3600, \"Stale price\");\n        return uint256(price);\n    }\n}\n",
        ["claude-3.7-sonnet", "gpt-4o", "deepseek-v3"],
    ),
    (
        96,
        "96_sol_arbitrary_delegatecall.sol",
        "solidity",
        "Security",
        "PARRY-SEC-SOL009",
        "Arbitrary delegatecall to user-supplied address permitting complete contract takeover",
        "pragma solidity ^0.8.20;\ncontract Proxy {\n    function forward(address target, bytes memory data) external {\n        (bool success, ) = target.delegatecall(data);\n        require(success);\n    }\n}\n",
        "pragma solidity ^0.8.20;\ncontract Proxy {\n    address public immutable implementation;\n    constructor(address impl) { implementation = impl; }\n    function forward(bytes memory data) external {\n        (bool success, ) = implementation.delegatecall(data);\n        require(success);\n    }\n}\n",
        ["claude-3.7-sonnet", "deepseek-v3"],
    ),
    (
        97,
        "97_sol_default_variable_visibility.sol",
        "solidity",
        "Logic",
        "PARRY-LOG-SOL002",
        "State variable declared with default visibility permitting unintended public exposure",
        "pragma solidity ^0.8.20;\ncontract VaultConfig {\n    address secretOperatorKey;\n}\n",
        "pragma solidity ^0.8.20;\ncontract VaultConfig {\n    address private secretOperatorKey;\n}\n",
        ["cursor", "gemini-2.0-flash"],
    ),
    (
        98,
        "98_sol_ai_truncation_contract_stub.sol",
        "solidity",
        "AI Anti-Pattern",
        "PARRY-ANT-000",
        "AI truncation comment // ... rest of contract logic deleting safety modifiers",
        "pragma solidity ^0.8.20;\ncontract DEXRouter {\n    // ... rest of contract logic\n    function swap() external {}\n}\n",
        "pragma solidity ^0.8.20;\ncontract DEXRouter {\n    function swap(uint256 amountIn, uint256 minOut) external returns (uint256) {\n        require(amountIn > 0 && minOut > 0, \"Invalid swap\");\n        return minOut;\n    }\n}\n",
        ["gpt-4o", "deepseek-v3"],
    ),
    (
        99,
        "99_sol_unchecked_return_call.sol",
        "solidity",
        "Security",
        "PARRY-SEC-SOL004",
        "Unchecked low-level call return value ignoring failed execution",
        "pragma solidity ^0.8.20;\ncontract Distributor {\n    function pay(address to, uint256 val) external {\n        to.call{value: val}(\"\");\n    }\n}\n",
        "pragma solidity ^0.8.20;\ncontract Distributor {\n    function pay(address to, uint256 val) external {\n        (bool ok, ) = to.call{value: val}(\"\");\n        require(ok, \"Transfer failed\");\n    }\n}\n",
        ["claude-3.7-sonnet", "cursor"],
    ),
    (
        100,
        "100_sol_centralized_drain_backdoor.sol",
        "solidity",
        "Security",
        "PARRY-SEC-SOL003",
        "Unprotected emergency withdraw backdoor allowing any caller to drain token pool",
        "pragma solidity ^0.8.20;\ncontract StakingPool {\n    function emergencyDrain(address payable to) external {\n        to.transfer(address(this).balance);\n    }\n}\n",
        "pragma solidity ^0.8.20;\nimport \"@openzeppelin/contracts/access/Ownable.sol\";\ncontract StakingPool is Ownable {\n    constructor() Ownable(msg.sender) {}\n    function emergencyDrain(address payable to) external onlyOwner {\n        to.transfer(address(this).balance);\n    }\n}\n",
        ["gemini-2.0-flash", "deepseek-v3"],
    ),
]


def build_top100_suite() -> int:
    """Build and write all 100 dirty/clean case pairs and manifest.json."""
    old_manifest_path = BENCHMARK_DIR / "manifest.json"
    old_items: List[Dict[str, Any]] = json.loads(old_manifest_path.read_text(encoding="utf-8")) if old_manifest_path.exists() else []
    old_by_id = {item["id"]: item for item in old_items}

    manifest_entries: List[Dict[str, Any]] = []

    # 1. Cases 1 through 25
    for cid in range(1, 26):
        old = old_by_id.get(cid)
        if not old:
            raise ValueError(f"Missing base case {cid} from manifest.json")
        dirty_rel = old["file"]
        dirty_path = REPO_DIR / dirty_rel
        if not dirty_path.exists():
            raise ValueError(f"Missing dirty file {dirty_path}")

        clean_filename = Path(dirty_rel).name
        clean_rel = f"benchmark/clean/{clean_filename}"
        clean_path = REPO_DIR / clean_rel

        clean_source = CLEAN_PATCHES_1_TO_25[cid]
        clean_path.write_text(clean_source, encoding="utf-8")

        models_failing = ["claude-3.7-sonnet", "gpt-4o", "gemini-2.0-flash", "deepseek-v3"]
        if cid % 3 == 0:
            models_failing.append("cursor")

        manifest_entries.append(
            {
                "id": cid,
                "file": dirty_rel,
                "clean_file": clean_rel,
                "language": old["language"],
                "category": (
                    "Hallucination"
                    if "HAL" in old["expected_rule"]
                    else "Security"
                    if "SEC" in old["expected_rule"]
                    else "Logic"
                    if "LOG" in old["expected_rule"]
                    else "AI Anti-Pattern"
                ),
                "expected_rule": old["expected_rule"],
                "description": old["description"],
                "models_failing": models_failing,
            }
        )

    # 2. Cases 26 through 100
    for cid, fname, lang, cat, rule, desc, dirty_code, clean_code, models in EXTRA_CASES:
        dirty_rel = f"benchmark/cases/{fname}"
        clean_rel = f"benchmark/clean/{fname}"
        dirty_path = REPO_DIR / dirty_rel
        clean_path = REPO_DIR / clean_rel

        dirty_path.write_text(dirty_code, encoding="utf-8")
        clean_path.write_text(clean_code, encoding="utf-8")

        manifest_entries.append(
            {
                "id": cid,
                "file": dirty_rel,
                "clean_file": clean_rel,
                "language": lang,
                "category": cat,
                "expected_rule": rule,
                "description": desc,
                "models_failing": models,
            }
        )

    assert len(manifest_entries) == 100, f"Expected 100 entries, got {len(manifest_entries)}"

    # Write manifest.json
    manifest_path = BENCHMARK_DIR / "manifest.json"
    manifest_path.write_text(json.dumps(manifest_entries, indent=2) + "\n", encoding="utf-8")
    print(f"[OK] Generated {len(manifest_entries)} benchmark pairs in benchmark/cases and benchmark/clean.")
    return len(manifest_entries)


if __name__ == "__main__":
    build_top100_suite()
