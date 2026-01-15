# hexlen_extract.py
# IDAPython module: build SQLite index + shortlist + batch LLM feature extraction
# Updated: adds progress_cb support for UI progress reporting.

import json
import os
import re
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

# LLM module merged into extract.py
import ida_funcs
import ida_kernwin
import ida_lines
import ida_name
import ida_segment
import idaapi
import idautils

# -----------------------------
# Config
# -----------------------------
DB_SUFFIX = ".hexlen.sqlite"

# Disassembly budget for "function package" sent to LLM
# Reduced for faster processing - LLM can still extract features from less code
MAX_HEAD_INSNS = 40  # Reduced from 80
MAX_TAIL_INSNS = 20  # Reduced from 40
MAX_CALLEES = 30     # Reduced from 80
MAX_CALLERS = 30     # Reduced from 80

# LLM feature extraction limits
LLM_MAX_FUNCS = 50  # Reduced significantly - only analyze top candidates, rest done on-demand
# Note: Neighbor expansion is done on-demand during chat queries via db.get_neighbors,
# not during indexing. This is more efficient - only analyze what's actually queried.
# Functions are processed one at a time (no batching) to reduce prompt size and improve speed.

# Scoring weights (cheap triage)
W_EXEC = 12
W_FILE = 8
W_AUTH = 8
W_ALLOC = 6
W_WRITE = 7
W_STR = 6
W_BIGFUNC = 3
W_FAN = 2
W_SRC_ENV = 4  # Functions that read environment variables
W_SRC_ARGV = 4  # Functions that parse command-line arguments

BIGFUNC_INSN_THRESHOLD = 220


# -----------------------------
# API name heuristics (cheap)
# -----------------------------
MEM_WRITE_HINTS = (
    "memcpy",
    "memmove",
    "strcpy",
    "strncpy",
    "sprintf",
    "snprintf",
    "strcat",
    "strncat",
    "gets",
    "stpcpy",
    "wcscpy",
    "wcsncpy",
)
ALLOC_HINTS = ("malloc", "calloc", "realloc", "free", "new", "delete", "alloca")
EXEC_HINTS = (
    "system",
    "popen",
    "execve",
    "execl",
    "execvp",
    "posix_spawn",
    "createprocess",
)
FILE_HINTS = (
    "open",
    "fopen",
    "read",
    "write",
    "recv",
    "send",
    "unlink",
    "rename",
    "chmod",
    "chown",
)
AUTH_HINTS = (
    "auth",
    "pam_",
    "seteuid",
    "setuid",
    "setgid",
    "getuid",
    "geteuid",
    "cap_",
    "policy",
    "permit",
    "deny",
)


# -----------------------------
# Utility
# -----------------------------
def _ea_hex(ea: int) -> str:
    return f"0x{ea:X}"


def _get_idb_path() -> str:
    return idaapi.get_path(idaapi.PATH_TYPE_IDB)


def _db_path_for_idb() -> str:
    return _get_idb_path() + DB_SUFFIX


def _safe_disasm(ea: int) -> str:
    line = ida_lines.generate_disasm_line(ea, 0)
    if not line:
        return ""
    return ida_lines.tag_remove(line).strip()


def _iter_func_insns(func: ida_funcs.func_t):
    ea = func.start_ea
    while ea != idaapi.BADADDR and ea < func.end_ea:
        yield ea
        ea = idaapi.next_head(ea, func.end_ea)


def _func_segment_name(ea: int) -> str:
    seg = ida_segment.getseg(ea)
    if not seg:
        return ""
    return ida_segment.get_segm_name(seg) or ""


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip())


def _normalize_call_name(name: str) -> str:
    """Normalize call name by stripping common prefixes/suffixes."""
    if not name:
        return ""
    # Strip prefixes: j_, __imp_, imp_, plt.
    name = re.sub(r'^(j_|__imp_|imp_|plt\.)', '', name)
    # Strip suffixes: @plt, @@GLIBC, @GLIBC_2.x, etc.
    name = re.sub(r'@.*$', '', name)
    return name.strip()


def _dedup_limit(items: List[str], limit: int = 30) -> List[str]:
    out: List[str] = []
    seen = set()
    for x in items:
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
        if len(out) >= limit:
            break
    return out


def _maybe_progress(progress_cb, phase: str, current: int, total: int, msg: str):
    if progress_cb:
        try:
            progress_cb(phase=phase, current=current, total=total, msg=msg)
        except Exception:
            # UI callback errors should never break extraction
            pass


# -----------------------------
# Cheap analysis per function
# -----------------------------
def _get_callees(func: ida_funcs.func_t) -> List[int]:
    callees: List[int] = []
    seen = set()
    for ea in _iter_func_insns(func):
        if not idaapi.is_call_insn(ea):
            continue
        for x in idautils.XrefsFrom(ea, 0):
            if x.type in (idaapi.fl_CN, idaapi.fl_CF):
                to = int(x.to)
                if to != idaapi.BADADDR and to not in seen:
                    seen.add(to)
                    callees.append(to)
                    if len(callees) >= MAX_CALLEES:
                        return callees
    return callees


def _get_callers(func: ida_funcs.func_t) -> List[int]:
    callers: List[int] = []
    seen = set()
    for x in idautils.XrefsTo(func.start_ea, 0):
        frm = int(x.frm)
        f = ida_funcs.get_func(frm)
        if not f:
            continue
        start = int(f.start_ea)
        if start not in seen:
            seen.add(start)
            callers.append(start)
            if len(callers) >= MAX_CALLERS:
                return callers
    return callers


def _basic_block_count(func: ida_funcs.func_t) -> int:
    try:
        fc = idaapi.FlowChart(func)
        return sum(1 for _ in fc)
    except Exception:
        return 0


def _collect_called_names(func: ida_funcs.func_t) -> List[str]:
    names: List[str] = []
    for ea in _iter_func_insns(func):
        if not idaapi.is_call_insn(ea):
            continue
        for x in idautils.XrefsFrom(ea, 0):
            if x.type not in (idaapi.fl_CN, idaapi.fl_CF):
                continue
            nm = ida_name.get_name(x.to) or ""
            nm = nm.strip()
            if nm:
                names.append(nm)
    return _dedup_limit(names, 60)


def _collect_called_names_normalized(func: ida_funcs.func_t) -> List[str]:
    """Collect called names and return both raw and normalized versions."""
    raw_names = _collect_called_names(func)
    normalized = []
    seen = set()
    for nm in raw_names:
        norm = _normalize_call_name(nm)
        if norm and norm not in seen:
            normalized.append(norm)
            seen.add(norm)
    # Return normalized names (raw names already stored separately)
    return normalized


def _cheap_flags_from_called_names(called: List[str]) -> Dict[str, int]:
    low = " ".join(called).lower()
    # Also check normalized names
    normalized = [_normalize_call_name(n) for n in called]
    low_normalized = " ".join(normalized).lower()
    combined = low + " " + low_normalized

    def has_any(hints) -> int:
        return 1 if any(h in combined for h in hints) else 0

    return {
        "has_alloc": has_any(ALLOC_HINTS),
        "has_write": has_any(MEM_WRITE_HINTS),
        "has_exec": has_any(EXEC_HINTS),
        "has_file": has_any(FILE_HINTS),
        "has_auth": has_any(AUTH_HINTS),
        "has_src_env": has_any(("getenv", "secure_getenv", "__secure_getenv")),
        "has_src_argv": has_any(("getopt", "getopt_long", "getopt_long_only")),
    }


def _bounded_disasm(func: ida_funcs.func_t) -> Dict[str, Any]:
    insns = list(_iter_func_insns(func))
    head = insns[:MAX_HEAD_INSNS]
    tail = insns[-MAX_TAIL_INSNS:] if len(insns) > MAX_HEAD_INSNS else []

    def dump(eas: List[int]) -> List[str]:
        out = []
        for ea in eas:
            d = _safe_disasm(ea)
            if d:
                out.append(f"{_ea_hex(ea)}: {d}")
        return out

    return {
        "insn_count": len(insns),
        "head": dump(head),
        "tail": dump(tail),
    }


def _triage_score(row: Dict[str, Any]) -> int:
    score = 0
    score += W_EXEC if row.get("has_exec") else 0
    score += W_FILE if row.get("has_file") else 0
    score += W_AUTH if row.get("has_auth") else 0
    score += W_ALLOC if row.get("has_alloc") else 0
    score += W_WRITE if row.get("has_write") else 0
    score += W_SRC_ENV if row.get("has_src_env") else 0
    score += W_SRC_ARGV if row.get("has_src_argv") else 0
    score += (
        W_STR
        if (
            "sprintf" in (row.get("called_text", "").lower())
            or "snprintf" in row.get("called_text", "").lower()
        )
        else 0
    )
    score += W_BIGFUNC if (row.get("insn_count", 0) >= BIGFUNC_INSN_THRESHOLD) else 0
    if (row.get("caller_count", 0) + row.get("callee_count", 0)) >= 20:
        score += W_FAN
    return score


# -----------------------------
# SQLite
# -----------------------------
def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA temp_store=MEMORY;")
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
CREATE TABLE IF NOT EXISTS functions (
  func_ea       INTEGER PRIMARY KEY,
  name          TEXT,
  segment       TEXT,
  insn_count    INTEGER,
  bb_count      INTEGER,
  caller_count  INTEGER,
  callee_count  INTEGER,

  called_names  TEXT,         -- JSON list of called symbol names
  called_text   TEXT,         -- normalized text for quick LIKE/FTS (includes normalized names)
  has_alloc     INTEGER,
  has_write     INTEGER,
  has_exec      INTEGER,
  has_file      INTEGER,
  has_auth      INTEGER,
  has_src_env   INTEGER,      -- calls getenv/secure_getenv
  has_src_argv  INTEGER,      -- calls getopt/getopt_long

  triage_score  INTEGER,

  features_json TEXT,         -- LLM output JSON (later)
  updated_at    INTEGER
);

CREATE VIRTUAL TABLE IF NOT EXISTS func_text
USING fts5(func_ea UNINDEXED, card_text, tokenize='unicode61');

CREATE TABLE IF NOT EXISTS edges (
  src_ea   INTEGER,
  dst_ea   INTEGER,
  kind     TEXT,
  detail   TEXT,
  PRIMARY KEY (src_ea, dst_ea, kind, detail)
);

CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(src_ea);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst_ea);
CREATE INDEX IF NOT EXISTS idx_functions_score ON functions(triage_score DESC);
"""
    )
    # Migrate existing databases: add new columns if they don't exist
    try:
        conn.execute("ALTER TABLE functions ADD COLUMN has_src_env INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # Column already exists
    try:
        conn.execute("ALTER TABLE functions ADD COLUMN has_src_argv INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # Column already exists
    conn.commit()


def _upsert_function_row(conn: sqlite3.Connection, row: Dict[str, Any]) -> None:
    conn.execute(
        """
INSERT INTO functions (
  func_ea, name, segment, insn_count, bb_count, caller_count, callee_count,
  called_names, called_text,
  has_alloc, has_write, has_exec, has_file, has_auth, has_src_env, has_src_argv,
  triage_score, features_json, updated_at
) VALUES (
  :func_ea, :name, :segment, :insn_count, :bb_count, :caller_count, :callee_count,
  :called_names, :called_text,
  :has_alloc, :has_write, :has_exec, :has_file, :has_auth, :has_src_env, :has_src_argv,
  :triage_score, :features_json, :updated_at
)
ON CONFLICT(func_ea) DO UPDATE SET
  name=excluded.name,
  segment=excluded.segment,
  insn_count=excluded.insn_count,
  bb_count=excluded.bb_count,
  caller_count=excluded.caller_count,
  callee_count=excluded.callee_count,
  called_names=excluded.called_names,
  called_text=excluded.called_text,
  has_alloc=excluded.has_alloc,
  has_write=excluded.has_write,
  has_exec=excluded.has_exec,
  has_file=excluded.has_file,
  has_auth=excluded.has_auth,
  has_src_env=excluded.has_src_env,
  has_src_argv=excluded.has_src_argv,
  triage_score=excluded.triage_score,
  features_json=COALESCE(excluded.features_json, functions.features_json),
  updated_at=excluded.updated_at
""",
        row,
    )


def _upsert_edges(
    conn: sqlite3.Connection, src_ea: int, dst_ea: int, kind: str, detail: str
) -> None:
    conn.execute(
        """
INSERT OR IGNORE INTO edges (src_ea, dst_ea, kind, detail)
VALUES (?, ?, ?, ?)
""",
        (src_ea, dst_ea, kind, detail),
    )


def _upsert_fts_card(conn: sqlite3.Connection, func_ea: int, card_text: str) -> None:
    conn.execute("DELETE FROM func_text WHERE func_ea=?", (func_ea,))
    conn.execute(
        "INSERT INTO func_text (func_ea, card_text) VALUES (?, ?)", (func_ea, card_text)
    )


# -----------------------------
# Function card (for FTS)
# -----------------------------
def _build_card_from_cheap(row: Dict[str, Any]) -> str:
    tags = []
    if row.get("has_alloc"):
        tags.append("SINK_ALLOC")
    if row.get("has_write"):
        tags.append("SINK_MEMWRITE")
    if row.get("has_exec"):
        tags.append("SINK_EXEC")
    if row.get("has_file"):
        tags.append("SINK_FILE")
    if row.get("has_auth"):
        tags.append("AUTH_OR_PRIV")
    if row.get("has_src_env"):
        tags.append("SRC_ENV")
    if row.get("has_src_argv"):
        tags.append("SRC_ARGV")

    called = []
    try:
        called = json.loads(row.get("called_names") or "[]")
    except Exception:
        called = []

    parts = [
        f"NAME {row.get('name','')}",
        f"EA {_ea_hex(row.get('func_ea',0))}",
        f"SEG {row.get('segment','')}",
        f"INSNS {row.get('insn_count',0)}",
        f"BB {row.get('bb_count',0)}",
        f"CALLERS {row.get('caller_count',0)}",
        f"CALLEES {row.get('callee_count',0)}",
        "TAGS " + " ".join(tags),
        "CALLS " + " ".join(_dedup_limit([str(x) for x in called], 40)),
    ]
    return _norm(" | ".join(parts))


def _build_card_from_features(
    func_row: Dict[str, Any], features: Dict[str, Any]
) -> str:
    base = _build_card_from_cheap(func_row)

    def as_list(k: str) -> List[str]:
        v = features.get(k, [])
        if isinstance(v, list):
            return [str(x) for x in v][:12]
        return []

    tags = []
    for src in as_list("input_sources"):
        tags.append(f"SRC_{src.upper()}")
    for s in as_list("exec_calls"):
        tags.append(f"EXEC_{str(s).upper()}")
    for s in as_list("file_ops"):
        tags.append(f"FILE_{str(s).upper()}")
    for s in as_list("auth_checks"):
        tags.append(f"AUTH_{str(s).upper()}")

    # ATT&CK-aligned malware features
    attack = features.get("attack", {})
    if isinstance(attack, dict):
        def attack_list(k: str) -> List[str]:
            v = attack.get(k, [])
            if isinstance(v, list):
                return [str(x) for x in v][:12]
            return []
        
        for sig in attack_list("signals"):
            if sig:
                tags.append(f"ATTACK_SIG_{str(sig).upper()}")
        for c2 in attack_list("c2"):
            if c2:
                tags.append(f"ATTACK_C2_{str(c2).upper()}")
        for persist in attack_list("persistence"):
            if persist:
                tags.append(f"ATTACK_PERSIST_{str(persist).upper()}")
        for evas in attack_list("evasion"):
            if evas:
                tags.append(f"ATTACK_EVAS_{str(evas).upper()}")
        for lat in attack_list("lateral"):
            if lat:
                tags.append(f"ATTACK_LATERAL_{str(lat).upper()}")
        for exfil in attack_list("exfiltration"):
            if exfil:
                tags.append(f"ATTACK_EXFIL_{str(exfil).upper()}")

    lb = str(features.get("len_behavior", "unknown")).upper()
    bc = str(features.get("bounds_checks", "unknown")).upper()
    eb = str(features.get("error_behavior", "unknown")).upper()

    extra = _norm(
        " | ".join(
            [
                "LLM",
                f"LEN_{lb}",
                f"BOUNDS_{bc}",
                f"ERR_{eb}",
                "X " + " ".join(tags[:30]),
                "NOTES " + " ".join(as_list("notes")[:8]),
            ]
        )
    )
    return _norm(base + " | " + extra)


# -----------------------------
# LLM Feature Extraction (merged from llm.py)
# -----------------------------
FEATURE_SCHEMA_DOC = {
    "func_name": "string",
    "entry_ea": "string hex",
    "is_entry": "bool",
    "callees": "list[string]",
    "callers": "list[string]",
    "input_sources": "list[string] (argv|env|file|socket|ipc|config|registry)",
    "trusted_boundary": "bool (optional, v1)",
    "exec_calls": "list[string]",
    "file_ops": "list[string]",
    "allocs": "list[object(kind,evidence,detail)]",
    "writes": "list[object(kind,evidence,detail)]",
    "reads": "list[object(kind,evidence,detail)]",
    "string_ops": "list[string] (concat|format|escape|unescape|normalize)",
    "len_behavior": "expands|shrinks|preserves|unknown",
    "bounds_checks": "yes|partial|none|unknown",
    "auth_checks": "list[string]",
    "error_behavior": "abort|return|continue|unknown",
    "invariant_assumptions": "list[string]",
    "notes": "list[string]",
    "attack": {
        "tactics": "list[string] (ATT&CK tactic IDs, optional)",
        "signals": "list[string] (concrete signals: process_injection|anti_debug|string_deobfuscation|beaconing_loop|http_c2|dns_tunnel|cred_dump|service_install|scheduled_task|autorun_registry|...)",
        "persistence": "list[string]",
        "evasion": "list[string]",
        "lateral": "list[string]",
        "c2": "list[string]",
        "exfiltration": "list[string]"
    },
    "confidence": "float 0..1"
}


def _llm_load_config() -> Dict[str, Any]:
    """Load LLM configuration from config file or environment."""
    config = {
        "provider": "openai",
        "openai_api_key": None,
        "openai_model_features": "gpt-4o-mini",  # Model for feature extraction
        "openai_model_chat": "gpt-5",  # Model for chat/planning (fallback, usually overridden)
        "openai_model": "gpt-4o-mini",  # Legacy fallback
        "ollama_base_url": "http://localhost:11434",
        "ollama_model_features": "llama3.2",  # Ollama model for feature extraction
        "ollama_model_chat": "llama3.2",  # Ollama model for chat/planning
        "ollama_model": "llama3.2",  # Legacy fallback
    }
    
    # Check environment variables first
    config["openai_api_key"] = os.environ.get("OPENAI_API_KEY")
    if os.environ.get("OLLAMA_BASE_URL"):
        config["ollama_base_url"] = os.environ.get("OLLAMA_BASE_URL")
    if os.environ.get("OLLAMA_MODEL"):
        config["ollama_model"] = os.environ.get("OLLAMA_MODEL")
    if os.environ.get("OLLAMA_MODEL_FEATURES"):
        config["ollama_model_features"] = os.environ.get("OLLAMA_MODEL_FEATURES")
    if os.environ.get("OLLAMA_MODEL_CHAT"):
        config["ollama_model_chat"] = os.environ.get("OLLAMA_MODEL_CHAT")
    
    # Load from config file
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "hexlens_config.json")
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                file_config = json.load(f)
                config.update(file_config)
        except Exception:
            pass
    
    return config


def _llm_get_client(config: Optional[Dict[str, Any]] = None):
    """Get LLM client (OpenAI or Ollama) based on configuration."""
    if config is None:
        config = _llm_load_config()
    
    provider = config.get("llm_provider", config.get("provider", "openai")).lower()
    
    if provider == "ollama":
        from openai import OpenAI
        base_url = config.get("ollama_base_url", "http://localhost:11434")
        # Ollama uses OpenAI-compatible API
        client = OpenAI(
            base_url=f"{base_url}/v1",
            api_key="ollama"  # Ollama doesn't require a real API key
        )
        # Use features model for feature extraction
        model = config.get("ollama_model_features") or config.get("ollama_model", "llama3.2")
        return client, "ollama", model
    else:
        # Default to OpenAI
        from openai import OpenAI
        api_key = config.get("openai_api_key") or os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OpenAI API key not found. Set OPENAI_API_KEY environment variable or configure in hexlens_config.json")
        client = OpenAI(api_key=api_key)
        # Use features model for feature extraction
        model = config.get("openai_model_features") or config.get("openai_model", "gpt-4o-mini")
        return client, "openai", model


def _llm_build_batch_prompt(func_pkgs: List[Dict[str, Any]]) -> str:
    """Request a SINGLE JSON object mapping entry_ea -> features."""
    return f"""
You are a binary security analyst. You will be given an array of function packages extracted from IDA Pro.
For EACH function, produce vulnerability-relevant features AND malware behavior signals (ATT&CK-aligned).

Output MUST be ONLY valid JSON (no markdown, no commentary) and MUST be a SINGLE JSON object:
{{
  "<entry_ea_hex>": <features_json>,
  ...
}}

Rules:
- Use ONLY evidence in each function package.
- If unsure, use "unknown" and lower confidence.
- Keep lists short (max ~12 items each).
- allocs/writes/reads items must include: kind, evidence (address like "0x..."), detail.
- For attack.signals: ONLY include concrete signals visible in code (no guessing technique IDs).
  Examples: process_injection, anti_debug, string_deobfuscation, beaconing_loop, http_c2, dns_tunnel, cred_dump, service_install, scheduled_task, autorun_registry.
- If no malware behavior detected, set attack to empty object: {{"tactics": [], "signals": [], "persistence": [], "evasion": [], "lateral": [], "c2": [], "exfiltration": []}}.

Each <features_json> MUST contain these keys (all required) and follow this schema:
{json.dumps(FEATURE_SCHEMA_DOC, indent=2)}

Function packages:
{json.dumps(func_pkgs, indent=2)}
""".strip()


def _llm_try_extract_json_object(text: str) -> Optional[str]:
    """If the model returns extra text, extract the first {{...}} block."""
    if not text:
        return None
    i = text.find("{")
    j = text.rfind("}")
    if i == -1 or j == -1 or j <= i:
        return None
    return text[i : j + 1]


def _llm_openai_json_call(prompt: str, model: Optional[str] = None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """LLM API call (OpenAI or Ollama) with JSON mode. Returns (result, metrics) where metrics contains timing and token info."""
    config = _llm_load_config()
    client, provider, default_model = _llm_get_client(config)
    
    # Use provided model or default from config
    if model is None:
        model = default_model
    
    start_time = time.time()
    
    # Build request parameters
    request_params = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
    }
    
    # OpenAI supports response_format, Ollama may not
    if provider == "openai":
        request_params["response_format"] = {"type": "json_object"}
    
    resp = client.chat.completions.create(**request_params)
    elapsed = time.time() - start_time
    
    # Extract token usage (Ollama may not provide this)
    usage = resp.usage
    metrics = {
        "elapsed_seconds": elapsed,
        "prompt_tokens": usage.prompt_tokens if usage else 0,
        "completion_tokens": usage.completion_tokens if usage else 0,
        "total_tokens": usage.total_tokens if usage else 0,
        "model": model,
        "provider": provider,
    }
    
    text = resp.choices[0].message.content
    try:
        result = json.loads(text)
        return result, metrics
    except Exception:
        sliced = _llm_try_extract_json_object(text)
        if sliced:
            result = json.loads(sliced)
            return result, metrics
        raise


def extract_features_batch(
    func_pkgs: List[Dict[str, Any]],
    model: Optional[str] = None,  # Uses model from config if None
) -> Tuple[Dict[int, Dict[str, Any]], Dict[str, Any]]:
    """
    Input: list of function packages (each has entry_ea like "0x401000")
    Output: (features_dict, metrics) where:
        - features_dict: { func_ea_int: features_dict }
        - metrics: { elapsed_seconds, prompt_tokens, completion_tokens, total_tokens, model }
    """
    if not func_pkgs:
        return {}, {"elapsed_seconds": 0, "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "model": model}
    
    prompt = _llm_build_batch_prompt(func_pkgs)
    obj, metrics = _llm_openai_json_call(prompt, model=model)
    
    out: Dict[int, Dict[str, Any]] = {}
    
    if not isinstance(obj, dict):
        for pkg in func_pkgs:
            ea_int = int(pkg["entry_ea"], 16)
            out[ea_int] = {"error": "llm_return_not_object", "confidence": 0.0}
        return out, metrics
    
    # Normalize keys
    for k, v in obj.items():
        try:
            ks = str(k)
            ea_int = int(ks, 16) if ks.startswith("0x") else int(ks)
        except Exception:
            continue
        
        if isinstance(v, dict):
            out[ea_int] = v
        else:
            out[ea_int] = {"error": "features_not_object", "confidence": 0.0}
    
    # Ensure every requested function has an entry
    requested = {int(pkg["entry_ea"], 16) for pkg in func_pkgs}
    for ea in requested:
        if ea not in out:
            out[ea] = {"error": "missing_features_for_function", "confidence": 0.0}
    
    return out, metrics


# -----------------------------
# LLM package creation
# -----------------------------
def _make_llm_pkg(func_ea: int) -> Optional[Dict[str, Any]]:
    func = ida_funcs.get_func(func_ea)
    if not func:
        return None

    name = ida_funcs.get_func_name(func.start_ea)

    pkg = {
        "func_name": name,
        "entry_ea": _ea_hex(func.start_ea),
        "end_ea": _ea_hex(func.end_ea),
        "segment": _func_segment_name(func.start_ea),
        "called_names": _collect_called_names(func),
        "callers": [_ea_hex(x) for x in _get_callers(func)],
        "callees": [_ea_hex(x) for x in _get_callees(func)],
        "disasm": _bounded_disasm(func),
    }
    return pkg


# -----------------------------
# Main extraction passes
# -----------------------------
def pass0_index_all(conn: sqlite3.Connection, progress_cb=None) -> None:
    ida_kernwin.show_wait_box(
        "HIDECANCEL\nHexLen: pass0 indexing functions + call graph..."
    )
    try:
        now = int(time.time())
        funcs = list(idautils.Functions())
        total = len(funcs)

        idx = 0
        for func_ea in funcs:
            idx += 1
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue

            name = ida_funcs.get_func_name(func.start_ea)
            seg = _func_segment_name(func.start_ea)

            insn_count = 0
            for _ in _iter_func_insns(func):
                insn_count += 1

            bb_count = _basic_block_count(func)
            callees = _get_callees(func)
            callers = _get_callers(func)

            called_names = _collect_called_names(func)
            # Build called_text with normalized names for better searchability
            normalized_names = _collect_called_names_normalized(func)
            called_text = _norm(" ".join(called_names + normalized_names)).lower()
            flags = _cheap_flags_from_called_names(called_names)

            row = {
                "func_ea": int(func.start_ea),
                "name": name,
                "segment": seg,
                "insn_count": insn_count,
                "bb_count": bb_count,
                "caller_count": len(callers),
                "callee_count": len(callees),
                "called_names": json.dumps(called_names),
                "called_text": called_text,
                "has_alloc": flags["has_alloc"],
                "has_write": flags["has_write"],
                "has_exec": flags["has_exec"],
                "has_file": flags["has_file"],
                "has_auth": flags["has_auth"],
                "has_src_env": flags["has_src_env"],
                "has_src_argv": flags["has_src_argv"],
                "triage_score": 0,
                "features_json": None,  # keep existing if present
                "updated_at": now,
            }
            row["triage_score"] = _triage_score(row)
            _upsert_function_row(conn, row)

            for dst in callees:
                _upsert_edges(conn, int(func.start_ea), int(dst), "call", "")

            # progress (every 25 funcs or at end)
            if idx % 25 == 0 or idx == total:
                _maybe_progress(
                    progress_cb, "pass0", idx, total, f"Indexed {idx}/{total} functions"
                )

        conn.commit()

        # Populate FTS with cheap card text
        cur = conn.execute(
            """
SELECT func_ea, name, segment, insn_count, bb_count, caller_count, callee_count, called_names, called_text,
       has_alloc, has_write, has_exec, has_file, has_auth, has_src_env, has_src_argv, triage_score
FROM functions
"""
        )
        rows = cur.fetchall()

        total2 = len(rows)
        for i, r in enumerate(rows, start=1):
            func_row = {
                "func_ea": r[0],
                "name": r[1],
                "segment": r[2],
                "insn_count": r[3],
                "bb_count": r[4],
                "caller_count": r[5],
                "callee_count": r[6],
                "called_names": r[7],
                "called_text": r[8],
                "has_alloc": r[9],
                "has_write": r[10],
                "has_exec": r[11],
                "has_file": r[12],
                "has_auth": r[13],
                "has_src_env": r[14] if len(r) > 14 else 0,
                "has_src_argv": r[15] if len(r) > 15 else 0,
                "triage_score": r[16] if len(r) > 16 else r[14],
            }
            card = _build_card_from_cheap(func_row)
            _upsert_fts_card(conn, int(func_row["func_ea"]), card)

            if i % 250 == 0 or i == total2:
                _maybe_progress(
                    progress_cb, "pass0", i, total2, f"FTS cards {i}/{total2}"
                )

        conn.commit()
        _maybe_progress(progress_cb, "pass0", total, total, "Pass0 complete")

    finally:
        ida_kernwin.hide_wait_box()


def _select_top_candidates(conn: sqlite3.Connection, limit: int) -> List[int]:
    cur = conn.execute(
        """
SELECT func_ea FROM functions
ORDER BY triage_score DESC
LIMIT ?
""",
        (limit,),
    )
    return [int(r[0]) for r in cur.fetchall()]


def _expand_neighbors(
    conn: sqlite3.Connection, seeds: List[int], depth: int = 1
) -> List[int]:
    if depth <= 0:
        return seeds
    seen = set(seeds)
    frontier = set(seeds)
    for _ in range(depth):
        if not frontier:
            break
        nxt = set()
        for ea in frontier:
            cur = conn.execute(
                "SELECT dst_ea FROM edges WHERE src_ea=? AND kind='call'", (ea,)
            )
            for (dst,) in cur.fetchall():
                d = int(dst)
                if d not in seen:
                    seen.add(d)
                    nxt.add(d)
            cur = conn.execute(
                "SELECT src_ea FROM edges WHERE dst_ea=? AND kind='call'", (ea,)
            )
            for (src,) in cur.fetchall():
                s = int(src)
                if s not in seen:
                    seen.add(s)
                    nxt.add(s)
        frontier = nxt
    return list(seen)


def pass2_llm_features(
    conn: sqlite3.Connection,
    max_funcs: int = LLM_MAX_FUNCS,
    progress_cb=None,
) -> None:
    """
    Extract LLM features for top candidate functions.
    Note: Neighbor expansion is done on-demand during chat queries, not here.
    This keeps indexing fast - only analyze what's actually needed when queried.
    """

    targets = _select_top_candidates(conn, max_funcs)

    # Remove already processed
    cur = conn.execute("SELECT func_ea FROM functions WHERE features_json IS NOT NULL")
    done = {int(r[0]) for r in cur.fetchall()}
    targets = [ea for ea in targets if ea not in done]

    if not targets:
        _maybe_progress(
            progress_cb, "pass2", 0, 0, "No new targets (features already present)."
        )
        return

    ida_kernwin.show_wait_box(
        f"HIDECANCEL\nHexLen: pass2 LLM feature extraction ({len(targets)} funcs, one at a time)..."
    )
    try:
        now = int(time.time())
        total = len(targets)

        def get_func_row(ea: int) -> Dict[str, Any]:
            cur2 = conn.execute(
                """
SELECT func_ea, name, segment, insn_count, bb_count, caller_count, callee_count,
       called_names, called_text, has_alloc, has_write, has_exec, has_file, has_auth, has_src_env, has_src_argv, triage_score
FROM functions WHERE func_ea=?
""",
                (ea,),
            )
            r = cur2.fetchone()
            if not r:
                return {}
            return {
                "func_ea": r[0],
                "name": r[1],
                "segment": r[2],
                "insn_count": r[3],
                "bb_count": r[4],
                "caller_count": r[5],
                "callee_count": r[6],
                "called_names": r[7],
                "called_text": r[8],
                "has_alloc": r[9],
                "has_write": r[10],
                "has_exec": r[11],
                "has_file": r[12],
                "has_auth": r[13],
                "has_src_env": r[14] if len(r) > 14 else 0,
                "has_src_argv": r[15] if len(r) > 15 else 0,
                "triage_score": r[16] if len(r) > 16 else r[14],
            }

        processed = 0
        for idx, ea in enumerate(targets, start=1):
            pkg = _make_llm_pkg(ea)
            if not pkg:
                processed += 1
                _maybe_progress(
                    progress_cb,
                    "pass2",
                    processed,
                    total,
                    f"Skipped {processed}/{total}",
                )
                continue

            try:
                func_start = time.time()
                # Process single function (no batching)
                result_map, metrics = extract_features_batch([pkg])
                func_elapsed = time.time() - func_start
                
                # Log metrics
                elapsed = metrics.get("elapsed_seconds", func_elapsed)
                prompt_tokens = metrics.get("prompt_tokens", 0)
                completion_tokens = metrics.get("completion_tokens", 0)
                total_tokens = metrics.get("total_tokens", 0)
                model = metrics.get("model", "unknown")
                
                func_name = pkg.get("func_name", "unknown")
                log_msg = (
                    f"{idx}/{total}: {func_name}, "
                    f"{elapsed:.2f}s, {total_tokens} tokens"
                )
                if prompt_tokens > 0 or completion_tokens > 0:
                    log_msg += f" [prompt={prompt_tokens}, completion={completion_tokens}]"
                
                processed += 1
                _maybe_progress(
                    progress_cb,
                    "pass2",
                    processed,
                    total,
                    log_msg,
                )
            except Exception as e:
                result_map = {
                    int(pkg["entry_ea"], 16): {"error": str(e), "confidence": 0.0}
                }
                processed += 1
                _maybe_progress(
                    progress_cb,
                    "pass2",
                    processed,
                    total,
                    f"{idx}/{total} error: {str(e)}",
                )

            # Store results
            ea_int = int(pkg["entry_ea"], 16)
            features = result_map.get(ea_int)
            if not isinstance(features, dict):
                features = {
                    "error": "missing_or_invalid_llm_output",
                    "confidence": 0.0,
                }

            func_row = get_func_row(ea_int)
            card = _build_card_from_features(func_row, features) if func_row else ""

            conn.execute(
                "UPDATE functions SET features_json=?, updated_at=? WHERE func_ea=?",
                (json.dumps(features), now, ea_int),
            )
            if card:
                _upsert_fts_card(conn, ea_int, card)

            conn.commit()

        _maybe_progress(progress_cb, "pass2", total, total, "Pass2 complete")

    finally:
        ida_kernwin.hide_wait_box()


# -----------------------------
# Public entrypoint
# -----------------------------
def run_full_indexing(progress_cb=None) -> None:
    """
    1) pass0: index all functions + callgraph + cheap cards
    2) pass2: shortlist + batch LLM extraction + enriched cards
    """
    db_path = _db_path_for_idb()
    conn = _connect(db_path)
    _init_schema(conn)

    pass0_index_all(conn, progress_cb=progress_cb)

    # Extract LLM features
    pass2_llm_features(conn, progress_cb=progress_cb)

    conn.close()
    _maybe_progress(progress_cb, "done", 1, 1, f"DB ready: {db_path}")
    ida_kernwin.info(f"HexLen: done.\nDB: {db_path}")
