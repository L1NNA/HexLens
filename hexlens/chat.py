# hexlen_chat.py
# Cursor-like chat agent for HexLens
# 
# How to use:
#   1. User types a question in the UI (e.g., "Find buffer overflow risks")
#   2. run_chat(user_text, ui_cb) is called
#   3. Agent plans → acts → evaluates → repeats until enough evidence
#   4. Agent produces final answer with findings, witness paths, evidence refs
#   5. UI displays answer and allows jumping to functions
#
# The agent uses a fixed set of tools (DB queries, IDA fetches, LLM enrichment)
# and operates within strict budgets to prevent excessive API calls or data fetching.

import json
import os
import re
import sqlite3
import time
import traceback
from collections import deque
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

import hexlens.extract as hexlen_extract
import ida_funcs
import ida_kernwin
import ida_lines
import ida_name
import ida_segment
import idaapi
import idautils
from openai import OpenAI


# -----------------------------
# Budget Configuration
# -----------------------------
class Budget:
    def __init__(self):
        self.max_db_queries = 50
        self.max_ida_fetches = 30
        self.max_disasm_lines = 500
        self.max_functions_deep = 20
        self.max_llm_calls = 5
        self.max_strings_per_func = 20
        self.max_xrefs_per_func = 50
        
        self.used_db_queries = 0
        self.used_ida_fetches = 0
        self.used_disasm_lines = 0
        self.used_functions_deep = 0
        self.used_llm_calls = 0
        
    def can_query_db(self) -> bool:
        return self.used_db_queries < self.max_db_queries
    
    def can_fetch_ida(self) -> bool:
        return self.used_ida_fetches < self.max_ida_fetches
    
    def can_add_disasm(self, lines: int) -> bool:
        return (self.used_disasm_lines + lines) <= self.max_disasm_lines
    
    def can_add_function(self) -> bool:
        return self.used_functions_deep < self.max_functions_deep
    
    def can_call_llm(self) -> bool:
        return self.used_llm_calls < self.max_llm_calls
    
    def get_progress(self) -> Tuple[int, int]:
        """Returns (used, total) for progress bar."""
        total = (self.max_db_queries + self.max_ida_fetches + 
                self.max_llm_calls + self.max_functions_deep)
        used = (self.used_db_queries + self.used_ida_fetches + 
               self.used_llm_calls + self.used_functions_deep)
        return (used, total)


# -----------------------------
# SQLite Helpers
# -----------------------------
# Cache for database path (set from main thread when using background worker)
_cached_db_path: Optional[str] = None

def _get_db_path() -> Optional[str]:
    """Get path to SQLite DB for current IDB. Uses same logic as extract.py."""
    # If we have a cached path (from main thread), use it
    global _cached_db_path
    if _cached_db_path:
        return _cached_db_path
    
    try:
        # Use the same function as extract.py for consistency
        return hexlen_extract._db_path_for_idb()
    except Exception:
        return None


def _connect_db() -> Optional[sqlite3.Connection]:
    """Open connection to Hex Len SQLite DB. Tries multiple strategies to find DB."""
    db_path = _get_db_path()
    
    # Strategy 1: Try the expected path (same as extract.py uses)
    if db_path and os.path.exists(db_path):
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            return conn
        except Exception:
            pass
    
    # Strategy 2: Search in IDB directory and input file directory for any .hexlen.sqlite file
    search_dirs = []
    try:
        idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB)
        if idb_path and idb_path.strip():
            search_dirs.append(os.path.dirname(idb_path))
        
        # Also try input file directory
        input_file = idaapi.get_input_file_path()
        if input_file and input_file.strip():
            input_dir = os.path.dirname(input_file)
            if input_dir and input_dir not in search_dirs:
                search_dirs.append(input_dir)
    except Exception:
        pass
    
    # Strategy 3: If we have an IDB path, try constructing DB path from IDB base name
    try:
        idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB)
        if idb_path and idb_path.strip():
            # Try: idb_path + .hexlen.sqlite
            candidate = idb_path + hexlen_extract.DB_SUFFIX
            if os.path.exists(candidate):
                try:
                    conn = sqlite3.connect(candidate)
                    conn.row_factory = sqlite3.Row
                    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='functions'")
                    if cur.fetchone():
                        return conn
                    conn.close()
                except Exception:
                    pass
    except Exception:
        pass
    
    # Search in all candidate directories
    for search_dir in search_dirs:
        if not search_dir or not os.path.isdir(search_dir):
            continue
        try:
            for fname in os.listdir(search_dir):
                if fname.endswith(hexlen_extract.DB_SUFFIX):
                    candidate_path = os.path.join(search_dir, fname)
                    if os.path.exists(candidate_path):
                        try:
                            conn = sqlite3.connect(candidate_path)
                            conn.row_factory = sqlite3.Row
                            # Verify it's a valid HexLen DB by checking for functions table
                            cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='functions'")
                            if cur.fetchone():
                                return conn
                            conn.close()
                        except Exception:
                            pass
        except Exception:
            pass
    
    return None


def db_search_cards(conn: sqlite3.Connection, fts_query: str, 
                    filters: Dict[str, Any], limit: int) -> List[Dict[str, Any]]:
    """Search function cards using LIKE queries first (more reliable for tags like SRC_ENV, SINK_MEMWRITE)."""
    
    # Normalize query
    query_lower = fts_query.lower()
    query_normalized = re.sub(r'_+', ' ', query_lower)  # Replace underscores with spaces
    query_normalized = re.sub(r'-+', ' ', query_normalized)  # Replace hyphens with spaces
    query_normalized = re.sub(r'\s+', ' ', query_normalized).strip()  # Collapse whitespace
    
    # Split query into individual terms for multi-term LIKE search
    # e.g., "SRC_ENV SINK_MEMWRITE" -> ["SRC_ENV", "SINK", "MEMWRITE"]
    terms = []
    # First, try to preserve tag-like terms (uppercase with underscores)
    tag_pattern = r'[A-Z_][A-Z0-9_]*'
    tag_matches = re.findall(tag_pattern, fts_query.upper())
    terms.extend(tag_matches)
    # Then add normalized terms (split on spaces)
    normalized_terms = query_normalized.split()
    for term in normalized_terms:
        if term.upper() not in [t.upper() for t in terms]:
            terms.append(term)
    # Also include the full query as-is
    if query_lower not in [t.lower() for t in terms]:
        terms.append(query_lower)
    if query_normalized not in [t.lower() for t in terms]:
        terms.append(query_normalized)
    
    # Build filter conditions
    filter_conditions = []
    filter_params = []
    if filters.get("has_exec"):
        filter_conditions.append("f.has_exec = 1")
    if filters.get("has_write"):
        filter_conditions.append("f.has_write = 1")
    if filters.get("has_alloc"):
        filter_conditions.append("f.has_alloc = 1")
    if filters.get("has_file"):
        filter_conditions.append("f.has_file = 1")
    if filters.get("has_auth"):
        filter_conditions.append("f.has_auth = 1")
    if filters.get("min_score"):
        filter_conditions.append("f.triage_score >= ?")
        filter_params.append(filters["min_score"])
    
    filter_clause = " AND " + " AND ".join(filter_conditions) if filter_conditions else ""
    
    # Build LIKE conditions - each term can match (OR logic)
    # For tags like "SRC_ENV", we want to match both "SRC_ENV" and "SRC ENV"
    like_conditions = []
    like_params = []
    for term in terms:
        term_lower = term.lower()
        # Match the term as-is and with underscores replaced by spaces
        term_normalized = term_lower.replace('_', ' ')
        like_conditions.append("(ft.card_text LIKE ? OR ft.card_text LIKE ?)")
        like_params.extend([f"%{term_lower}%", f"%{term_normalized}%"])
    
    # Combine all LIKE conditions with OR (any term can match)
    like_where = "(" + " OR ".join(like_conditions) + ")" + filter_clause
    
    like_query_sql = f"""
    SELECT f.func_ea, f.name, f.segment, f.insn_count, f.bb_count,
           f.caller_count, f.callee_count, f.triage_score,
           f.has_alloc, f.has_write, f.has_exec, f.has_file, f.has_auth,
           f.features_json, ft.card_text
    FROM func_text ft
    JOIN functions f ON ft.func_ea = f.func_ea
    WHERE {like_where}
    ORDER BY f.triage_score DESC
    LIMIT ?
    """
    like_params.extend(filter_params)
    like_params.append(limit)
    
    results = []
    seen_eas = set()
    
    try:
        cur = conn.execute(like_query_sql, like_params)
        for r in cur.fetchall():
            ea = int(r["func_ea"])
            if ea not in seen_eas:
                seen_eas.add(ea)
                results.append({
                    "func_ea": ea,
                    "name": r["name"],
                    "segment": r["segment"],
                    "insn_count": r["insn_count"],
                    "bb_count": r["bb_count"],
                    "caller_count": r["caller_count"],
                    "callee_count": r["callee_count"],
                    "triage_score": r["triage_score"],
                    "has_alloc": bool(r["has_alloc"]),
                    "has_write": bool(r["has_write"]),
                    "has_exec": bool(r["has_exec"]),
                    "has_file": bool(r["has_file"]),
                    "has_auth": bool(r["has_auth"]),
                    "features_json": r["features_json"],
                    "card_text": r["card_text"],
                })
    except Exception as e:
        # If LIKE fails, return empty results
        pass
    
    return results[:limit]


def db_get_function_rows(conn: sqlite3.Connection, func_eas: List[int]) -> List[Dict[str, Any]]:
    """Get function rows by EA list."""
    if not func_eas:
        return []
    placeholders = ",".join("?" * len(func_eas))
    query = f"""
    SELECT func_ea, name, segment, insn_count, bb_count,
           caller_count, callee_count, triage_score,
           has_alloc, has_write, has_exec, has_file, has_auth,
           features_json, called_names
    FROM functions
    WHERE func_ea IN ({placeholders})
    """
    cur = conn.execute(query, func_eas)
    rows = []
    for r in cur.fetchall():
        rows.append({
            "func_ea": int(r["func_ea"]),
            "name": r["name"],
            "segment": r["segment"],
            "insn_count": r["insn_count"],
            "bb_count": r["bb_count"],
            "caller_count": r["caller_count"],
            "callee_count": r["callee_count"],
            "triage_score": r["triage_score"],
            "has_alloc": bool(r["has_alloc"]),
            "has_write": bool(r["has_write"]),
            "has_exec": bool(r["has_exec"]),
            "has_file": bool(r["has_file"]),
            "has_auth": bool(r["has_auth"]),
            "features_json": r["features_json"],
            "called_names": r["called_names"],
        })
    return rows


def db_find_function_by_name(conn: sqlite3.Connection, func_name: str) -> List[Dict[str, Any]]:
    """Find function(s) by name (exact or partial match)."""
    if not func_name:
        return []
    
    # Try exact match first
    query = """
    SELECT func_ea, name, segment, insn_count, bb_count,
           caller_count, callee_count, triage_score,
           has_alloc, has_write, has_exec, has_file, has_auth,
           features_json, called_names
    FROM functions
    WHERE name = ?
    LIMIT 10
    """
    cur = conn.execute(query, (func_name,))
    rows = []
    for r in cur.fetchall():
        rows.append({
            "func_ea": int(r["func_ea"]),
            "name": r["name"],
            "segment": r["segment"],
            "insn_count": r["insn_count"],
            "bb_count": r["bb_count"],
            "caller_count": r["caller_count"],
            "callee_count": r["callee_count"],
            "triage_score": r["triage_score"],
            "has_alloc": bool(r["has_alloc"]),
            "has_write": bool(r["has_write"]),
            "has_exec": bool(r["has_exec"]),
            "has_file": bool(r["has_file"]),
            "has_auth": bool(r["has_auth"]),
            "features_json": r["features_json"],
            "called_names": r["called_names"],
        })
    
    # If no exact match, try LIKE search
    if not rows:
        query = """
        SELECT func_ea, name, segment, insn_count, bb_count,
               caller_count, callee_count, triage_score,
               has_alloc, has_write, has_exec, has_file, has_auth,
               features_json, called_names
        FROM functions
        WHERE name LIKE ?
        LIMIT 10
        """
        cur = conn.execute(query, (f"%{func_name}%",))
        for r in cur.fetchall():
            rows.append({
                "func_ea": int(r["func_ea"]),
                "name": r["name"],
                "segment": r["segment"],
                "insn_count": r["insn_count"],
                "bb_count": r["bb_count"],
                "caller_count": r["caller_count"],
                "callee_count": r["callee_count"],
                "triage_score": r["triage_score"],
                "has_alloc": bool(r["has_alloc"]),
                "has_write": bool(r["has_write"]),
                "has_exec": bool(r["has_exec"]),
                "has_file": bool(r["has_file"]),
                "has_auth": bool(r["has_auth"]),
                "features_json": r["features_json"],
                "called_names": r["called_names"],
            })
    
    return rows


def db_get_features(conn: sqlite3.Connection, func_eas: List[Any]) -> Dict[int, Dict[str, Any]]:
    """Get features_json for functions. Accepts EAs (int/hex) or function names (str)."""
    # Handle mixed input (EAs and names)
    processed_eas = []
    for x in func_eas:
        if isinstance(x, str):
            # Try to parse as hex address
            try:
                if x.startswith("0x") or x.startswith("0X"):
                    processed_eas.append(int(x, 16))
                else:
                    # Might be a function name, try to find it
                    found = db_find_function_by_name(conn, x)
                    if found:
                        processed_eas.extend([f["func_ea"] for f in found])
            except (ValueError, TypeError):
                # Not a valid EA, try as function name
                found = db_find_function_by_name(conn, x)
                if found:
                    processed_eas.extend([f["func_ea"] for f in found])
        else:
            processed_eas.append(int(x))
    
    if not processed_eas:
        return {}
    
    rows = db_get_function_rows(conn, processed_eas)
    result = {}
    for row in rows:
        ea = row["func_ea"]
        features_str = row.get("features_json")
        if features_str:
            try:
                result[ea] = json.loads(features_str)
            except Exception:
                result[ea] = {}
        else:
            result[ea] = None
    return result


def db_get_neighbors(conn: sqlite3.Connection, func_eas: List[int], 
                     direction: str, depth: int, limit: int) -> List[int]:
    """Get neighbor function EAs (callers/callees)."""
    if not func_eas or depth <= 0:
        return []
    
    seen = set(func_eas)
    frontier = set(func_eas)
    
    for _ in range(depth):
        if not frontier:
            break
        nxt = set()
        for ea in frontier:
            if direction in ("out", "both"):
                cur = conn.execute(
                    "SELECT dst_ea FROM edges WHERE src_ea=? AND kind='call' LIMIT ?",
                    (ea, limit)
                )
                for (dst,) in cur.fetchall():
                    d = int(dst)
                    if d not in seen:
                        seen.add(d)
                        nxt.add(d)
            
            if direction in ("in", "both"):
                cur = conn.execute(
                    "SELECT src_ea FROM edges WHERE dst_ea=? AND kind='call' LIMIT ?",
                    (ea, limit)
                )
                for (src,) in cur.fetchall():
                    s = int(src)
                    if s not in seen:
                        seen.add(s)
                        nxt.add(s)
        frontier = nxt
    
    return list(seen)[:limit]


def db_find_paths(conn: sqlite3.Connection, src_ea: int, dst_ea: int, 
                  max_depth: int, max_paths: int) -> List[List[int]]:
    """BFS to find call paths from src to dst. Optimized with batch queries."""
    if src_ea == dst_ea:
        return [[src_ea]]
    
    if max_depth <= 0:
        return []
    
    paths = []
    # Use BFS with path tracking (simpler and more efficient)
    # Queue: (current_ea, path_so_far)
    queue = deque([(src_ea, [src_ea])])
    seen = set()  # Track visited (ea, depth) to avoid cycles
    
    while queue and len(paths) < max_paths:
        current, path = queue.popleft()
        
        if current == dst_ea:
            paths.append(path)
            continue
        
        if len(path) >= max_depth:
            continue
        
        # Avoid cycles: check if we've visited this node at this depth
        depth_key = (current, len(path))
        if depth_key in seen:
            continue
        seen.add(depth_key)
        
        # Batch query: get all callees for current node
        cur = conn.execute(
            "SELECT dst_ea FROM edges WHERE src_ea=? AND kind='call'",
            (current,)
        )
        next_eas = [int(row[0]) for row in cur.fetchall()]
        
        for next_ea in next_eas:
            # Avoid cycles in path
            if next_ea not in path:
                queue.append((next_ea, path + [next_ea]))
    
    return paths[:max_paths]


def db_reverse_bfs_to_sources(conn: sqlite3.Connection, sink_eas: Set[int], 
                               candidate_sources: Set[int], max_depth: int, 
                               max_hits: int) -> List[List[int]]:
    """Reverse BFS from sinks backward to find paths to any candidate source.
    
    Returns paths in forward order: [source, ..., sink]
    """
    if not sink_eas or not candidate_sources or max_depth <= 0:
        return []
    
    paths = []
    # Reverse BFS: start from sinks, go backward (find callers)
    queue = deque([(sink, 0, [sink]) for sink in sink_eas])
    visited_at_depth = {0: set(sink_eas)}
    
    while queue and len(paths) < max_hits:
        current, depth, path = queue.popleft()
        
        # Check if we reached any candidate source
        if current in candidate_sources:
            paths.append(path[::-1])  # Reverse to get source->sink order
            continue
        
        if depth >= max_depth:
            continue
        
        # Get callers (reverse direction: who calls current?)
        next_depth = depth + 1
        if next_depth not in visited_at_depth:
            visited_at_depth[next_depth] = set()
        
        cur = conn.execute(
            "SELECT src_ea FROM edges WHERE dst_ea=? AND kind='call'",
            (current,)
        )
        for (caller_ea,) in cur.fetchall():
            caller = int(caller_ea)
            # Avoid cycles and revisiting at same depth
            if caller in visited_at_depth.get(next_depth, set()):
                continue
            
            # Check if seen at earlier depth
            seen_earlier = False
            for d in range(next_depth):
                if caller in visited_at_depth.get(d, set()):
                    seen_earlier = True
                    break
            
            if not seen_earlier and caller not in path:  # Avoid cycles in path
                visited_at_depth[next_depth].add(caller)
                queue.append((caller, next_depth, path + [caller]))
    
    return paths[:max_hits]


def find_ls_chains(conn: sqlite3.Connection, L_eas: List[int], S_eas: List[int],
                   depth: int = 6, max_chains: int = 10) -> List[Dict[str, Any]]:
    """Find chains from source functions (L) to sink functions (S).
    
    Returns list of {src_ea, dst_ea, path, path_length}
    """
    L_set = set(L_eas)
    S_set = set(S_eas)
    
    if not L_set or not S_set:
        return []
    
    chains = []
    
    # Strategy 1: Reverse BFS from sinks (usually faster - sinks are fewer)
    reverse_paths = db_reverse_bfs_to_sources(conn, S_set, L_set, depth, max_chains * 2)
    
    for path in reverse_paths:
        if len(path) >= 2:
            chains.append({
                "src_ea": path[0],
                "dst_ea": path[-1],
                "path": path,
                "path_length": len(path) - 1  # number of edges
            })
    
    # Strategy 2: Forward BFS from sources if we need more chains
    if len(chains) < max_chains:
        for src in L_eas[:5]:  # Limit forward search to avoid explosion
            for dst in S_eas[:5]:
                forward_paths = db_find_paths(conn, src, dst, depth, max_chains - len(chains))
                for path in forward_paths:
                    if len(path) >= 2:
                        # Check if we already have this chain
                        existing = any(
                            c["src_ea"] == path[0] and c["dst_ea"] == path[-1] 
                            for c in chains
                        )
                        if not existing:
                            chains.append({
                                "src_ea": path[0],
                                "dst_ea": path[-1],
                                "path": path,
                                "path_length": len(path) - 1
                            })
                            if len(chains) >= max_chains:
                                break
                if len(chains) >= max_chains:
                    break
    
    # Rank chains: shorter paths first, then by triage score
    # Get triage scores for functions in paths
    if chains:
        all_func_eas = set()
        for chain in chains:
            all_func_eas.update(chain["path"])
        
        # Get triage scores
        scores = {}
        if all_func_eas:
            placeholders = ",".join("?" * len(all_func_eas))
            cur = conn.execute(
                f"SELECT func_ea, triage_score FROM functions WHERE func_ea IN ({placeholders})",
                list(all_func_eas)
            )
            for row in cur.fetchall():
                scores[int(row[0])] = row[1] or 0
        
        # Score each chain: sum of scores, prefer shorter paths
        for chain in chains:
            path_score = sum(scores.get(ea, 0) for ea in chain["path"])
            chain["score"] = path_score
            chain["avg_score"] = path_score / len(chain["path"]) if chain["path"] else 0
        
        # Sort: shorter paths first, then by score
        chains.sort(key=lambda c: (c["path_length"], -c["score"]))
    
    return chains[:max_chains]


# -----------------------------
# IDAAPI Helpers
# -----------------------------
def _ea_hex(ea: int) -> str:
    return f"0x{ea:X}"


def _safe_disasm(ea: int) -> str:
    line = ida_lines.generate_disasm_line(ea, 0)
    if not line:
        return ""
    return ida_lines.tag_remove(line).strip()


def ida_get_disasm_head_tail(func_ea: int, head: int, tail: int) -> Dict[str, Any]:
    """Get head and tail disassembly for a function."""
    func = ida_funcs.get_func(func_ea)
    if not func:
        return {"head": [], "tail": []}
    
    insns = []
    ea = func.start_ea
    while ea != idaapi.BADADDR and ea < func.end_ea:
        insns.append(ea)
        ea = idaapi.next_head(ea, func.end_ea)
    
    head_insns = insns[:head]
    tail_insns = insns[-tail:] if len(insns) > head else []
    
    def dump(eas: List[int]) -> List[str]:
        out = []
        for e in eas:
            d = _safe_disasm(e)
            if d:
                out.append(f"{_ea_hex(e)}: {d}")
        return out
    
    return {
        "head": dump(head_insns),
        "tail": dump(tail_insns),
        "total_insns": len(insns),
    }


def ida_get_disasm_callsites(func_ea: int, sinks: List[str], 
                             window: int, max_sites: int) -> List[Dict[str, Any]]:
    """Get disassembly windows around calls to sink functions."""
    func = ida_funcs.get_func(func_ea)
    if not func:
        return []
    
    sinks_lower = [s.lower() for s in sinks]
    sites = []
    
    ea = func.start_ea
    while ea != idaapi.BADADDR and ea < func.end_ea and len(sites) < max_sites:
        if idaapi.is_call_insn(ea):
            for x in idautils.XrefsFrom(ea, 0):
                if x.type in (idaapi.fl_CN, idaapi.fl_CF):
                    name = ida_name.get_name(x.to) or ""
                    if any(sink in name.lower() for sink in sinks_lower):
                        # Get window around this call
                        window_start = ea
                        for _ in range(window):
                            prev = idaapi.prev_head(window_start, func.start_ea)
                            if prev == idaapi.BADADDR:
                                break
                            window_start = prev
                        
                        window_end = ea
                        for _ in range(window):
                            nxt = idaapi.next_head(window_end, func.end_ea)
                            if nxt == idaapi.BADADDR or nxt >= func.end_ea:
                                break
                            window_end = nxt
                        
                        disasm_lines = []
                        curr = window_start
                        while curr != idaapi.BADADDR and curr <= window_end:
                            d = _safe_disasm(curr)
                            if d:
                                marker = " <-- CALL" if curr == ea else ""
                                disasm_lines.append(f"{_ea_hex(curr)}: {d}{marker}")
                            curr = idaapi.next_head(curr, func.end_ea)
                        
                        sites.append({
                            "call_ea": _ea_hex(ea),
                            "target_name": name,
                            "window": disasm_lines,
                        })
        ea = idaapi.next_head(ea, func.end_ea)
    
    return sites[:max_sites]


def ida_get_strings_in_func(func_ea: int, limit: int) -> List[Dict[str, Any]]:
    """Get strings referenced in a function."""
    func = ida_funcs.get_func(func_ea)
    if not func:
        return []
    
    strings = []
    seen = set()
    
    # Scan function for string references
    ea = func.start_ea
    while ea != idaapi.BADADDR and ea < func.end_ea and len(strings) < limit:
        # Check if this instruction references a string
        for x in idautils.XrefsFrom(ea, 0):
            if x.type == idaapi.fl_F:
                str_ea = int(x.to)
                if str_ea in seen:
                    continue
                seen.add(str_ea)
                
                # Try to get string value
                str_val = idaapi.get_strlit_contents(str_ea)
                if str_val:
                    try:
                        str_text = str_val.decode('utf-8', errors='replace')
                        if len(str_text) > 0:
                            strings.append({
                                "ea": _ea_hex(str_ea),
                                "value": str_text[:200],  # truncate long strings
                                "ref_ea": _ea_hex(ea),
                            })
                    except Exception:
                        pass
        ea = idaapi.next_head(ea, func.end_ea)
    
    return strings[:limit]


def ida_get_xrefs_to_func(func_ea: int, limit: int) -> List[Dict[str, Any]]:
    """Get xrefs to a function."""
    xrefs = []
    for x in idautils.XrefsTo(func_ea, 0):
        if len(xrefs) >= limit:
            break
        caller_func = ida_funcs.get_func(x.frm)
        if caller_func:
            caller_name = ida_funcs.get_func_name(caller_func.start_ea) or "unknown"
            xrefs.append({
                "from_ea": _ea_hex(x.frm),
                "from_func": caller_name,
                "from_func_ea": _ea_hex(caller_func.start_ea),
            })
    return xrefs[:limit]


def ida_get_xrefs_from_func(func_ea: int, limit: int) -> List[Dict[str, Any]]:
    """Get xrefs from a function."""
    func = ida_funcs.get_func(func_ea)
    if not func:
        return []
    
    xrefs = []
    ea = func.start_ea
    while ea != idaapi.BADADDR and ea < func.end_ea and len(xrefs) < limit:
        for x in idautils.XrefsFrom(ea, 0):
            if x.type in (idaapi.fl_CN, idaapi.fl_CF):
                target_name = ida_name.get_name(x.to) or "unknown"
                xrefs.append({
                    "to_ea": _ea_hex(x.to),
                    "to_name": target_name,
                    "from_ea": _ea_hex(ea),
                })
        ea = idaapi.next_head(ea, func.end_ea)
    
    return xrefs[:limit]


def ida_get_hex_bytes(ea: int, size: int) -> Dict[str, Any]:
    """Get hex dump of bytes at EA."""
    if size > 256:
        size = 256  # hard cap
    
    bytes_data = idaapi.get_bytes(ea, size)
    if not bytes_data:
        return {"ea": _ea_hex(ea), "hex": "", "error": "failed_to_read"}
    
    hex_str = bytes_data.hex()
    # Format as hex dump
    hex_lines = []
    for i in range(0, len(hex_str), 32):
        chunk = hex_str[i:i+32]
        hex_lines.append(" ".join(chunk[j:j+2] for j in range(0, len(chunk), 2)))
    
    return {
        "ea": _ea_hex(ea),
        "hex": "\n".join(hex_lines),
        "size": len(bytes_data),
    }


# -----------------------------
# Evidence Pack Builder
# -----------------------------
def build_evidence_pack(conn: sqlite3.Connection, func_eas: List[int], 
                       include_disasm: bool = False, include_strings: bool = False,
                       include_full_disasm: bool = False,
                       budget: Budget = None) -> Dict[str, Any]:
    """Build compact evidence pack for given function EAs."""
    if budget is None:
        budget = Budget()
    
    rows = db_get_function_rows(conn, func_eas)
    features_map = db_get_features(conn, func_eas)
    
    evidence = {
        "functions": [],
        "total_functions": len(rows),
    }
    
    for row in rows:
        ea = row["func_ea"]
        func_evidence = {
            "func_ea": _ea_hex(ea),
            "name": row["name"],
            "segment": row["segment"],
            "insn_count": row["insn_count"],
            "bb_count": row["bb_count"],
            "caller_count": row["caller_count"],
            "callee_count": row["callee_count"],
            "triage_score": row["triage_score"],
            "has_alloc": row["has_alloc"],
            "has_write": row["has_write"],
            "has_exec": row["has_exec"],
            "has_file": row["has_file"],
            "has_auth": row["has_auth"],
        }
        
        # Add features if available
        features = features_map.get(ea)
        if features:
            func_evidence["features"] = features
        
        # Add disasm if requested
        if include_disasm and budget.can_fetch_ida():
            budget.used_ida_fetches += 1
            if include_full_disasm:
                # Get full disassembly for LLM analysis
                func = ida_funcs.get_func(ea)
                if func:
                    full_disasm = []
                    func_ea = func.start_ea
                    line_count = 0
                    while func_ea != idaapi.BADADDR and func_ea < func.end_ea and line_count < 200:
                        d = _safe_disasm(func_ea)
                        if d:
                            full_disasm.append(f"{_ea_hex(func_ea)}: {d}")
                            line_count += 1
                        func_ea = idaapi.next_head(func_ea, func.end_ea)
                    if budget.can_add_disasm(line_count):
                        budget.used_disasm_lines += line_count
                        func_evidence["disasm"] = {
                            "full": full_disasm,
                            "total_insns": line_count
                        }
            else:
                disasm = ida_get_disasm_head_tail(ea, head=20, tail=10)
                if budget.can_add_disasm(len(disasm.get("head", [])) + len(disasm.get("tail", []))):
                    budget.used_disasm_lines += len(disasm.get("head", [])) + len(disasm.get("tail", []))
                    func_evidence["disasm"] = disasm
        
        # Add strings if requested
        if include_strings and budget.can_fetch_ida():
            budget.used_ida_fetches += 1
            strings = ida_get_strings_in_func(ea, limit=budget.max_strings_per_func)
            func_evidence["strings"] = strings
        
        evidence["functions"].append(func_evidence)
    
    return evidence


# -----------------------------
# Action Executor
# -----------------------------
def _format_action_result(action_type: str, args: Dict[str, Any], result: Dict[str, Any]) -> str:
    """Format a concise result summary for an action."""
    if "error" in result:
        return f"❌ {result.get('error', 'unknown error')}"
    
    if action_type == "db.search_cards":
        count = result.get("count", len(result.get("results", [])))
        if count > 0:
            funcs = result.get("results", [])[:3]
            names = [f.get("name", "unknown") for f in funcs]
            summary = f"✓ Found {count} function(s)"
            if names:
                summary += f": {', '.join(names)}"
                if count > 3:
                    summary += f" and {count - 3} more"
            return summary
        else:
            return "✗ No functions found"
    
    elif action_type == "db.get_function_rows":
        count = result.get("count", len(result.get("results", [])))
        if count > 0:
            funcs = result.get("results", [])[:2]
            names = [f.get("name", "unknown") for f in funcs]
            return f"✓ Got {count} function(s): {', '.join(names) if names else 'unknown'}"
        else:
            return "✗ No functions found"
    
    elif action_type == "db.find_function_by_name":
        count = result.get("count", len(result.get("results", [])))
        if count > 0:
            funcs = result.get("results", [])[:2]
            names = [f.get("name", "unknown") for f in funcs]
            eas = [f"0x{f.get('func_ea', 0):X}" for f in funcs]
            return f"✓ Found {count} function(s): {', '.join(names)} ({', '.join(eas)})"
        else:
            return "✗ Function not found"
    
    elif action_type == "db.get_features":
        features = result.get("results", {})
        count = len([f for f in features.values() if f is not None])
        if count > 0:
            return f"✓ Retrieved features for {count} function(s)"
        else:
            return "✗ No features available"
    
    elif action_type == "db.get_neighbors":
        count = result.get("count", len(result.get("results", [])))
        if count > 0:
            return f"✓ Found {count} neighbor function(s)"
        else:
            return "✗ No neighbors found"
    
    elif action_type == "ida.get_disasm_head_tail":
        disasm = result.get("results", {})
        head_lines = len(disasm.get("head", []))
        tail_lines = len(disasm.get("tail", []))
        if head_lines > 0 or tail_lines > 0:
            return f"✓ Got {head_lines + tail_lines} disasm lines"
        else:
            return "✗ No disassembly available"
    
    elif action_type == "ida.get_full_disasm":
        disasm_result = result.get("results", {})
        lines = disasm_result.get("total_lines", len(disasm_result.get("disasm", [])))
        func_name = disasm_result.get("func_name", "unknown")
        if lines > 0:
            return f"✓ Got {lines} disasm lines for {func_name}"
        else:
            return "✗ No disassembly available"
    
    elif action_type == "ida.get_disasm_callsites":
        count = result.get("count", len(result.get("results", [])))
        if count > 0:
            sites = result.get("results", [])[:2]
            sinks = [s.get("target_name", "unknown") for s in sites]
            summary = f"✓ Found {count} callsite(s)"
            if sinks:
                summary += f": {', '.join(sinks)}"
            return summary
        else:
            return "✗ No callsites found"
    
    elif action_type == "ida.get_strings_in_func":
        count = result.get("count", len(result.get("results", [])))
        if count > 0:
            return f"✓ Found {count} string(s)"
        else:
            return "✗ No strings found"
    
    elif action_type in ("ida.get_xrefs_to_func", "ida.get_xrefs_from_func"):
        count = result.get("count", len(result.get("results", [])))
        if count > 0:
            return f"✓ Found {count} xref(s)"
        else:
            return "✗ No xrefs found"
    
    elif action_type == "db.find_paths":
        paths = result.get("results", [])
        count = len(paths)
        if count > 0:
            # Show path length for first path
            first_path_len = len(paths[0]) if paths else 0
            return f"✓ Found {count} path(s), first path: {first_path_len} functions"
        else:
            return "✗ No paths found"
    
    elif action_type == "db.find_ls_chains":
        chains = result.get("results", [])
        count = len(chains)
        if count > 0:
            # Show path length for first chain
            first_chain_len = chains[0].get("path_length", 0) if chains else 0
            return f"✓ Found {count} chain(s), first chain: {first_chain_len} hops"
        else:
            return "✗ No chains found"
    
    elif action_type == "llm.enrich_features":
        count = result.get("count", len(result.get("results", {})))
        if count > 0:
            return f"✓ Enriched {count} function(s) with LLM features"
        else:
            return "✗ Enrichment failed"
    
    return ""


def execute_action(conn: sqlite3.Connection, action: Dict[str, Any], 
                  budget: Budget, ui_cb: Optional[Callable] = None) -> Dict[str, Any]:
    """Execute a single action and return results."""
    action_type = action.get("type")
    args = action.get("args", {})
    
    # Track timing for tool execution
    start_time = time.time()
    result = None
    
    try:
        if action_type == "db.search_cards":
            if not budget.can_query_db():
                result = {"error": "budget_exceeded", "type": "db_query"}
            else:
                budget.used_db_queries += 1
                results = db_search_cards(conn, args.get("fts_query", ""), 
                                         args.get("filters", {}), args.get("limit", 10))
                result = {"results": results, "count": len(results)}
        
        elif action_type == "db.get_function_rows":
            if not budget.can_query_db():
                result = {"error": "budget_exceeded", "type": "db_query"}
            else:
                budget.used_db_queries += 1
                func_eas = args.get("func_eas", [])
                # Handle both EA integers and function names
                processed_eas = []
                for x in func_eas:
                    if isinstance(x, str):
                        # Try to parse as hex address
                        try:
                            if x.startswith("0x") or x.startswith("0X"):
                                processed_eas.append(int(x, 16))
                            else:
                                # Might be a function name, try to find it
                                found = db_find_function_by_name(conn, x)
                                if found:
                                    processed_eas.extend([f["func_ea"] for f in found])
                        except (ValueError, TypeError):
                            # Not a valid EA, try as function name
                            found = db_find_function_by_name(conn, x)
                            if found:
                                processed_eas.extend([f["func_ea"] for f in found])
                    else:
                        processed_eas.append(int(x))
                
                if processed_eas:
                    results = db_get_function_rows(conn, processed_eas)
                else:
                    results = []
                result = {"results": results, "count": len(results)}
        
        elif action_type == "db.find_function_by_name":
            if not budget.can_query_db():
                result = {"error": "budget_exceeded", "type": "db_query"}
            else:
                budget.used_db_queries += 1
                func_name = args.get("func_name", "")
                results = db_find_function_by_name(conn, func_name)
                result = {"results": results, "count": len(results)}
        
        elif action_type == "db.get_features":
            if not budget.can_query_db():
                result = {"error": "budget_exceeded", "type": "db_query"}
            else:
                budget.used_db_queries += 1
                func_eas = args.get("func_eas", [])
                # Handle both EAs and function names
                features = db_get_features(conn, func_eas)
                result = {"results": features, "count": len(features)}
        
        elif action_type == "db.get_neighbors":
            if not budget.can_query_db():
                result = {"error": "budget_exceeded", "type": "db_query"}
            else:
                budget.used_db_queries += 1
                func_eas = [int(x) for x in args.get("func_eas", [])]
                direction = args.get("direction", "both")
                depth = args.get("depth", 1)
                limit = args.get("limit", 20)
                neighbors = db_get_neighbors(conn, func_eas, direction, depth, limit)
                result = {"results": [{"func_ea": _ea_hex(ea)} for ea in neighbors], "count": len(neighbors)}
        
        elif action_type == "db.find_paths":
            if not budget.can_query_db():
                result = {"error": "budget_exceeded", "type": "db_query"}
            else:
                budget.used_db_queries += 1
                src_ea = int(args.get("src_ea", 0))
                dst_ea = int(args.get("dst_ea", 0))
                max_depth = args.get("max_depth", 6)  # Default to 6 for multi-hop
                max_paths = args.get("max_paths", 5)
                paths = db_find_paths(conn, src_ea, dst_ea, max_depth, max_paths)
                result = {"results": [[_ea_hex(ea) for ea in path] for path in paths], "count": len(paths)}
        
        elif action_type == "db.find_ls_chains":
            if not budget.can_query_db():
                result = {"error": "budget_exceeded", "type": "db_query"}
            else:
                budget.used_db_queries += 1
                L_eas = [int(x) for x in args.get("source_eas", [])]
                S_eas = [int(x) for x in args.get("sink_eas", [])]
                depth = args.get("depth", 6)
                max_chains = args.get("max_chains", 10)
                chains = find_ls_chains(conn, L_eas, S_eas, depth, max_chains)
                # Format chains for return
                formatted_chains = []
                for chain in chains:
                    formatted_chains.append({
                        "src_ea": _ea_hex(chain["src_ea"]),
                        "dst_ea": _ea_hex(chain["dst_ea"]),
                        "path": [_ea_hex(ea) for ea in chain["path"]],
                        "path_length": chain["path_length"],
                        "score": chain.get("score", 0)
                    })
                result = {"results": formatted_chains, "count": len(formatted_chains)}
        
        elif action_type == "ida.get_disasm_head_tail":
            if not budget.can_fetch_ida():
                result = {"error": "budget_exceeded", "type": "ida_fetch"}
            else:
                budget.used_ida_fetches += 1
                func_ea = int(args.get("func_ea", 0))
                head = args.get("head", 20)
                tail = args.get("tail", 10)
                disasm = ida_get_disasm_head_tail(func_ea, head, tail)
                lines = len(disasm.get("head", [])) + len(disasm.get("tail", []))
                if budget.can_add_disasm(lines):
                    budget.used_disasm_lines += lines
                    result = {"results": disasm}
                else:
                    result = {"error": "disasm_budget_exceeded"}
        
        elif action_type == "ida.get_full_disasm":
            if not budget.can_fetch_ida():
                result = {"error": "budget_exceeded", "type": "ida_fetch"}
            else:
                budget.used_ida_fetches += 1
                func_ea_arg = args.get("func_ea", 0)
                # Handle both EA and function name
                if isinstance(func_ea_arg, str):
                    found = db_find_function_by_name(conn, func_ea_arg)
                    if not found:
                        result = {"error": f"Function '{func_ea_arg}' not found"}
                    else:
                        func_ea = found[0]["func_ea"]
                        func = ida_funcs.get_func(func_ea)
                        if not func:
                            result = {"error": f"Function at 0x{func_ea:X} not found"}
                        else:
                            full_disasm = []
                            func_ea_curr = func.start_ea
                            line_count = 0
                            max_lines = args.get("max_lines", 200)
                            
                            while func_ea_curr != idaapi.BADADDR and func_ea_curr < func.end_ea and line_count < max_lines:
                                d = _safe_disasm(func_ea_curr)
                                if d:
                                    full_disasm.append(f"{_ea_hex(func_ea_curr)}: {d}")
                                    line_count += 1
                                func_ea_curr = idaapi.next_head(func_ea_curr, func.end_ea)
                            
                            if budget.can_add_disasm(line_count):
                                budget.used_disasm_lines += line_count
                                result = {
                                    "results": {
                                        "func_ea": _ea_hex(func_ea),
                                        "func_name": ida_funcs.get_func_name(func.start_ea) or "unknown",
                                        "disasm": full_disasm,
                                        "total_lines": line_count
                                    }
                                }
                            else:
                                result = {"error": "disasm_budget_exceeded"}
                else:
                    func_ea = int(func_ea_arg)
                    func = ida_funcs.get_func(func_ea)
                    if not func:
                        result = {"error": f"Function at 0x{func_ea:X} not found"}
                    else:
                        full_disasm = []
                        func_ea_curr = func.start_ea
                        line_count = 0
                        max_lines = args.get("max_lines", 200)
                        
                        while func_ea_curr != idaapi.BADADDR and func_ea_curr < func.end_ea and line_count < max_lines:
                            d = _safe_disasm(func_ea_curr)
                            if d:
                                full_disasm.append(f"{_ea_hex(func_ea_curr)}: {d}")
                                line_count += 1
                            func_ea_curr = idaapi.next_head(func_ea_curr, func.end_ea)
                        
                        if budget.can_add_disasm(line_count):
                            budget.used_disasm_lines += line_count
                            result = {
                                "results": {
                                    "func_ea": _ea_hex(func_ea),
                                    "func_name": ida_funcs.get_func_name(func.start_ea) or "unknown",
                                    "disasm": full_disasm,
                                    "total_lines": line_count
                                }
                            }
                        else:
                            result = {"error": "disasm_budget_exceeded"}
        
        elif action_type == "ida.get_disasm_callsites":
            if not budget.can_fetch_ida():
                result = {"error": "budget_exceeded", "type": "ida_fetch"}
            else:
                budget.used_ida_fetches += 1
                func_ea = int(args.get("func_ea", 0))
                sinks = args.get("sinks", [])
                window = args.get("window", 5)
                max_sites = args.get("max_sites", 10)
                sites = ida_get_disasm_callsites(func_ea, sinks, window, max_sites)
                total_lines = sum(len(s.get("window", [])) for s in sites)
                if budget.can_add_disasm(total_lines):
                    budget.used_disasm_lines += total_lines
                    result = {"results": sites, "count": len(sites)}
                else:
                    result = {"error": "disasm_budget_exceeded"}
        
        elif action_type == "ida.get_strings_in_func":
            if not budget.can_fetch_ida():
                result = {"error": "budget_exceeded", "type": "ida_fetch"}
            else:
                budget.used_ida_fetches += 1
                func_ea = int(args.get("func_ea", 0))
                limit = args.get("limit", 20)
                strings = ida_get_strings_in_func(func_ea, limit)
                result = {"results": strings, "count": len(strings)}
        
        elif action_type == "ida.get_xrefs_to_func":
            if not budget.can_fetch_ida():
                result = {"error": "budget_exceeded", "type": "ida_fetch"}
            else:
                budget.used_ida_fetches += 1
                func_ea = int(args.get("func_ea", 0))
                limit = args.get("limit", 50)
                xrefs = ida_get_xrefs_to_func(func_ea, limit)
                result = {"results": xrefs, "count": len(xrefs)}
        
        elif action_type == "ida.get_xrefs_from_func":
            if not budget.can_fetch_ida():
                result = {"error": "budget_exceeded", "type": "ida_fetch"}
            else:
                budget.used_ida_fetches += 1
                func_ea = int(args.get("func_ea", 0))
                limit = args.get("limit", 50)
                xrefs = ida_get_xrefs_from_func(func_ea, limit)
                result = {"results": xrefs, "count": len(xrefs)}
        
        elif action_type == "ida.get_hex_bytes":
            if not budget.can_fetch_ida():
                result = {"error": "budget_exceeded", "type": "ida_fetch"}
            else:
                budget.used_ida_fetches += 1
                ea = int(args.get("ea", 0))
                size = args.get("size", 64)
                hex_dump = ida_get_hex_bytes(ea, size)
                result = {"results": hex_dump}
        
        elif action_type == "llm.enrich_features":
            if not budget.can_call_llm():
                result = {"error": "budget_exceeded", "type": "llm_call"}
            else:
                budget.used_llm_calls += 1
                func_eas = [int(x) for x in args.get("func_eas", [])]
                if not func_eas:
                    result = {"error": "no_functions"}
                else:
                    # Build LLM packages (similar to extract.py)
                    pkgs = []
                    for ea in func_eas:
                        func = ida_funcs.get_func(ea)
                        if not func:
                            continue
                        name = ida_funcs.get_func_name(func.start_ea)
                        
                        # Collect called names
                        called_names = []
                        seen_names = set()
                        func_ea = func.start_ea
                        while func_ea != idaapi.BADADDR and func_ea < func.end_ea:
                            if idaapi.is_call_insn(func_ea):
                                for x in idautils.XrefsFrom(func_ea, 0):
                                    if x.type in (idaapi.fl_CN, idaapi.fl_CF):
                                        nm = ida_name.get_name(x.to) or ""
                                        nm = nm.strip()
                                        if nm and nm not in seen_names:
                                            seen_names.add(nm)
                                            called_names.append(nm)
                                            if len(called_names) >= 60:
                                                break
                            func_ea = idaapi.next_head(func_ea, func.end_ea)
                        
                        # Get callers/callees (simplified)
                        callers = []
                        for x in idautils.XrefsTo(func.start_ea, 0):
                            frm_func = ida_funcs.get_func(x.frm)
                            if frm_func:
                                callers.append(_ea_hex(frm_func.start_ea))
                                if len(callers) >= 20:
                                    break
                        
                        callees = []
                        seen_callees = set()
                        func_ea = func.start_ea
                        while func_ea != idaapi.BADADDR and func_ea < func.end_ea:
                            if idaapi.is_call_insn(func_ea):
                                for x in idautils.XrefsFrom(func_ea, 0):
                                    if x.type in (idaapi.fl_CN, idaapi.fl_CF):
                                        to_ea = int(x.to)
                                        if to_ea != idaapi.BADADDR and to_ea not in seen_callees:
                                            seen_callees.add(to_ea)
                                            callees.append(_ea_hex(to_ea))
                                            if len(callees) >= 20:
                                                break
                            func_ea = idaapi.next_head(func_ea, func.end_ea)
                        
                        pkg = {
                            "func_name": name,
                            "entry_ea": _ea_hex(func.start_ea),
                            "end_ea": _ea_hex(func.end_ea),
                            "segment": ida_segment.get_segm_name(ida_segment.getseg(func.start_ea)) or "",
                            "called_names": called_names,
                            "callers": callers,
                            "callees": callees,
                            "disasm": ida_get_disasm_head_tail(ea, head=40, tail=20),
                        }
                        pkgs.append(pkg)
                    
                    if not pkgs:
                        result = {"error": "no_valid_functions"}
                    else:
                        # Call LLM
                        try:
                            result_map, metrics = hexlen_extract.extract_features_batch(pkgs)
                            # Log metrics for chat enrichment
                            elapsed = metrics.get("elapsed_seconds", 0)
                            total_tokens = metrics.get("total_tokens", 0)
                            if ui_cb and elapsed > 0.01:
                                ui_cb(f"    ⏱️ LLM enrichment: {elapsed:.2f}s, {total_tokens} tokens")
                            # Store to DB
                            now = int(time.time())
                            for pkg in pkgs:
                                ea_int = int(pkg["entry_ea"], 16)
                                features = result_map.get(ea_int, {})
                                conn.execute(
                                    "UPDATE functions SET features_json=?, updated_at=? WHERE func_ea=?",
                                    (json.dumps(features), now, ea_int)
                                )
                            conn.commit()
                            result = {"results": result_map, "count": len(result_map)}
                        except Exception as e:
                            result = {"error": str(e)}
        
        else:
            result = {"error": f"unknown_action_type: {action_type}"}
    
    except Exception as e:
        result = {"error": str(e), "traceback": traceback.format_exc()}
    
    finally:
        # Report timing for tool execution
        elapsed = time.time() - start_time
        if ui_cb and elapsed > 0.01:  # Only report if > 10ms
            # Format action type for display
            action_display = action_type.replace("db.", "").replace("ida.", "").replace("llm.", "")
            ui_cb(f"    ⏱️ {action_display}: {elapsed:.2f}s")
    
    return result


# -----------------------------
# Evidence Sufficiency Checks
# -----------------------------
def has_enough_evidence(goal: str, evidence: Dict[str, Any]) -> bool:
    """Deterministic check: do we have enough evidence for the goal?"""
    functions = evidence.get("functions", [])
    if not functions:
        return False
    
    if goal == "vuln.buffer":
        # Need: writes/SINK_MEMWRITE + allocs/buffer hints + bounds_checks none/unknown
        has_write_sink = False
        has_alloc_hint = False
        has_bounds_issue = False
        
        for func in functions:
            if func.get("has_write") or (func.get("features", {}).get("writes")):
                has_write_sink = True
            if func.get("has_alloc") or (func.get("features", {}).get("allocs")):
                has_alloc_hint = True
            features = func.get("features", {})
            bounds = features.get("bounds_checks", "unknown")
            if bounds in ("none", "unknown", "partial"):
                has_bounds_issue = True
        
        return has_write_sink and (has_alloc_hint or has_bounds_issue)
    
    elif goal == "vuln.injection":
        # Need: source + string build + exec sink
        has_source = False
        has_string_build = False
        has_exec_sink = False
        
        for func in functions:
            features = func.get("features", {})
            if features.get("input_sources"):
                has_source = True
            if features.get("string_ops") or "format" in str(features.get("string_ops", [])).lower():
                has_string_build = True
            if func.get("has_exec") or features.get("exec_calls"):
                has_exec_sink = True
        
        return has_source and has_string_build and has_exec_sink
    
    elif goal == "vuln.auth":
        # Need: auth checks or privilege ops
        for func in functions:
            if func.get("has_auth") or func.get("features", {}).get("auth_checks"):
                return True
        return False
    
    elif goal in ("malware.persistence", "malware.c2", "malware.evasion"):
        # Need: attack signals or strong API evidence
        for func in functions:
            features = func.get("features", {})
            attack = features.get("attack", {})
            if attack.get("signals") or attack.get("persistence") or attack.get("c2") or attack.get("evasion"):
                return True
            # Also check for strong API patterns
            if goal == "malware.c2" and (func.get("has_file") or "socket" in str(func.get("called_names", "")).lower()):
                return True
        return False
    
    elif goal == "general.triage":
        # Always enough for general triage
        return len(functions) > 0
    
    return False


# -----------------------------
# LLM Planner & Answerer
# -----------------------------
def _llm_load_config() -> Dict[str, Any]:
    """Load LLM configuration from config file or environment."""
    config = {
        "provider": "openai",
        "openai_api_key": None,
        "openai_model_chat": "gpt-5",  # Model for chat/planning/answering
        "openai_model_features": "gpt-4o-mini",  # Model for feature extraction (not used in chat.py)
        "openai_model": "gpt-5",  # Legacy fallback for chat
        "ollama_base_url": "http://localhost:11434",
        "ollama_model_chat": "llama3.2",  # Ollama model for chat/planning/answering
        "ollama_model_features": "llama3.2",  # Ollama model for feature extraction (not used in chat.py)
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
        base_url = config.get("ollama_base_url", "http://localhost:11434")
        # Ollama uses OpenAI-compatible API
        client = OpenAI(
            base_url=f"{base_url}/v1",
            api_key="ollama"  # Ollama doesn't require a real API key
        )
        # Use chat model for planning and answering
        model = config.get("ollama_model_chat") or config.get("ollama_model", "llama3.2")
        return client, "ollama", model
    else:
        # Default to OpenAI
        api_key = config.get("openai_api_key") or os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OpenAI API key not found. Set OPENAI_API_KEY environment variable or configure in hexlens_config.json")
        client = OpenAI(api_key=api_key)
        # Use chat model for planning and answering
        model = config.get("openai_model_chat") or config.get("openai_model", "gpt-5")
        return client, "openai", model


def llm_plan(user_query: str, evidence_so_far: Dict[str, Any], 
             budget: Budget, attempted_actions: List[Dict[str, Any]] = None,
             ui_cb: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """Call LLM to produce a plan (goal + actions)."""
    config = _llm_load_config()
    client, provider, model = _llm_get_client(config)
    
    if attempted_actions is None:
        attempted_actions = []
    
    # Build evidence summary
    funcs = evidence_so_far.get("functions", [])
    func_names = [f.get("name", "unknown") for f in funcs[:10]]
    evidence_summary = f"{len(funcs)} functions analyzed"
    if func_names:
        evidence_summary += f": {', '.join(func_names[:5])}"
        if len(func_names) > 5:
            evidence_summary += f" and {len(func_names) - 5} more"
    
    # Count functions with features
    funcs_with_features = [f for f in funcs if f.get("features")]
    if funcs_with_features:
        evidence_summary += f"\n{len(funcs_with_features)}/{len(funcs)} have LLM features"
    elif funcs:
        evidence_summary += f"\n⚠ None have LLM features - may need llm.enrich_features"
    
    # Build attempted actions summary
    attempted_summary = ""
    if attempted_actions:
        attempted_summary = "\n\nPreviously attempted actions (DO NOT repeat these):\n"
        for i, act in enumerate(attempted_actions[-5:], 1):  # Last 5 attempts
            act_type = act.get("type", "unknown")
            args = act.get("args", {})
            if act_type == "db.search_cards":
                attempted_summary += f"  {i}. Searched FTS: '{args.get('fts_query', '')}'\n"
            elif act_type == "db.get_function_rows":
                attempted_summary += f"  {i}. Got function rows for {len(args.get('func_eas', []))} functions\n"
            else:
                attempted_summary += f"  {i}. {act_type}\n"
    
    prompt = f"""You are a binary security analysis agent. Plan concrete actions to answer the user's query.

USER QUERY: "{user_query}"

⚠️ BEFORE PLANNING: Check if query mentions: "chain", "path", "from X to Y", "trace", "flow", "data flow", 
"source to sink", "reach", "connect", "between", "miscomputed and later used", "argv length →", "getenv to execve".
If YES → You MUST use db.find_ls_chains or db.find_paths (see MULTI-HOP PATH SEARCH STRATEGY below).

EVIDENCE COLLECTED SO FAR:
{evidence_summary}
{attempted_summary}

AVAILABLE ACTIONS (choose 1-3 specific actions per iteration):
1. db.search_cards: Search function cards with FTS query
   Args: {{"fts_query": "search terms", "filters": {{"has_exec": true}}, "limit": 10}}
   Use for: Finding functions by keywords/tags
   
   IMPORTANT: Function cards contain STRUCTURED TAGS, not natural language:
   - Input sources: SRC_ARGV, SRC_ENV, SRC_FILE, SRC_SOCKET, SRC_IPC, SRC_CONFIG
   - Sinks: SINK_EXEC, SINK_MEMWRITE, SINK_FILE, SINK_ALLOC, AUTH_OR_PRIV
   - Bounds: LEN_EXPANDS, LEN_SHRINKS, BOUNDS_YES, BOUNDS_NONE, BOUNDS_PARTIAL
   - Error handling: ERR_ABORT, ERR_RETURN, ERR_CONTINUE
   - Function names: NAME main, NAME parse_args (search for exact function names)
   
   Examples:
   - Find functions using argv: "SRC_ARGV"
   - Find functions with no bounds checks: "BOUNDS_NONE"
   - Find argv + exec: "SRC_ARGV SINK_EXEC"
   - Find function by name: "NAME main"

2. db.get_function_rows: Get metadata for specific function EAs or names
   Args: {{"func_eas": [0x401000, "sub_13590", 0x402000]}}  # Can mix EAs and names
   Use for: Getting details about known functions (accepts hex EAs or function names)

3. db.find_function_by_name: Find function(s) by name
   Args: {{"func_name": "sub_13590"}}
   Use for: Finding functions when you only know the name

4. db.get_features: Get LLM-extracted features for functions
   Args: {{"func_eas": [0x401000, "getenv", "sub_13590"]}}  # Can mix EAs and names
   Use for: Getting structured security features (input_sources, bounds_checks, etc.)

5. ida.get_full_disasm: Get complete disassembly for function (for LLM analysis)
   Args: {{"func_ea": 0x401000}}  # Or use function name via db.find_function_by_name first
   Use for: Getting full function code for detailed LLM analysis

6. db.get_neighbors: Get callers/callees of functions
   Args: {{"func_eas": [0x401000], "direction": "out|in|both", "depth": 1-3, "limit": 10-30}}
   Use for: Expanding call graph to find related functions
   Direction: "out"=callees (functions it calls), "in"=callers (functions that call it), "both"=both
   Depth: 1=direct neighbors only, 2=2 hops, 3=3 hops (use higher depth for data flow analysis)
   IMPORTANT: Use this AFTER finding candidate functions to discover:
   - Who calls vulnerable functions (direction="in", depth=2-3) - find entry points
   - What vulnerable functions call (direction="out", depth=2-3) - trace data flow
   - Complete call paths between source and sink (use both directions, depth=2-3)
   CRITICAL: For data flow queries (buffer overflow, injection, taint analysis), ALWAYS use depth=2 or depth=3
   to trace multi-hop paths. Single-hop (depth=1) is insufficient for vulnerability analysis.

7. db.find_paths: Find call paths between two functions (multi-hop BFS)
   Args: {{"src_ea": 0x401000, "dst_ea": 0x402000, "max_depth": 6, "max_paths": 5}}
   Use for: Finding complete call chains from source to sink (e.g., argv parsing → memcpy)
   Default max_depth=6 (supports up to 6 hops)
   Returns: List of paths, each path is a list of function EAs [src, ..., dst]
   CRITICAL: Use this for queries asking about "chains", "paths", "from X to Y", "trace", "flow"
   Example: "Find chain from argv parsing to memcpy" → find_paths(src=parse_func, dst=memcpy_func, max_depth=6)

8. db.find_ls_chains: Find chains from source functions (L) to sink functions (S)
   Args: {{"source_eas": [0x401000, 0x402000], "sink_eas": [0x403000, 0x404000], "depth": 6, "max_chains": 10}}
   Use for: Finding multiple chains when you have sets of sources and sinks
   Example: "Find chains where argv length is miscomputed and later used for allocation"
   → First find argv/parse candidates (sources), then find alloc/copy sinks
   → Then: find_ls_chains(source_eas=[...], sink_eas=[...], depth=6, max_chains=10)
   This uses reverse BFS from sinks for efficiency and returns ranked chains (shorter paths first)

9. ida.get_disasm_head_tail: Get function disassembly
   Args: {{"func_ea": 0x401000, "head": 20, "tail": 10}}
   Use for: Inspecting function code

10. ida.get_disasm_callsites: Get code around sink calls
   Args: {{"func_ea": 0x401000, "sinks": ["memcpy", "strcpy"], "window": 5, "max_sites": 5}}
   Use for: Finding dangerous operations

11. llm.enrich_features: Extract features for functions (expensive)
   Args: {{"func_eas": [0x401000]}}
   Use for: Deep analysis of specific functions

BUDGET: DB={budget.max_db_queries - budget.used_db_queries}, IDA={budget.max_ida_fetches - budget.used_ida_fetches}, LLM={budget.max_llm_calls - budget.used_llm_calls}

PLANNING RULES:
- Be SPECIFIC: Use exact function EAs (hex like 0x401000), concrete search terms, specific sinks
- Make PROGRESS: Each action must advance toward answering the query. Don't search vaguely.
- Avoid REPETITION: Check attempted_actions above. Don't repeat the same search/action.
- Be CONCISE: Reasoning = 1 sentence. Action reason = 1 short phrase (3-5 words max).
- Think STEP-BY-STEP: 
  * If query mentions a function name/EA, use db.get_function_rows with that EA first
  * If query is about finding functions, use db.search_cards with STRUCTURED TAGS (see above)
  * If you have function EAs, get their features to check input_sources, bounds_checks, etc.
  * If functions don't have features_json, use llm.enrich_features to extract them
  * For "assume sanitized" queries: Search for SRC_ARGV/SRC_ENV, then check bounds_checks in features

⚠️ CRITICAL: MULTI-HOP PATH SEARCH STRATEGY ⚠️

HARD RULE #1: If query mentions ANY of these keywords: "chain", "path", "from X to Y", "trace", "flow", 
"miscomputed and later used", "data flow", "source to sink", "reach", "connect", "between", 
you MUST use db.find_paths or db.find_ls_chains (NOT just db.get_neighbors with depth=1).

HARD RULE #2: For vulnerability/data flow queries ("buffer overflow", "injection", "taint", "argv length → alloc"),
you MUST:
  1. First find sources (e.g., SRC_ARGV, SRC_ENV functions)
  2. Then find sinks (e.g., SINK_MEMWRITE, SINK_ALLOC functions)
  3. Then use db.find_ls_chains(source_eas=[...], sink_eas=[...], depth=6, max_chains=10) to connect them
  4. DO NOT stop after just finding sources and sinks - you MUST connect them with path search

For chain/path queries ("find chain", "show path", "trace from X to Y", "argv length → alloc/copy"):
  STEP 1: Find source candidates (e.g., argv parsing, getopt, getenv)
    → db.search_cards: {{"fts_query": "SRC_ARGV getopt argv option", "limit": 10}}
  STEP 2: Find sink candidates (e.g., memcpy, sprintf, malloc)
    → db.search_cards: {{"fts_query": "SINK_MEMWRITE SINK_ALLOC memcpy sprintf", "limit": 10}}
  STEP 3: ⚠️ MANDATORY - Connect them with multi-hop path search:
    Option A (PREFERRED): db.find_ls_chains(source_eas=[...], sink_eas=[...], depth=6, max_chains=10)
    Option B: For each source-sink pair: db.find_paths(src_ea=..., dst_ea=..., max_depth=6, max_paths=3)
  STEP 4: Get callsite details for functions on paths:
    → ida.get_disasm_callsites(func_ea=..., sinks=["memcpy", "sprintf"], window=20, max_sites=3)
  
  ⚠️ DO NOT SKIP STEP 3 - Finding sources and sinks is NOT enough. You MUST use db.find_ls_chains or db.find_paths to connect them.

NEIGHBOR EXPANSION STRATEGY (use db.get_neighbors after finding candidates):
- For data flow/vulnerability queries ("buffer overflow", "injection", "taint", "data flow"):
  → CRITICAL: Use depth=2 or depth=3 (NOT depth=1) - these require multi-hop analysis
  → Expand both directions: direction="both", depth=2-3, limit=20-30
  → Example: After finding buffer overflow candidates, use depth=2-3 to trace complete data flow paths
- For path/trace queries ("find paths", "trace", "flow", "how does X reach Y"):
  → MUST use db.find_paths with max_depth=4-6 (NOT just get_neighbors with depth=1)
  → Or use db.find_ls_chains if you have multiple sources/sinks
- For entry point queries ("who calls", "where is X called", "entry points"):
  → Use direction="in", depth=2-3 to find all callers (including indirect callers)
- For sink analysis ("where does X go", "what does X call", "sink analysis"):
  → Use direction="out", depth=2-3 to trace where candidate functions call (find sinks through multiple hops)
- For vulnerability analysis ("buffer overflow", "injection", "vulnerable functions"):
  → ALWAYS use depth=2-3 (NOT depth=1) - vulnerabilities span multiple function calls
  → Expand both directions: direction="both", depth=2-3, limit=25-30
  → This finds: entry points (who calls vulnerable code) AND impact scope (what vulnerable code calls)
- For general queries about a single function:
  → Use depth=1 only if query is simple (e.g., "what does function X do")
  → For any security/vulnerability context, prefer depth=2-3

NO 1-HOP ONLY RULE: If you've only done 1-hop expansion (depth=1) and still have budget, you MUST attempt
2-6 hop path search using db.find_paths or db.find_ls_chains before giving up.

EXAMPLES:
Query: "what does sub_9490 do"
→ db.find_function_by_name: {{"func_name": "sub_9490"}}  # Find by name first
→ db.get_function_rows: {{"func_eas": [0x9490]}}  # Or use EA if known
→ ida.get_disasm_head_tail: {{"func_ea": 0x9490, "head": 30, "tail": 15}}  # Then analyze

Query: "tell me about sub_13590 why SRC_ENV"
→ db.find_function_by_name: {{"func_name": "sub_13590"}}  # Find the function
→ db.get_features: {{"func_eas": [0x13590]}}  # Get its features to check SRC_ENV

Query: "find buffer overflows"
→ db.search_cards: {{"fts_query": "SINK_MEMWRITE BOUNDS_NONE", "limit": 10}}  # Find candidates
→ db.get_features: {{"func_eas": [0x401000, 0x402000]}}  # Get details for candidates
→ db.get_neighbors: {{"func_eas": [0x401000, 0x402000], "direction": "both", "depth": 3, "limit": 30}}  # CRITICAL: Use depth=3 for data flow (NOT depth=1)

Query: "which functions assume argv/env is sanitized"
→ db.search_cards: {{"fts_query": "SRC_ARGV SRC_ENV", "limit": 20}}  # Find functions using argv/env
→ db.get_features: {{"func_eas": [0x401000, ...]}}  # Check their features for bounds_checks
→ db.get_neighbors: {{"func_eas": [0x401000, ...], "direction": "in", "depth": 2, "limit": 25}}  # Find who calls these (entry points, depth=2 for multi-hop)
→ Look for functions with input_sources=["argv","env"] AND bounds_checks="none" or "unknown"
→ Or functions with SRC_ARGV/SRC_ENV AND BOUNDS_NONE in cards

Query: "Find a chain where argv length is miscomputed and later used for allocation or copy"
→ db.search_cards: {{"fts_query": "SRC_ARGV getopt argv option", "limit": 10}}  # Find argv parsing sources
→ db.search_cards: {{"fts_query": "SINK_MEMWRITE SINK_ALLOC memcpy malloc", "limit": 10}}  # Find alloc/copy sinks
→ db.find_ls_chains: {{"source_eas": [0x401000, 0x402000], "sink_eas": [0x403000, 0x404000], "depth": 6, "max_chains": 10}}  # CRITICAL: Multi-hop chain search
→ For each chain found, get callsite details: ida.get_disasm_callsites(func_ea=..., sinks=["memcpy", "malloc"], window=20)

Query: "Show a call path from argument parsing to any unsafe memory write"
→ db.search_cards: {{"fts_query": "SRC_ARGV getopt parse", "limit": 10}}  # Find parsing functions
→ db.search_cards: {{"fts_query": "SINK_MEMWRITE memcpy strcpy", "limit": 10}}  # Find memory write sinks
→ db.find_ls_chains: {{"source_eas": [0x401000, ...], "sink_eas": [0x403000, ...], "depth": 6, "max_chains": 5}}  # Find paths
→ db.find_paths: {{"src_ea": 0x401000, "dst_ea": 0x403000, "max_depth": 6, "max_paths": 3}}  # Alternative: direct path search

Query: "Trace env/getenv usage to a memcpy/sprintf sink"
→ db.search_cards: {{"fts_query": "SRC_ENV getenv", "limit": 10}}  # Find getenv sources
→ db.search_cards: {{"fts_query": "SINK_MEMWRITE memcpy sprintf", "limit": 10}}  # Find sinks
→ db.find_ls_chains: {{"source_eas": [0x401000, ...], "sink_eas": [0x403000, ...], "depth": 6, "max_chains": 10}}  # Multi-hop chains

Query: "find paths from getenv to execve"
→ db.find_function_by_name: {{"func_name": "getenv"}}  # Find source
→ db.find_function_by_name: {{"func_name": "execve"}}  # Find sink
→ db.find_paths: {{"src_ea": 0x401000, "dst_ea": 0x402000, "max_depth": 6, "max_paths": 5}}  # CRITICAL: Use find_paths with max_depth=6 (NOT just get_neighbors)

Query: "who calls the vulnerable function"
→ db.find_function_by_name: {{"func_name": "vulnerable_func"}}  # Find the function
→ db.get_neighbors: {{"func_eas": [0x401000], "direction": "in", "depth": 2, "limit": 25}}  # Find all callers (entry points, depth=2 for indirect callers)

Output JSON only:
{{
  "goal": "vuln.buffer|vuln.injection|vuln.auth|malware.persistence|malware.c2|malware.evasion|general.triage",
  "reasoning": "One sentence: what you're doing this iteration",
  "actions": [
    {{
      "type": "action_type",
      "reason": "Short phrase: what this reveals",
      "args": {{...}}
    }}
  ]
}}
"""
    
    start_time = time.time()
    request_params = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
    }
    # OpenAI supports response_format, Ollama may not
    if provider == "openai":
        request_params["response_format"] = {"type": "json_object"}
    resp = client.chat.completions.create(**request_params)
    elapsed = time.time() - start_time
    
    # Extract token usage if available
    usage = resp.usage if hasattr(resp, 'usage') else None
    prompt_tokens = usage.prompt_tokens if usage else 0
    completion_tokens = usage.completion_tokens if usage else 0
    total_tokens = usage.total_tokens if usage else 0
    
    # Report timing to UI
    if ui_cb:
        time_str = f"{elapsed:.1f}s"
        token_str = f"{total_tokens} tokens" if total_tokens > 0 else ""
        if token_str:
            ui_cb(f"⏱️ Planning: {time_str}, {token_str} ({prompt_tokens} prompt + {completion_tokens} completion)\n")
        else:
            ui_cb(f"⏱️ Planning: {time_str}\n")
    
    text = resp.choices[0].message.content
    try:
        return json.loads(text)
    except Exception:
        # Try to extract JSON
        i = text.find("{")
        j = text.rfind("}")
        if i != -1 and j != -1:
            return json.loads(text[i:j+1])
        raise


def llm_answer(user_query: str, goal: str, evidence: Dict[str, Any],
               ui_cb: Optional[Callable[[str], None]] = None) -> str:
    """Call LLM to produce final answer from evidence."""
    config = _llm_load_config()
    client, provider, model = _llm_get_client(config)
    
    evidence_json = json.dumps(evidence, indent=2)
    
    # Determine if this is a general query or security-focused
    query_lower = user_query.lower()
    is_general = any(word in query_lower for word in [
        "tell me about", "describe", "summarize", "what does", "explain", 
        "investigate", "analyze", "overview", "information about"
    ])
    is_security = any(word in query_lower for word in [
        "vulnerability", "vuln", "exploit", "attack", "malware", "risk",
        "security", "unsafe", "dangerous", "injection", "overflow", "sanitize"
    ])
    
    # Default to general if not clearly security-focused
    answer_style = "security" if is_security and not is_general else "general"
    
    if answer_style == "general":
        prompt = f"""
You are a binary analysis assistant. The user asked: "{user_query}"

Evidence collected (ONLY use facts from this evidence, never hallucinate):
{evidence_json}

Provide a helpful answer about the function(s) in the evidence. Include:
1. What the function does (based on name, disassembly, called functions, features)
2. Key characteristics (size, complexity, callers/callees, segment)
3. Security-relevant observations (if any) - but don't force it if none exist
4. Suggested next steps (function EAs to jump to, related functions to investigate)

Be informative and helpful. If the query is about a specific function, focus on that function.
If evidence is insufficient, say so. Never claim facts not in evidence.

Output format (JSON):
{{
  "summary": "brief summary of what the function does",
  "description": "detailed description based on evidence",
  "characteristics": {{
    "size": "small|medium|large",
    "complexity": "simple|moderate|complex",
    "callers": ["0x401000: caller1"],
    "callees": ["0x402000: callee1"],
    "segment": "text|data|...",
    "features": ["uses argv", "calls getenv", "has bounds checks"]
  }},
  "security_notes": ["any security observations if relevant, otherwise empty array"],
  "findings": [
    {{
      "type": "observation|vulnerability|feature",
      "description": "...",
      "evidence_refs": ["feature: input_sources=argv", "disasm: 0x401050: call getenv"],
      "jump_targets": ["0x401000", "0x401050"]
    }}
  ],
  "next_actions": ["0x401000", "0x402000"]
}}
"""
    else:
        prompt = f"""
You are a binary security analyst. The user asked: "{user_query}"

Goal category: {goal}

Evidence collected (ONLY use facts from this evidence, never hallucinate):
{evidence_json}

Produce a structured answer with:
1. Top findings (list of vulnerabilities/malware behaviors found)
2. Witness call paths (function name/EA sequences showing the issue)
3. Evidence references (which feature field or disasm line supports each finding)
4. Suggested next actions (jump targets: function EAs to investigate)

If evidence is insufficient, say so. Never claim facts not in evidence.

Output format (JSON):
{{
  "summary": "brief summary",
  "findings": [
    {{
      "severity": "high|medium|low",
      "type": "buffer_overflow|injection|auth_bypass|...",
      "description": "...",
      "witness_path": ["0x401000: func1", "0x402000: func2"],
      "evidence_refs": ["feature: bounds_checks=none", "disasm: 0x401050: call memcpy"],
      "jump_targets": ["0x401000", "0x401050"]
    }}
  ],
  "next_actions": ["0x401000", "0x402000"]
}}
"""
    
    start_time = time.time()
    request_params = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
    }
    # OpenAI supports response_format, Ollama may not
    if provider == "openai":
        request_params["response_format"] = {"type": "json_object"}
    resp = client.chat.completions.create(**request_params)
    elapsed = time.time() - start_time
    
    # Extract token usage if available
    usage = resp.usage if hasattr(resp, 'usage') else None
    prompt_tokens = usage.prompt_tokens if usage else 0
    completion_tokens = usage.completion_tokens if usage else 0
    total_tokens = usage.total_tokens if usage else 0
    
    # Report timing to UI
    if ui_cb:
        time_str = f"{elapsed:.1f}s"
        token_str = f"{total_tokens} tokens" if total_tokens > 0 else ""
        if token_str:
            ui_cb(f"⏱️ Answering: {time_str}, {token_str} ({prompt_tokens} prompt + {completion_tokens} completion)\n")
        else:
            ui_cb(f"⏱️ Answering: {time_str}\n")
    
    return resp.choices[0].message.content


# -----------------------------
# Main Agent Loop
# -----------------------------
def run_chat(user_text: str, ui_cb: Optional[Callable[[str], None]] = None) -> str:
    """
    Main chat entrypoint. Runs agent loop: plan → act → evaluate → repeat → answer.
    
    Args:
        user_text: User's question/query
        ui_cb: Optional callback for UI updates (receives log messages)
    
    Returns:
        Final answer string (JSON formatted)
    """
    
    # Check DB exists - try to connect first (which will search for DB)
    conn = _connect_db()
    if not conn:
        # Try to get a helpful path for error message
        db_path = _get_db_path()
        expected_path = db_path if db_path else "unknown"
        msg = f"Database not found. Expected at: {expected_path}. Please click 'Start Agent' to build the index first."
        if ui_cb:
            ui_cb(msg)
        return json.dumps({"error": msg}, indent=2)
    
    try:
        budget = Budget()
        evidence = {"functions": []}
        goal = None
        iteration = 0
        max_iterations = 10
        
        if ui_cb:
            ui_cb(f"🔍 Analyzing: {user_text}\n")
        
        # Initial plan
        try:
            plan = llm_plan(user_text, evidence, budget, [], ui_cb=ui_cb)
            goal = plan.get("goal", "general.triage")
            actions = plan.get("actions", [])
            reasoning = plan.get("reasoning", "")
            if ui_cb:
                if reasoning:
                    ui_cb(f"📋 {reasoning}")
        except Exception as e:
            if ui_cb:
                ui_cb(f"❌ Planning error: {e}")
            return json.dumps({"error": f"Planning failed: {e}"}, indent=2)
        
        # Agent loop
        seen_func_eas = set()  # Track which functions we've already added
        attempted_actions = []  # Track attempted actions to avoid repetition
        
        while iteration < max_iterations:
            iteration += 1
            
            # Execute actions with reasoning
            action_results = []
            for action in actions:
                # Show concise action description
                reason = action.get("reason", "")
                action_type = action.get("type", "unknown")
                args = action.get("args", {})
                
                # Build concise action description
                if action_type == "db.search_cards":
                    desc = f"Search: '{args.get('fts_query', '')}'"
                elif action_type == "db.get_function_rows":
                    eas = args.get("func_eas", [])
                    desc = f"Get {len(eas)} function(s)"
                elif action_type == "db.find_function_by_name":
                    name = args.get("func_name", "")
                    desc = f"Find: {name}"
                elif action_type == "ida.get_disasm_head_tail":
                    ea = args.get("func_ea", 0)
                    desc = f"Disasm: {_ea_hex(ea) if ea else 'unknown'}"
                elif action_type == "ida.get_full_disasm":
                    ea = args.get("func_ea", 0)
                    if isinstance(ea, str):
                        desc = f"Full disasm: {ea}"
                    else:
                        desc = f"Full disasm: {_ea_hex(ea) if ea else 'unknown'}"
                elif action_type == "ida.get_disasm_callsites":
                    ea = args.get("func_ea", 0)
                    sinks = args.get("sinks", [])
                    desc = f"Callsites: {_ea_hex(ea) if ea else 'unknown'} ({', '.join(sinks[:2])})"
                else:
                    desc = f"{action_type}"
                
                if ui_cb:
                    ui_cb(f"  • {desc}")
                
                # Track attempted action
                attempted_actions.append(action)
                
                result = execute_action(conn, action, budget, ui_cb)  # Pass ui_cb for timing
                action_results.append({"action": action, "result": result})
                
                # Show result summary
                if ui_cb:
                    result_summary = _format_action_result(action_type, args, result)
                    if result_summary:
                        ui_cb(f"    {result_summary}")
                
                # Update evidence from results
                if "results" in result:
                    if action["type"] in ("db.search_cards", "db.get_function_rows", "db.find_function_by_name"):
                        func_eas = [r["func_ea"] for r in result["results"]]
                        # Only add new functions
                        new_eas = [ea for ea in func_eas if ea not in seen_func_eas]
                        if new_eas:
                            seen_func_eas.update(new_eas)
                            new_evidence = build_evidence_pack(conn, new_eas, 
                                                               include_disasm=False, 
                                                               include_strings=False,
                                                               budget=budget)
                            evidence["functions"].extend(new_evidence["functions"])
                    elif action["type"] == "db.get_features":
                        # Update features for existing functions, or add new functions if not in evidence
                        args = action.get("args", {})
                        func_eas = args.get("func_eas", [])
                        if func_eas:
                            features_map = db_get_features(conn, func_eas)
                            # Get function rows for any new functions
                            func_eas_int = list(features_map.keys())
                            func_rows = db_get_function_rows(conn, func_eas_int)
                            
                            # Update existing or add new functions
                            for row in func_rows:
                                ea = row["func_ea"]
                                if ea not in seen_func_eas:
                                    seen_func_eas.add(ea)
                                    new_evidence = build_evidence_pack(conn, [ea], 
                                                                       include_disasm=False, 
                                                                       include_strings=False,
                                                                       budget=budget)
                                    evidence["functions"].extend(new_evidence["functions"])
                                
                                # Update features for all functions (existing or new)
                                for func in evidence["functions"]:
                                    if int(func["func_ea"], 16) == ea:
                                        if ea in features_map and features_map[ea]:
                                            func["features"] = features_map[ea]
                                        break
                    elif action["type"] == "ida.get_full_disasm":
                        # Add full disassembly to existing function in evidence
                        args = action.get("args", {})
                        func_ea_arg = args.get("func_ea", 0)
                        # Resolve function name to EA if needed
                        if isinstance(func_ea_arg, str):
                            found = db_find_function_by_name(conn, func_ea_arg)
                            if found:
                                func_ea = found[0]["func_ea"]
                            else:
                                continue
                        else:
                            func_ea = int(func_ea_arg)
                        
                        disasm_result = result.get("results", {})
                        for func in evidence["functions"]:
                            if int(func["func_ea"], 16) == func_ea:
                                func["full_disasm"] = disasm_result
                                break
                    elif action["type"] == "db.get_neighbors":
                        neighbor_eas = [int(r["func_ea"], 16) for r in result["results"]]
                        # Only add new neighbors
                        new_eas = [ea for ea in neighbor_eas if ea not in seen_func_eas]
                        if new_eas:
                            seen_func_eas.update(new_eas)
                            new_evidence = build_evidence_pack(conn, new_eas,
                                                               include_disasm=False,
                                                               include_strings=False,
                                                               budget=budget)
                            evidence["functions"].extend(new_evidence["functions"])
                    elif action["type"] == "ida.get_disasm_head_tail":
                        # Add disasm to existing function in evidence
                        args = action.get("args", {})
                        func_ea = int(args.get("func_ea", 0))
                        if func_ea > 0:
                            disasm_result = result.get("results", {})
                            for func in evidence["functions"]:
                                if int(func["func_ea"], 16) == func_ea:
                                    func["disasm"] = disasm_result
                                    break
                
                # Progress updates removed for cleaner output
            
            # Check if enough evidence
            if has_enough_evidence(goal, evidence):
                if ui_cb:
                    ui_cb("✓ Enough evidence collected")
                break
            
            # Check budget
            if not budget.can_query_db() and not budget.can_fetch_ida() and not budget.can_call_llm():
                if ui_cb:
                    ui_cb("⚠ Budget exhausted, using available evidence")
                break
            
            # Plan next actions
            try:
                plan = llm_plan(user_text, evidence, budget, attempted_actions, ui_cb=ui_cb)
                actions = plan.get("actions", [])
                reasoning = plan.get("reasoning", "")
                if not actions:
                    break
                if ui_cb and reasoning:
                    ui_cb(f"\n📋 {reasoning}")
            except Exception as e:
                if ui_cb:
                    ui_cb(f"❌ Planning error: {e}")
                break
            
            # Process events for UI responsiveness
            try:
                from PySide6 import QtWidgets
                QtWidgets.QApplication.processEvents()
            except Exception:
                pass
        
        # Generate final answer
        try:
            if ui_cb:
                ui_cb("\n📝 Generating answer...")
            answer_json = llm_answer(user_text, goal, evidence, ui_cb=ui_cb)
            return answer_json
        except Exception as e:
            if ui_cb:
                ui_cb(f"❌ Answer generation error: {e}")
            return json.dumps({"error": f"Answer generation failed: {e}"}, indent=2)
    
    finally:
        conn.close()
