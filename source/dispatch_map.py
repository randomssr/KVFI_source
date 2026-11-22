#!/usr/bin/env python3
# Shared structural "dispatch discovery" front-end (§2.7 unification).
#
# Both source engines need the SAME sub-result: a binary's request-dispatch map — which
# function is the URI dispatcher / table registrar, and which URI strings route through
# it. Engine A (dataflow/analyze_binary.py) already recovers this structurally and for
# free while confirming recv_param handlers, in result["registrations"]. Engine B's
# URI-dispatch check (process_llm_uri_check.py) used to re-derive the SAME thing by
# asking an LLM about each candidate getter's parent function. This module exposes engine
# A's result so engine B consults STRUCTURE FIRST and only calls the LLM when structure
# is silent.
#
# SAFETY CONTRACT — structure may only ADD a positive:
#   * A hit = a function engine A has PROVEN to be a dispatch point (registrar/dispatcher),
#     returned with the concrete URI strings recovered from the registration table.
#   * A miss returns None = "structure can't say", which DEFERS to the LLM. There is no
#     structural NEGATIVE. So this can only save LLM calls and sharpen precision; it can
#     never suppress a real dispatcher the structural engine happened to miss.
#
#   from dispatch_map import structural_uri_result
#   r = structural_uri_result(binary_path, parent_func_name)   # {match,strings,reason} | None
import os, sys, json, hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "dataflow"))
from config import settings

_MEM = {}            # sha1 -> DispatchMap        (per-process, so engine A runs once/binary)
_PERSISTED = None    # binary_path -> registrations, from result_path/*/dispatch_map.json

def _sha1(path):
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

class DispatchMap:
    """Per-binary structural dispatch map: {dispatch-point fn name -> set(URI strings)}.
    Built from analyze_binary's `dispatch_sites` (preferred) — the ENCLOSING registration
    functions (init_form / websAspInit / formDefineUtilities) + runtime dispatchers, keyed
    by the same names get_caller hands engine B. Falls back to reconstructing from the
    older `registrations` shape (registrar-API + dispatcher names) when dispatch_sites is
    absent (older cached results)."""
    def __init__(self, dispatch_sites=None, registrations=None, handler_routes=None):
        self.uris_by_func = {}
        for fn, uris in (dispatch_sites or {}).items():
            u = {x for x in (uris or []) if x}
            if fn and u:
                self.uris_by_func.setdefault(fn, set()).update(u)
        # a CONFIRMED request handler is also request-context: a getter whose ancestor is
        # such a handler is proven to run on a network request (§ static-table + register
        # families). So index handler names -> their route(s) too.
        for fn, routes in (handler_routes or {}).items():
            u = {x for x in (routes or []) if x}
            if fn and u:
                self.uris_by_func.setdefault(fn, set()).update(u)
        if not self.uris_by_func:      # legacy fallback
            for reg_fn, info in (registrations or {}).items():
                uris = {u for (u, _h) in (info.get("handlers") or []) if u}
                if not uris:
                    continue
                for fn in (reg_fn, info.get("dispatcher")):
                    if fn:
                        self.uris_by_func.setdefault(fn, set()).update(uris)

    @classmethod
    def from_analyze(cls, res):
        res = res or {}
        # confirmed request handlers -> their route strings (register_string), from sources
        hr = {}
        for s in res.get("sources", []) or []:
            h = s.get("handler"); rs = s.get("register_string")
            if h and rs:
                hr.setdefault(h, set()).add(rs)
        return cls(dispatch_sites=res.get("dispatch_sites"),
                   registrations=res.get("registrations"),
                   handler_routes=hr)

    def uri_check(self, func_name):
        """Engine-B-compatible answer for `func_name`, or None if structure is silent.
        Returns the SAME JSON shape prompt_uri_check returns, so it is a drop-in
        short-circuit for the LLM URI-dispatch check."""
        uris = self.uris_by_func.get(func_name)
        if not uris:
            return None
        strings = sorted(u for u in uris if not str(u).isdigit())
        if not strings:                      # all-numeric -> not a real URI set (match=0 rule)
            return None
        return {"match": 1, "strings": strings,
                "reason": (f"structural: '{func_name}' is a stage-1-recovered request "
                           f"dispatch point or confirmed handler; {len(strings)} route(s) "
                           f"recovered (engine-A dispatch discovery, no LLM).")}

def _load_persisted():
    """Index every dispatch_map.json the structural pass has written under result_path."""
    global _PERSISTED
    if _PERSISTED is not None:
        return _PERSISTED
    _PERSISTED = {}
    root = getattr(settings, "result_path", None)
    if root and os.path.isdir(root):
        for dp, _dn, files in os.walk(root):
            if "dispatch_map.json" not in files:
                continue
            try:
                d = json.load(open(os.path.join(dp, "dispatch_map.json")))
                for b, regs in d.items():
                    _PERSISTED.setdefault(b, regs)
            except Exception:
                pass
    return _PERSISTED

def load_dispatch_map(binary_path):
    """Return the DispatchMap for a binary, from (1) in-proc cache, (2) a persisted
    per-device dispatch_map.json produced by the structural pass, or (3) an on-demand
    engine-A run (deterministic, no LLM). Cached by file content hash."""
    try:
        key = _sha1(binary_path)
    except Exception:
        key = binary_path
    if key in _MEM:
        return _MEM[key]
    persisted = _load_persisted().get(binary_path)
    if persisted is not None:
        if isinstance(persisted, dict) and ("dispatch_sites" in persisted or
                                            "handler_routes" in persisted):
            dm = DispatchMap(dispatch_sites=persisted.get("dispatch_sites"),
                             handler_routes=persisted.get("handler_routes"))
        else:
            # legacy: {fn: [uris]} dispatch_sites map, or {reg_fn: {...}} registrations
            vals = list(persisted.values())
            if vals and isinstance(vals[0], dict):
                dm = DispatchMap(registrations=persisted)
            else:
                dm = DispatchMap(dispatch_sites=persisted)
    else:
        # on-demand fallback: run engine A (headless IDA) once for this binary
        try:
            import run_dataflow
            dm = DispatchMap.from_analyze(run_dataflow.analyze_one(binary_path))
        except Exception:
            dm = DispatchMap()
    _MEM[key] = dm
    return dm

def structural_uri_result(binary_path, func_name):
    """Convenience: the structural URI-dispatch answer for one parent function, or None
    when structure is silent (LLM fallback). Never raises."""
    try:
        return load_dispatch_map(binary_path).uri_check(func_name)
    except Exception:
        return None

def registrations_of(analyze_result):
    """Extract the {register_fn: {...}} dispatch map from one analyze_binary result."""
    return (analyze_result or {}).get("registrations", {}) or {}
