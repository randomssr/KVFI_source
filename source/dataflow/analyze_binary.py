# KVFI recv_param source analyzer (register-table dispatch family, e.g. GoAhead/webs)
# Runs headless in IDA on ONE binary. No function names given as input.
#
#   idat64 -A -S"analyze_binary.py <output.json>" <binary_or_i64>
#
# Pipeline (all deterministic):
#   1. discover handler registrations:  register_fn(url_string, ..., handler_fnptr, ...)
#   2. resolve each register_fn's dispatch table -> dispatcher -> indirect-call arg exprs
#   3. for each handler param whose dispatcher arg is a request-struct field a1[N],
#      backward-close: some writer of field N reaches a recv/read primitive
#   4. emit confirmed recv_param sources with the recv->handler dataflow chain
import idaapi, idautils, idc, ida_hexrays, ida_auto, ida_pro, json, re
import ida_bytes, ida_segment, ida_funcs, statistics
from collections import deque, defaultdict

RECV = {"recv", "recvfrom", "recvmsg", "read", "readv", "SSL_read", "SSL_read_ex"}

# ---- static data-segment dispatch-table recovery (cstecgi-style) ----
# Some servers (Totolink cstecgi, private cgi) dispatch by a STATIC array in the data
# segment: struct { char name[K]; ...; void (*handler)(); }[]. The name is an INLINE
# char array (not a char*), and the handler pointers often aren't even recognized as
# functions by the disassembler (their only reference is this table). The call-site
# registration detector (step 1) can't see any of this. This recovers those tables so
# the register-table engine also covers the static-table family.
def _table_ptr_size():
    return 8 if idaapi.inf_is_64bit() else 4

def recover_static_tables():
    """Return [(route_name, handler_ea, table_start)] recovered from static dispatch
    tables. Conservative: inline name >=5 chars, table median name length >=8, >=5 entries
    -> avoids matching incidental function-pointer arrays (vtables etc.)."""
    PS = _table_ptr_size()
    execr, datar = [], []
    for s in idautils.Segments():
        seg = ida_segment.getseg(s); r = (idc.get_segm_start(s), idc.get_segm_end(s))
        (execr if seg.perm & ida_segment.SEGPERM_EXEC else datar).append(r)
    if not execr:
        return []
    # only the LARGEST executable segment is real code (.text). Small exec-flagged segments
    # (.reginfo/.init/.plt in a .so) hold values like 0x66 that would false-match as fnptrs.
    big = max(execr, key=lambda r: r[1] - r[0])
    def in_exec(v):
        v &= ~1                                   # ARM thumb bit
        return big[0] <= v < big[1]
    rd = (lambda ea: idc.get_wide_dword(ea)) if PS == 4 else (lambda ea: idc.get_qword(ea))
    def name_at(ea):
        raw = ida_bytes.get_bytes(ea, 64) or b""; s = raw.split(b"\x00")[0]
        if 5 <= len(s) <= 48 and re.fullmatch(rb'[A-Za-z_][A-Za-z0-9_./-]*', s):
            return s.decode()
        return None
    def clean(ea):
        b = ida_bytes.get_byte(ea - 1); return b == 0 or b < 0x20 or b > 0x7e
    slots = []
    for a, b in datar:
        ea = a
        while ea < b - PS:
            v = rd(ea)
            if v and in_exec(v): slots.append(ea)
            ea += PS
    sl = set(slots); slots.sort(); used = set(); out = []
    for s0 in slots:
        if s0 in used: continue
        best = None
        for S in sorted({t - s0 for t in slots if 8 <= t - s0 <= 512}):
            run = []; nxt = s0
            while nxt in sl and nxt not in used: run.append(nxt); nxt += S
            if len(run) < 5: continue
            for noff in range(PS, S, 4):
                nms = [name_at(r - noff) for r in run]
                good = [n for n in nms if n]
                if len(good) >= max(5, int(0.7 * len(run))):
                    sc = (len(good), sum(len(n) for n in good))
                    if best is None or sc > best[0]: best = (sc, S, noff, run)
        if best:
            _sc, S, noff, run = best
            nms = [name_at(r - noff) for r in run]
            good = [n for n in nms if n]
            if len(good) >= 5 and statistics.median(len(n) for n in good) >= 8:
                for r in run:
                    nm = name_at(r - noff)
                    if nm and clean(r - noff):
                        out.append((nm, rd(r) & ~1, run[0] - noff)); used.add(r)
    return out

def recover_charptr_tables():
    """Recover static char*-NAME dispatch tables: struct {char* name; ...; fnptr handler}[]
    searched by strcmp — the shape Netgear uhttpd/net-cgi uses (a two-level registry: the URI
    table, and cgi_setobject's submit_flag action table `for(i=&off;*i;i+=3) if(!strcmp(*i,v))
    ((fn)i[2])(a1,a2)`). Unlike recover_static_tables the name is a POINTER to a route string,
    and the handler is identified via get_func (reliable even in single-LOAD-segment ELFs).
    Returns [(route, handler_ea)]. Drops static/MIME noise: routes whose handler is shared by
    many routes (a generic static-file handler) and text/*, image/* … MIME "routes"."""
    PS = _table_ptr_size()
    rd = (lambda ea: idc.get_wide_dword(ea)) if PS == 4 else (lambda ea: idc.get_qword(ea))
    datar = []
    for s in idautils.Segments():
        seg = ida_segment.getseg(s)
        if not (seg.perm & ida_segment.SEGPERM_EXEC):
            datar.append((idc.get_segm_start(s), idc.get_segm_end(s)))
    def is_func(v):
        v &= ~1; f = idaapi.get_func(v); return bool(f and f.start_ea == v)
    def route_of(v):
        s = idc.get_strlit_contents(v)
        if not s: return None
        t = s.decode("latin1", "ignore")
        return t if (3 <= len(t) <= 48 and re.fullmatch(r'[A-Za-z_/][A-Za-z0-9_./-]*', t)) else None
    # a dispatch-table entry keeps the name char* within a few slots of the handler fnptr;
    # find fnptr slots whose NEAREST neighbour is a char*->route-string (O(data), no O(n^2)).
    pairs = []
    for a, b in datar:
        ea = a
        while ea < b - PS:
            v = rd(ea)
            if v and is_func(v):
                for off in (PS, -PS, 2*PS, -2*PS, 3*PS, -3*PS, 4*PS, -4*PS):
                    nv = rd(ea + off)
                    r = route_of(nv) if nv else None
                    if r:
                        pairs.append((r, v & ~1)); break
            ea += PS
    from collections import Counter
    hcount = Counter(h for _n, h in pairs)
    ncount = Counter(n for n, _h in pairs)
    MIME = ("text/", "image/", "application/", "audio/", "video/", "multipart/", "font/")
    out, seen = [], set()
    for nm, h in pairs:
        if hcount[h] > 4:                              # generic/static handler shared by many
            continue
        if ncount[nm] > 2:                             # one route pairing many fnptrs = not a
            continue                                   #   real {name,fnptr} table (a stray char*
        if any(nm.startswith(m) for m in MIME):        #   next to an unrelated fnptr array)
            continue
        if (nm, h) in seen: continue
        seen.add((nm, h)); out.append((nm, h))
    return out

def fname(ea):
    f = idaapi.get_func(ea)
    return idaapi.get_func_name(f.start_ea) if f else None

def deco(ea):
    try:
        return ida_hexrays.decompile(ea)
    except Exception:
        return None

def is_func_ea(ea):
    f = idaapi.get_func(ea)
    return bool(f and f.start_ea == ea)

# ---- ctree expr printer ----
def P(e, cf):
    if e is None:
        return "?"
    H = ida_hexrays; op = e.op
    if op == H.cot_var:
        try: return cf.lvars[e.v.idx].name or f"v{e.v.idx}"
        except Exception: return f"v{e.v.idx}"
    if op == H.cot_num:  return hex(e.numval())
    if op == H.cot_obj:  return idc.get_name(e.obj_ea) or hex(e.obj_ea)
    if op == H.cot_str:  return f'"{e.string}"'
    if op == H.cot_cast: return P(e.x, cf)
    if op == H.cot_ref:  return "&" + P(e.x, cf)
    if op == H.cot_ptr:  return "*" + P(e.x, cf)
    if op == H.cot_idx:  return f"{P(e.x, cf)}[{P(e.y, cf)}]"
    if op == H.cot_memptr: return f"{P(e.x, cf)}->{e.m}"
    if op == H.cot_memref: return f"{P(e.x, cf)}.{e.m}"
    if op == H.cot_add:  return f"({P(e.x, cf)} + {P(e.y, cf)})"
    if op == H.cot_sub:  return f"({P(e.x, cf)} - {P(e.y, cf)})"
    if op == H.cot_call: return f"{P(e.x, cf)}(...)"
    return H.get_ctype_name(op) or f"op{op}"

def find_fnptr(e):
    if e is None: return None
    if e.op == ida_hexrays.cot_obj and is_func_ea(e.obj_ea):
        return e.obj_ea
    for c in (getattr(e,'x',None), getattr(e,'y',None), getattr(e,'z',None)):
        if isinstance(c, ida_hexrays.cexpr_t):
            r = find_fnptr(c)
            if r is not None: return r
    return None

def find_strlit(e):
    if e is None: return None
    if e.op == ida_hexrays.cot_obj:
        s = idc.get_strlit_contents(e.obj_ea)
        if s: return s.decode('utf-8','ignore')
    if e.op == ida_hexrays.cot_str:
        return e.string
    for c in (getattr(e,'x',None), getattr(e,'y',None), getattr(e,'z',None)):
        if isinstance(c, ida_hexrays.cexpr_t):
            r = find_strlit(c)
            if r is not None: return r
    return None

class CallV(ida_hexrays.ctree_visitor_t):
    def __init__(s): ida_hexrays.ctree_visitor_t.__init__(s, ida_hexrays.CV_FAST); s.calls=[]
    def visit_expr(s, e):
        if e.op == ida_hexrays.cot_call: s.calls.append(e)
        return 0

def calls_of(cf):
    v = CallV(); v.apply_to(cf.body, None); return v.calls

def callee_ea(e):
    x = e.x
    while x is not None and x.op == ida_hexrays.cot_cast:
        x = x.x
    if x is not None and x.op == ida_hexrays.cot_obj:
        return x.obj_ea
    return None  # indirect

def globals_used(cf):
    outs = set()
    class ObjV(ida_hexrays.ctree_visitor_t):
        def __init__(s): ida_hexrays.ctree_visitor_t.__init__(s, ida_hexrays.CV_FAST)
        def visit_expr(s, e):
            if e.op == ida_hexrays.cot_obj and not is_func_ea(e.obj_ea):
                if not idc.get_strlit_contents(e.obj_ea):
                    outs.add(e.obj_ea)
            return 0
    ObjV().apply_to(cf.body, None)
    return outs

# request-struct field: "a1[0x31]", "(a1 + 0xC4)", or "*(a1 + 0xa4)" -> field index
FIELD_IDX_RE = re.compile(r'^a1\[(0x[0-9a-fA-F]+|\d+)\]$')
FIELD_OFF_RE = re.compile(r'^\*?\(?a1 \+ (0x[0-9a-fA-F]+|\d+)\)?$')
ROUTE_RE = re.compile(r'^[/A-Za-z_][\w./:-]*$')
def is_route_string(s):
    # a plausible route / handler name: no format specifiers, no control chars,
    # has at least one alnum. Kills "::", "%s", "\x0b", single chars, etc.
    if not s or len(s) < 2: return False
    if '%' in s: return False
    if any(ord(c) < 32 for c in s): return False
    if not ROUTE_RE.match(s): return False
    return any(c.isalnum() for c in s)

def parse_field_index(expr):
    e = expr.strip()
    m = FIELD_IDX_RE.match(e)
    if m:
        g = m.group(1); return int(g, 16) if g.startswith('0x') else int(g)
    m = FIELD_OFF_RE.match(e)
    if m:
        g = m.group(1); off = int(g, 16) if g.startswith('0x') else int(g)
        return off // 4
    return None

PARAM_RE = re.compile(r'^a(\d+)$')
def parse_param_index(expr):
    # dispatcher passing its OWN parameter, e.g. "a7" -> 0-based index 6
    m = PARAM_RE.match(expr.strip())
    return int(m.group(1)) - 1 if m else None

# ---- input localization: inside a confirmed handler, which concrete input keys are read ----
def arg_lvars(cf):
    # param position (0-based) -> lvar index, in declaration order
    m = {}; pos = 0
    for i, lv in enumerate(cf.lvars):
        if lv.is_arg_var:
            m[pos] = i; pos += 1
    return m

def base_var_idx(e):
    # peel casts/derefs/field-access to the underlying local var index (or None)
    while e is not None and e.op == ida_hexrays.cot_cast:
        e = e.x
    if e is None:
        return None
    if e.op == ida_hexrays.cot_var:
        return e.v.idx
    if e.op in (ida_hexrays.cot_ptr, ida_hexrays.cot_memptr, ida_hexrays.cot_memref,
                ida_hexrays.cot_ref, ida_hexrays.cot_idx, ida_hexrays.cot_add):
        return base_var_idx(e.x)
    return None

# calls that emit/format output or compare/parse rather than fetch an input value by key
# -> not a getter. (comparators like strcmp/websCompareVar and libc string/format fns read
# the value but don't RETRIEVE-BY-KEY, so they are not sources.)
GETTER_NOISE = ('write', 'redirect', 'header', 'error', 'done', 'flush', 'printf',
                'print', 'log', 'send', 'free', 'close', 'response', 'html',
                'setcookie', 'set_cookie', 'assert', 'sprintf', 'snprintf',
                'cmp', 'compare', 'conflict', 'match', 'strstr', 'strchr', 'strrchr',
                'strtok', 'atoi', 'atol', 'strlen', 'memcpy', 'memset', 'setvar', 'set_var')
# response/status literals (a reporter's operands, not GET keys) — real form fields
# are essentially never named these, so dropping them is high-precision.
STATUS_WORDS = {"ok", "error", "success", "fail", "failure", "done", "null",
                "none", "true", "false"}
def is_key_string(s):
    # a plausible key/field name: short, no format specifiers, no path/whitespace,
    # no markup (kills "<body>" and other output/template strings)
    if not s or not (2 <= len(s) <= 31): return False
    if any(ord(c) < 32 for c in s): return False
    if any(c in s for c in '% /<>="\t'): return False
    if s.lower() in STATUS_WORDS: return False
    if s.endswith('.html') or s.endswith('.asp') or s.endswith('.htm'): return False
    # a real field name has a letter; pure numeric/index args ("0.1", "-1") are config
    # selectors, not form keys
    return any(c.isalpha() for c in s)

class _BareCallV(ida_hexrays.ctree_visitor_t):
    # calls that are a whole statement -> their return value is discarded
    def __init__(s): ida_hexrays.ctree_visitor_t.__init__(s, ida_hexrays.CV_FAST); s.bare=set()
    def visit_insn(s, i):
        if i.op == ida_hexrays.cit_expr and i.cexpr is not None and i.cexpr.op == ida_hexrays.cot_call:
            s.bare.add((callee_ea(i.cexpr), i.cexpr.ea))
        return 0

def bare_calls_of(cf):
    v = _BareCallV(); v.apply_to(cf.body, None); return v.bare

def localize_inputs(hea, param_idxs, deco):
    """Find getter-style calls inside handler `hea` that read a network-tainted
    param (the request struct) with a string key -> [{getter, key}]. This recovers
    the SAME notion of source the original KVFI LLM approach found (getter fn + key)."""
    cf = deco(hea)
    if not cf: return []
    am = arg_lvars(cf)
    src_lvars = {am[p] for p in param_idxs if p in am} or set(am.values())
    bare = bare_calls_of(cf)
    out, seen_k = [], set()
    for e in calls_of(cf):
        cea = callee_ea(e)
        # a getter's RETURN VALUE is consumed; a call whose return is discarded (a whole
        # statement) is a response-writer / logger / setter, not a value getter.
        if (cea, e.ea) in bare:
            continue
        cname = (idc.get_name(cea) or "").split("@")[0] if cea else None
        if cname and any(n in cname.lower() for n in GETTER_NOISE):
            continue
        args = list(e.a) if e.a is not None else []
        if not any(base_var_idx(a) in src_lvars for a in args):
            continue
        # take only the FIRST key-sane string arg: it is the lookup key. Later string
        # args of a getter/setter are default/value operands ("", "ok") -> not keys.
        for a in args:
            ks = find_strlit(a)
            if ks and is_key_string(ks):
                k = (cname or "indirect", ks)
                if k not in seen_k:
                    seen_k.add(k)
                    out.append({"getter": cname, "key": ks})
                break
    return out

def main():
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    result = {"sources": [], "registrations": {}}
    binpath = idc.get_input_file_path()
    # ---- ablation knobs (env-gated; default = full engine, all off) ----
    import os as _os
    ABL_NO_TRANSITIVE = _os.environ.get("KVFI_ABLATE_TRANSITIVE") == "1"  # skip step 4b
    ABL_NO_CONTRACT   = _os.environ.get("KVFI_ABLATE_CONTRACT")   == "1"  # skip step 4c
    ABL_NO_DISPSCORE  = _os.environ.get("KVFI_ABLATE_DISPSCORE")  == "1"  # step 2: pick 1st max-arg

    # ---- 1. discover registrations (functions whose address is data-taken) ----
    ref_sites = {}
    for g in idautils.Functions():
        for x in idautils.XrefsTo(g):
            if x.iscode: continue
            fr = idaapi.get_func(x.frm)
            if fr: ref_sites.setdefault(fr.start_ea, set()).add(g)

    registrations = {}   # reg_fn ea -> list of (string, handler_ea)
    site_uris = defaultdict(set)   # ENCLOSING registration-site fn name -> {uris registered there}
    for site_ea in ref_sites:
        cf = deco(site_ea)
        if not cf: continue
        site_nm = fname(site_ea)
        for e in calls_of(cf):
            cea = callee_ea(e)
            if cea is None: continue
            args = list(e.a) if e.a is not None else []
            hptr = slit = None
            for a in args:
                if hptr is None: hptr = find_fnptr(a)
                if slit is None: slit = find_strlit(a)
            if hptr is not None and slit is not None and is_route_string(slit):
                registrations.setdefault(cea, []).append((slit, hptr))
                # the function that CONTAINS the websFormDefine("x",h) table is exactly the
                # "request dispatcher" engine B's URI-check looks for (callback-registration
                # form). Record it by name + the URI it registers so the shared dispatch map
                # (dispatch_map.py, §2.7) can answer engine B structurally.
                if site_nm: site_uris[site_nm].add(slit)

    # ---- 2. resolve dispatcher + indirect-call arg exprs per register_fn ----
    reg_info = {}   # reg_fn ea -> {"dispatcher":name,"args":[expr...],"handlers":[(str,ea)]}
    needed_fields = set()
    for rea, handlers in registrations.items():
        cf = deco(rea)
        tbls = globals_used(cf) if cf else set()
        disp = None; disp_args = None; best = -1
        cand = set()
        for gg in tbls:
            for x in idautils.XrefsTo(gg):
                fr = idaapi.get_func(x.frm)
                if fr and fr.start_ea != rea: cand.add(fr.start_ea)
        for fea in cand:
            dcf = deco(fea)
            if not dcf: continue
            for e in calls_of(dcf):
                if callee_ea(e) is None:
                    a = list(e.a) if e.a is not None else []
                    argexprs = [P(x, dcf) for x in a]
                    # A dispatcher can have SEVERAL indirect calls; the real handler
                    # dispatch is the one that FORWARDS the request — a param (a{N}) or a
                    # request-struct field (a1[N]) — not the max-arg one. Score it up so we
                    # don't pick a bystander indirect call (e.g. websFormHandler dispatches
                    # via (a1,v14,a7) but also has (v26,0,0x34) helper calls with same arity).
                    fwd = any(parse_param_index(x) is not None or parse_field_index(x) is not None
                              for x in argexprs)
                    # ablation: without scoring, fall back to "first max-arg indirect call"
                    # (the pre-fix behavior that missed DIR816's real dispatch)
                    score = len(a) if ABL_NO_DISPSCORE else len(a) + (100 if fwd else 0)
                    if score > best:
                        best = score; disp = fname(fea)
                        disp_args = argexprs
        reg_info[rea] = {"register_fn": fname(rea), "dispatcher": disp,
                         "args": disp_args, "handlers": handlers}
        if disp_args:
            for ex in disp_args:
                fi = parse_field_index(ex)
                if fi is not None: needed_fields.add(fi)
        result["registrations"][fname(rea)] = {
            "dispatcher": disp,
            "handlers": [[s, fname(h)] for s, h in handlers],
            "indirect_args": disp_args,
        }
        # a runtime dispatcher routes every URI its registrar registered -> it, too, is a
        # dispatch point engine B may inspect.
        if disp:
            site_uris[disp].update(s for s, _h in handlers)

    # ---- 2c. STATIC DISPATCH-TABLE recovery (cstecgi-style): recover data-segment
    # {inline name, handler fnptr} arrays the call-site detector can't see, and emit each
    # handler as a recv_param source (kind="table-dispatch"). This extends coverage to the
    # static-table family (Totolink cstecgi & private cgi) that stage 1 previously missed.
    tables = recover_static_tables()
    if tables:
        by_table = defaultdict(list)
        seen_hea = set()
        for route, hea, tstart in tables:
            by_table[tstart].append((route, hea))
        for tstart, routes in by_table.items():
            disp = None
            for x in idautils.XrefsTo(tstart):
                f = idaapi.get_func(x.frm)
                if f: disp = fname(f.start_ea); break
            dname = disp or ("static_dispatch_%X" % tstart)
            for route, hea in routes:
                site_uris[dname].add(route)          # expose route for getter-context reuse
                if hea in seen_hea: continue         # one source per distinct handler
                seen_hea.add(hea)
                if not idaapi.get_func(hea):
                    ida_funcs.add_func(hea)          # disassembler missed it; define it
                hname = fname(hea) or ("sub_%X" % hea)
                result["sources"].append({
                    "binary": binpath, "handler": hname, "param_index": 0,
                    "source_field": "static-table:%s" % route, "register_string": route,
                    "register_fn": "static-table", "dispatcher": dname,
                    "primitive": "recv(cgi table-dispatch contract)", "kind": "table-dispatch",
                    "chain": ["static dispatch table[%s]" % route,
                              "%s(request handler)" % hname],
                })

    # ---- 2d. CHAR*-NAME DISPATCH-TABLE recovery (Netgear uhttpd/net-cgi): {char* name; ...;
    # fnptr handler}[] searched by strcmp — two-level (URI table + submit_flag action table).
    # Name is a pointer, handler found via get_func. Emit each handler as a recv_param source
    # (kind="charptr-dispatch"). Static/MIME noise is filtered inside recover_charptr_tables.
    # GATE (dominance): keep the char*-table result only when it DOMINATES call-site
    # registration — i.e. char* tables are actually this binary's dispatch mechanism
    # (Netgear net-cgi/uhttpd: ~400 char* handlers vs ~1 incidental register). goahead/boa/
    # module binaries dispatch via register("x",h) (100+ handlers) and their data holds a few
    # unrelated fn-ptr arrays that would false-match — those never dominate, so they're dropped.
    _reg_h = sum(len(v) for v in registrations.values())
    ct = recover_charptr_tables()
    if len(ct) < max(10, 2 * _reg_h):
        ct = []
    if ct:
        seen_h = set()
        for route, hea in ct:
            site_uris["charptr_dispatch"].add(route)   # expose route for getter-context reuse
            if hea in seen_h: continue
            seen_h.add(hea)
            if not idaapi.get_func(hea):
                ida_funcs.add_func(hea)
            hname = fname(hea) or ("sub_%X" % hea)
            result["sources"].append({
                "binary": binpath, "handler": hname, "param_index": 0,
                "source_field": "charptr-table:%s" % route, "register_string": route,
                "register_fn": "charptr-table", "dispatcher": "charptr_dispatch",
                "primitive": "recv(charptr table-dispatch contract)", "kind": "charptr-dispatch",
                "chain": ["char* dispatch table[%s]" % route, "%s(request handler)" % hname],
            })

    # ---- 2b. shared DISPATCH-SITE map (§2.7): every function that structurally IS a
    # request dispatch point (the enclosing registration-table function like init_form /
    # websAspInit / formDefineUtilities, plus the runtime dispatcher) -> the URI strings it
    # routes. dispatch_map.py exposes this so engine B's URI-dispatch check reuses it
    # instead of asking an LLM. Keyed by function NAME (matches what get_caller inspects).
    result["dispatch_sites"] = {nm: sorted(u) for nm, u in site_uris.items() if u}

    # ---- 3. ONE pass over all functions: call graph + writers of needed fields ----
    callgraph = {}
    field_writers = {k: set() for k in needed_fields}
    # =(?!=) : an assignment, NOT a "==" comparison (the latter wrongly flagged e.g.
    # websError as a writer of a field it only compares).
    field_pats = {k: [re.compile(r'\[%d\]\s*=(?!=)' % k),
                      re.compile(r'\+\s*%d\)\s*=(?!=)' % (k*4)),
                      re.compile(r'\+\s*0x%X\)\s*=(?!=)' % (k*4), re.I)] for k in needed_fields}
    for fea in idautils.Functions():
        cf = deco(fea)
        if not cf:
            callgraph[fea] = set(); continue
        callgraph[fea] = set(c for c in (callee_ea(e) for e in calls_of(cf)) if c is not None)
        if needed_fields:
            s = str(cf)
            for k, pats in field_pats.items():
                if any(p.search(s) for p in pats):
                    field_writers[k].add(fea)

    CLEANUP = ('free', 'close', 'error', 'response', 'done', 'send', 'write',
               'clean', 'abort', 'reset', 'fault', 'fail')
    def _bfs(start_ea, avoid, maxdepth=6):
        q = deque([(start_ea, [fname(start_ea) or hex(start_ea)])]); seen = {start_ea}
        while q:
            ea, path = q.popleft()
            if len(path) > maxdepth: continue
            for cea in callgraph.get(ea, ()):
                nm = idc.get_name(cea) or ""
                if nm.split("@")[0] in RECV:
                    return path + [nm], nm.split("@")[0]
                if avoid and any(a in nm.lower() for a in avoid):
                    continue
                if cea not in seen:
                    seen.add(cea); q.append((cea, path + [nm or hex(cea)]))
        return None, None
    def reaches_recv(start_ea):
        # prefer a clean request-read path (avoid close/error/response/send/... nodes);
        # only fall back to any recv-reaching path if no clean one exists.
        p, pr = _bfs(start_ea, CLEANUP)
        if p: return p, pr
        return _bfs(start_ea, None)

    # ---- 4. confirm recv_param sources ----
    seen = set()
    func_tainted = {}   # handler name -> {param idx confirmed network-tainted}

    # 4a. BOOTSTRAP: dispatcher arg is a request-struct field a1[N] that reaches recv.
    # Pick the writer whose recv path is SHORTEST (the real read path, not close/error).
    for rea, info in reg_info.items():
        args = info["args"]
        if not args: continue
        for (s, hea) in info["handlers"]:
            hname = fname(hea)
            for i, ex in enumerate(args):
                fi = parse_field_index(ex)
                if fi is None: continue
                key = (hname, i, ex)
                if key in seen: continue
                best = None; best_score = 1e9  # prefer short path + non-cleanup writer
                for w in field_writers.get(fi, ()):
                    path, prim = reaches_recv(w)
                    if not path: continue
                    wn = (fname(w) or "").lower()
                    score = len(path) + (100 if any(c in wn for c in CLEANUP) else 0)
                    if score < best_score:
                        best_score = score; best = (path, prim, w)
                if best:
                    seen.add(key); func_tainted.setdefault(hname, set()).add(i)
                    path, prim, w = best
                    result["sources"].append({
                        "binary": binpath, "handler": hname, "param_index": i,
                        "source_field": ex, "register_string": s,
                        "register_fn": info["register_fn"], "dispatcher": info["dispatcher"],
                        "primitive": prim, "kind": "field",
                        "chain": list(reversed(path)) + [
                            f"{fname(w)}(writes {ex})",
                            f"{info['dispatcher']}(dispatch arg[{i}])",
                            f"{hname}(param {i})"],
                    })

    # 4b. TRANSITIVE (nested dispatch, e.g. websFormDefine/websAspDefine): a dispatcher
    # that passes one of its OWN already-tainted params to registered handlers taints
    # the corresponding handler param. Iterate to a fixpoint.
    changed = not ABL_NO_TRANSITIVE   # ablation: skip the transitive fixpoint entirely
    while changed:
        changed = False
        for rea, info in reg_info.items():
            D = info["dispatcher"]; args = info["args"]
            if not D or not args: continue
            dt = func_tainted.get(D)
            if not dt: continue
            for i, ex in enumerate(args):
                pk = parse_param_index(ex)
                if pk is None or pk not in dt: continue
                for (s, hea) in info["handlers"]:
                    hname = fname(hea)
                    key = (hname, i, ex)
                    if key in seen: continue
                    seen.add(key); func_tainted.setdefault(hname, set()).add(i)
                    changed = True
                    result["sources"].append({
                        "binary": binpath, "handler": hname, "param_index": i,
                        "source_field": f"{D}:a{pk+1}", "register_string": s,
                        "register_fn": info["register_fn"], "dispatcher": D,
                        "primitive": "recv(nested)", "kind": "transitive",
                        "chain": [f"{D}(param {pk} = network data)",
                                  f"{D}(dispatch arg[{i}])", f"{hname}(param {i})"],
                    })

    # 4c. FRAMEWORK-CONTRACT bootstrap: a handler registered via a GoAhead form/asp
    # registrar receives the HTTP request by contract. If its dispatcher forwards the
    # request-struct param (a1 = param0) and no dataflow confirmation exists, emit the
    # handler param as a source, tagged kind="framework-contract" (weaker evidence than
    # a dataflow-confirmed field/transitive source). Unlocks pure-Form/Asp servers that
    # have no websUrlHandlerDefine to bootstrap from.
    for rea, info in ({} if ABL_NO_CONTRACT else reg_info).items():   # ablation: skip 4c
        rn = (info["register_fn"] or "").lower()
        D = info["dispatcher"]; args = info["args"]
        if not D or not args: continue
        if "formdefine" not in rn and "aspdefine" not in rn: continue
        for i, ex in enumerate(args):
            if parse_param_index(ex) != 0:      # only the wp request struct (param 0)
                continue
            if 0 in func_tainted.get(D, set()):  # already dataflow-confirmed
                continue
            for (s, hea) in info["handlers"]:
                hname = fname(hea); key = (hname, i, ex)
                if key in seen: continue
                if hname in func_tainted: continue   # fallback only: already confirmed by dataflow
                seen.add(key)
                result["sources"].append({
                    "binary": binpath, "handler": hname, "param_index": i,
                    "source_field": f"{D}:wp(param0)", "register_string": s,
                    "register_fn": info["register_fn"], "dispatcher": D,
                    "primitive": "recv(framework-contract)", "kind": "framework-contract",
                    "chain": [f"{D}(request struct wp — GoAhead form/asp contract)",
                              f"{D}(dispatch arg[{i}])", f"{hname}(param {i})"],
                })

    # 4d. GENERIC REGISTRATION fallback: a handler registered with a route STRING via ANY
    # registrar — e.g. a module's cste_hook_register("getWiFiApcliScan", h) — is a request
    # handler for that route by construction, even when no runtime dispatcher / param-forward
    # was resolved (common in the modular cgi .so family: handlers register by call-site into
    # a hook API instead of GoAhead form/asp). Emit as a weak source kind="registered"
    # (registration-by-contract, no dataflow chain), only for handlers NO stronger tier
    # already covered, so it never double-counts or perturbs the goahead numbers.
    if not ABL_NO_CONTRACT:
        already = {src["handler"] for src in result["sources"]}
        for rea, info in reg_info.items():
            rn = (info["register_fn"] or "").lower()
            # goahead form/asp/url registrars are handled (and precisely filtered) by 4a-4c;
            # 4d is ONLY for a genuinely different registrar (a module hook API) whose
            # handlers no goahead tier covers -> don't re-admit the asp display functions
            # (MakeUserList/websWrite...) that framework-contract deliberately drops.
            if any(x in rn for x in ("formdefine", "aspdefine", "urlhandler", "aspredirect")):
                continue
            for (s, hea) in info["handlers"]:
                hname = fname(hea)
                if hname in already or not is_route_string(s):
                    continue
                already.add(hname)
                result["sources"].append({
                    "binary": binpath, "handler": hname, "param_index": 0,
                    "source_field": f"registered:{s}", "register_string": s,
                    "register_fn": info["register_fn"], "dispatcher": info["dispatcher"],
                    "primitive": "recv(registration contract)", "kind": "registered",
                    "chain": [f'{info["register_fn"]}("{s}", {hname}) — registration contract',
                              f"{hname}(request handler)"],
                })

    # ---- 5. INPUT LOCALIZATION: for every confirmed handler (field / transitive /
    # framework-contract alike), pinpoint the concrete network-input keys it reads via
    # getter calls on its tainted request param. This yields the SAME (getter fn, key)
    # information the original KVFI LLM approach produced, but structurally and grouped
    # per handler -> the bridge between the two source classes.
    handler_params = defaultdict(set)
    for s in result["sources"]:
        handler_params[s["handler"]].add(s["param_index"])
    name2ea = {}
    for rea, info in reg_info.items():
        for (_s, hea) in info["handlers"]:
            name2ea[fname(hea)] = hea

    access = {}          # handler -> [{getter, key}]
    for hname, params in handler_params.items():
        hea = name2ea.get(hname)
        if hea is None: continue
        ks = localize_inputs(hea, params, deco)
        if ks: access[hname] = ks
    result["input_access"] = access
    for s in result["sources"]:
        a = access.get(s["handler"])
        if a:
            s["input_keys"] = sorted({k["key"] for k in a})
            s["getters"] = sorted({k["getter"] for k in a if k["getter"]})

    # ---- 6. CHAIN STITCHING: a transitive source's own chain only says its
    # dispatcher's param "= network data"; splice on that dispatcher-param's OWN
    # chain (recursively) so every field/transitive source carries a FULL chain
    # that literally traces back to the recv primitive. framework-contract sources
    # have no dataflow root, so full_chain == chain (convention-only, no recv proof).
    by_hp = {}   # (handler, param_index) -> source  (prefer a field-rooted one)
    for s in result["sources"]:
        k = (s["handler"], s["param_index"])
        cur = by_hp.get(k)
        if cur is None or (s["kind"] == "field" and cur["kind"] != "field"):
            by_hp[k] = s
    def full_chain(s, seen):
        if s["kind"] == "field":
            return list(s["chain"])
        if s["kind"] == "transitive":
            m = PARAM_RE.match((s.get("source_field") or "").split(":")[-1])
            D = s.get("dispatcher"); pk = int(m.group(1)) - 1 if m else None
            if D is not None and pk is not None and (D, pk) not in seen:
                root = by_hp.get((D, pk))
                if root is not None:
                    rc = full_chain(root, seen | {(D, pk)})
                    if rc:
                        return rc + list(s["chain"][1:])  # drop redundant "D(param = network data)"
            return list(s["chain"])
        return list(s["chain"])   # framework-contract
    for s in result["sources"]:
        fc = full_chain(s, {(s["handler"], s["param_index"])})
        s["full_chain"] = fc
        # true iff the spliced chain literally originates at a recv primitive
        s["evidence_to_recv"] = bool(fc) and any(p in (fc[0] or "") for p in RECV)

    json.dump(result, open(idc.ARGV[1], "w"), indent=2, ensure_ascii=False)
    ida_pro.qexit(0)

main()
