# Batch decompiler that includes CALLEES. In ONE headless IDA session, for each wanted
# function it decompiles the function itself PLUS its direct callees (1 level, same binary),
# so the classifier can see the semantics of helper functions (e.g. a getter whose keyed
# lookup lives in sub_40EA3C / hsearch_r). Callees that are imports/thunks resolved from
# another binary are reported in "_external" so the caller can fetch their bodies elsewhere.
#   idat64 -A -S"decompile_with_callees.py <names.json> <out.json>" <binary>
# out.json = { "code": {func: target+callees_decompiled}, "_external": {func: [import names]} }
import idaapi, idautils, idc, ida_hexrays, ida_auto, ida_funcs, ida_typeinf, ida_pro, json, re

# libc/runtime helpers that add noise but no getter semantics — skip as callees.
SKIP_CALLEE = {"_stack_chk_fail", "__stack_chk_fail", "__stack_chk_guard", "memcpy", "memset",
    "memmove", "strcpy", "strncpy", "strlen", "strcat", "strncat", "malloc", "calloc",
    "free", "realloc", "printf", "sprintf", "snprintf", "fprintf", "puts", "abort",
    "__assert_fail", "strchr", "strrchr", "atoi", "strtol"}

def callee_eas(func_ea):
    """Direct call targets of func_ea."""
    eas = set()
    f = ida_funcs.get_func(func_ea)
    if not f:
        return eas
    for head in idautils.FuncItems(func_ea):
        for ref in idautils.CodeRefsFrom(head, 0):   # 0 = exclude normal flow -> calls/jumps
            fn = ida_funcs.get_func(ref)
            if fn and fn.start_ea != func_ea:
                eas.add(fn.start_ea)
    return eas

def deco(ea, cache):
    if ea in cache:
        return cache[ea]
    try:
        c = ida_hexrays.decompile(ea)
        s = str(c) if c else ""
    except Exception:
        s = ""
    cache[ea] = s
    return s

_WRAP_RE = re.compile(r"\breturn\s+([A-Za-z_]\w*)\s*\(\s*\)\s*;")

def fix_wrapper(ea, body, cache):
    """A thin forwarder often decompiles as `return callee();` with the key argument LOST
    (IDA typed the wrapper with 0 args). Detect that, apply the callee's prototype to the
    wrapper, and re-decompile so the forwarded key becomes visible (`return callee(a1);`).
    Returns the (possibly improved) body."""
    m = _WRAP_RE.search(body)
    if not m:
        return body
    callee_ea = idc.get_name_ea_simple(m.group(1))
    if callee_ea == idc.BADADDR:
        return body
    cf = None
    try:
        cf = ida_hexrays.decompile(callee_ea)
    except Exception:
        return body
    if not cf:
        return body
    tif = ida_typeinf.tinfo_t()
    if not cf.get_func_type(tif) or tif.get_nargs() == 0:
        return body   # callee takes no args either -> nothing to forward
    if not ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
        return body
    ida_hexrays.mark_cfunc_dirty(ea)
    cache.pop(ea, None)
    return deco(ea, cache)

def main():
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    wanted = set(json.load(open(idc.ARGV[1])))
    out_path = idc.ARGV[2]

    # name -> ea for all functions
    name2ea = {}
    for ea in idautils.Functions():
        name2ea[idaapi.get_func_name(ea)] = ea
    imports = set()
    for i in range(idaapi.get_import_module_qty()):
        idaapi.enum_import_names(i, lambda ea, name, ordn: (imports.add(name) if name else None) or True)

    cache = {}
    code = {}
    external = {}
    for name in wanted:
        ea = name2ea.get(name)
        if ea is None:
            continue
        target_body = fix_wrapper(ea, deco(ea, cache), cache)
        parts = [target_body]
        ext = []
        for cea in callee_eas(ea):
            cname = idaapi.get_func_name(cea)
            if cname in SKIP_CALLEE or cname.lstrip("_") in SKIP_CALLEE:
                continue
            body = deco(cea, cache)
            # a thunk to an import (tiny stub) -> record the import name as external
            flags = idc.get_func_attr(cea, idc.FUNCATTR_FLAGS)
            if flags & idc.FUNC_THUNK and (not body or "return " in body[-40:]):
                ext.append(cname)
            if body:
                parts.append(body)
        # prepend callees, target last (matches original ordering: helpers then function)
        merged = "\n\n".join([p for p in parts[1:]] + [parts[0]]) if len(parts) > 1 else parts[0]
        code[name] = merged
        if ext:
            external[name] = sorted(set(ext))

    json.dump({"code": code, "_external": external}, open(out_path, "w"), ensure_ascii=False)
    ida_pro.qexit(0)

if __name__ == "__main__":
    main()
