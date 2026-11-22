# Batch callsite-context decompiler. For each wanted function, decompile a few of its CALLERS
# so the classifier can see WHERE the container argument comes from (request body vs a config/
# response object). This is the container-provenance signal the original KVFI deep-check used.
#   idat64 -A -S"decompile_callsites.py <names.json> <out.json>" <binary>
# out.json = { func_name: "<concatenated caller function bodies>" }
import idaapi, idautils, idc, ida_hexrays, ida_auto, ida_funcs, ida_pro, json

MAX_CALLERS = 3

def main():
    ida_auto.auto_wait(); ida_hexrays.init_hexrays_plugin()
    wanted = set(json.load(open(idc.ARGV[1])))
    out_path = idc.ARGV[2]
    out = {}
    deco_cache = {}
    def deco(ea):
        if ea in deco_cache: return deco_cache[ea]
        try:
            c = ida_hexrays.decompile(ea); s = str(c) if c else ""
        except Exception:
            s = ""
        deco_cache[ea] = s; return s
    for name in wanted:
        tea = idc.get_name_ea_simple(name)
        if tea == idc.BADADDR:
            continue
        callers = {}
        for ref in idautils.CodeRefsTo(tea, 0):
            fn = ida_funcs.get_func(ref)
            if fn and fn.start_ea != tea:
                callers[fn.start_ea] = idaapi.get_func_name(fn.start_ea)
            if len(callers) >= MAX_CALLERS:
                break
        parts = []
        for ea in list(callers)[:MAX_CALLERS]:
            b = deco(ea)
            if b:
                parts.append(b)
        if parts:
            out[name] = "\n\n/* --- caller --- */\n".join(parts)[:12000]
    json.dump(out, open(out_path, "w"), ensure_ascii=False)
    ida_pro.qexit(0)

if __name__ == "__main__":
    main()
