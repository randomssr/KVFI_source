# Batch callsite extractor: for each target function, dump up to N caller statements
# that CALL it (the "usage" view), in ONE headless IDA session.
#   idat64 -A -S"callsites_of.py <names.json> <out.json> [maxcs]" <binary>
# out.json: {func_name: [callsite_line, ...]}
import idaapi, idautils, idc, ida_hexrays, ida_auto, ida_pro, json

def main():
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    names = set(json.load(open(idc.ARGV[1])))
    out_path = idc.ARGV[2]
    maxcs = int(idc.ARGV[3]) if len(idc.ARGV) > 3 else 8

    # map wanted name -> ea
    name2ea = {}
    for ea in idautils.Functions():
        n = idaapi.get_func_name(ea)
        if n in names:
            name2ea[n] = ea
    # also resolve imports/thunks by name
    for n in names:
        if n not in name2ea:
            e = idc.get_name_ea_simple(n)
            if e != idc.BADADDR:
                name2ea[n] = e

    out = {}
    deco_cache = {}
    def deco(fea):
        if fea not in deco_cache:
            try: deco_cache[fea] = ida_hexrays.decompile(fea)
            except Exception: deco_cache[fea] = None
        return deco_cache[fea]

    for name, tea in name2ea.items():
        lines = []
        callers = set()
        for x in idautils.XrefsTo(tea):
            if not x.iscode: continue
            f = idaapi.get_func(x.frm)
            if f: callers.add(f.start_ea)
        for cea in callers:
            if len(lines) >= maxcs: break
            cf = deco(cea)
            if not cf: continue
            for ln in str(cf).splitlines():
                if name in ln:
                    s = ln.strip()
                    if s and s not in lines:
                        lines.append(s)
                        if len(lines) >= maxcs: break
        if lines:
            out[name] = lines
    json.dump(out, open(out_path, "w"), ensure_ascii=False)
    ida_pro.qexit(0)

main()
