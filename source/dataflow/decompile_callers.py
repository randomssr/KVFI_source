# Decompile the CALLERS of a target function, to inspect where the container argument it
# receives is created (request-parse vs config-load). One headless IDA session.
#   idat64 -A -S"decompile_callers.py <target> <out.json>" <binary>
# out.json = { "callers": [ {"name":.., "code":..} ] }
import idaapi, idautils, idc, ida_hexrays, ida_auto, ida_funcs, ida_pro, json

def main():
    ida_auto.auto_wait(); ida_hexrays.init_hexrays_plugin()
    target = idc.ARGV[1]; out_path = idc.ARGV[2]
    tea = idc.get_name_ea_simple(target)
    callers = {}
    if tea != idc.BADADDR:
        for ref in idautils.CodeRefsTo(tea, 0):
            fn = ida_funcs.get_func(ref)
            if fn: callers[fn.start_ea] = idaapi.get_func_name(fn.start_ea)
    out = []
    for ea, name in list(callers.items())[:6]:
        try:
            c = ida_hexrays.decompile(ea)
            out.append({"name": name, "code": str(c) if c else ""})
        except Exception:
            pass
    json.dump({"target": target, "n_callers": len(callers), "callers": out}, open(out_path, "w"), ensure_ascii=False)
    ida_pro.qexit(0)

if __name__ == "__main__":
    main()
