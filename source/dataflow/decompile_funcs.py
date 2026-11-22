# Batch decompiler: decompile many functions in ONE headless IDA session.
#   idat64 -A -S"decompile_funcs.py <names.json> <out.json>" <binary>
# names.json: JSON list of function names (or [] / missing -> all named functions with
#             at least one caller). out.json: {func_name: decompiled_c_text}.
import idaapi, idautils, idc, ida_hexrays, ida_auto, ida_pro, json

def main():
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    names_path = idc.ARGV[1]
    out_path = idc.ARGV[2]
    try:
        wanted = set(json.load(open(names_path)))
    except Exception:
        wanted = set()

    out = {}
    for ea in idautils.Functions():
        name = idaapi.get_func_name(ea)
        if wanted and name not in wanted:
            continue
        try:
            cf = ida_hexrays.decompile(ea)
            if cf:
                out[name] = str(cf)
        except Exception:
            continue
    json.dump(out, open(out_path, "w"), ensure_ascii=False)
    ida_pro.qexit(0)

main()
