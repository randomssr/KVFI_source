"""Recover the producer of a getter's shared key-value container.

IDA batch usage:
  idat -A -S"decompile_container_provenance.py names.json out.json" binary

For every candidate getter, this script finds writable global objects referenced by
the getter, collects the other functions that reference the same object, and looks
for a request-parameter producer.  The high-confidence pattern is deliberately
narrow: a producer that splits multiple fields and key/value pairs, performs URL
decoding, and manages the lifetime of the shared container.

The script is read-only and does not rename functions or modify the database.
"""

import json
import sys

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_name
import ida_segment
import idaapi
import idautils
import idc


MAX_OBJECTS = 8
MAX_FUNCTIONS = 16
MAX_CODE = 14000


def func_start(ea):
    f = ida_funcs.get_func(ea)
    return int(f.start_ea) if f else None


def symbol(ea):
    return ida_name.get_name(ea) or f"sub_{ea:X}"


def locate(name):
    ea = ida_name.get_name_ea(idaapi.BADADDR, name)
    if ea != idaapi.BADADDR:
        return int(ea)
    lname = name.lower()
    for fva in idautils.Functions():
        if symbol(fva).lower() == lname:
            return int(fva)
    return None


def decompile(ea):
    try:
        return str(ida_hexrays.decompile(ea))
    except Exception:
        return ""


def is_writable_data(ea):
    seg = ida_segment.getseg(ea)
    if not seg or (seg.perm & ida_segment.SEGPERM_EXEC):
        return False
    if not (seg.perm & ida_segment.SEGPERM_WRITE):
        return False
    # Literal strings and vtables are context, not mutable request containers.
    if ida_bytes.get_strlit_contents(ea, -1, idc.STRTYPE_C) is not None:
        return False
    return True


def data_refs_in_function(fva):
    refs = set()
    for insn in idautils.FuncItems(fva):
        for target in idautils.DataRefsFrom(insn):
            target = int(target)
            if is_writable_data(target):
                refs.add(target)
    return refs


def referencing_functions(ea, depth=2):
    """Resolve direct references and one level of data indirection."""
    frontier = {ea}
    seen = set()
    funcs = set()
    for _ in range(depth):
        nxt = set()
        for target in frontier:
            if target in seen:
                continue
            seen.add(target)
            for xr in idautils.XrefsTo(target, 0):
                src = int(xr.frm)
                fva = func_start(src)
                if fva is not None:
                    funcs.add(fva)
                elif is_writable_data(src):
                    nxt.add(src)
        frontier = nxt
    return funcs


def callers_of(fva):
    out = set()
    for xr in idautils.XrefsTo(fva, 0):
        caller = func_start(int(xr.frm))
        if caller is not None:
            out.add(caller)
    return out


def parser_signals(code):
    lower = code.lower()
    signals = []
    if "strsep" in lower and ('\"&;\"' in code or '\"&\"' in code):
        signals.append("field-split")
    if "strsep" in lower and '\"=\"' in code:
        signals.append("key-value-split")
    if ("strpbrk" in lower and "%+" in code) or ("%02x" in lower and "sscanf" in lower):
        signals.append("url-decode")
    if "hcreate_r" in lower:
        signals.append("container-create")
    if "hdestroy_r" in lower:
        signals.append("container-destroy")
    if "hsearch_r" in lower:
        signals.append("hash-access")
    return signals


def is_request_parser(signals):
    s = set(signals)
    # Requiring both dimensions of form parsing avoids treating a generic tokenizer
    # or a persistent configuration table as request-backed.
    return ("field-split" in s and "key-value-split" in s and
            ("url-decode" in s or "container-create" in s))


def analyze_getter(name):
    getter = locate(name)
    if getter is None:
        return {"getter": name, "request_backed": False, "error": "function-not-found"}

    getter_callers = callers_of(getter)
    objects = []
    for obj in data_refs_in_function(getter):
        refs = referencing_functions(obj)
        # A private scalar referenced only by the getter cannot reveal a producer.
        if len(refs) < 2:
            continue
        candidates = []
        for fva in sorted(refs)[:MAX_FUNCTIONS]:
            if fva == getter:
                continue
            code = decompile(fva)
            signals = parser_signals(code)
            candidates.append({
                "address": hex(fva),
                "name": symbol(fva),
                "signals": signals,
                "request_parser": is_request_parser(signals),
                "code": code[:MAX_CODE],
                "callers": [symbol(x) for x in sorted(callers_of(fva))[:MAX_FUNCTIONS]],
            })
        if not candidates:
            continue
        candidates.sort(key=lambda x: (not x["request_parser"], -len(x["signals"]), x["address"]))
        objects.append({
            "address": hex(obj),
            "name": symbol(obj),
            "referencing_functions": [symbol(x) for x in sorted(refs)[:MAX_FUNCTIONS]],
            "producers": candidates,
        })

    objects.sort(key=lambda x: (
        not any(p["request_parser"] for p in x["producers"]),
        -max((len(p["signals"]) for p in x["producers"]), default=0),
        x["address"],
    ))
    objects = objects[:MAX_OBJECTS]
    request_objects = [o for o in objects if any(p["request_parser"] for p in o["producers"])]
    selected = request_objects[0] if request_objects else None
    producer = next((p for p in (selected or {}).get("producers", [])
                     if p["request_parser"]), None)
    return {
        "getter": name,
        "getter_address": hex(getter),
        "getter_callers": [symbol(x) for x in sorted(getter_callers)[:MAX_FUNCTIONS]],
        "request_backed": bool(selected and producer),
        "selected_container": None if not selected else {
            "address": selected["address"], "name": selected["name"]},
        "selected_producer": producer,
        "containers": objects,
    }


def main():
    ida_auto.auto_wait()
    if len(idc.ARGV) < 3:
        print("usage: decompile_container_provenance.py names.json out.json")
        return 2
    names = json.load(open(idc.ARGV[1]))
    result = {name: analyze_getter(name) for name in names}
    with open(idc.ARGV[2], "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    return 0


try:
    status = main()
except Exception as exc:
    print(f"[container-provenance] {type(exc).__name__}: {exc}")
    status = 1

idc.qexit(status)
