#!/usr/bin/env python3
# Merge recv_param sources into KVFI's deepin_result_path.json schema so that recv_param
# and key-value sources are consumed uniformly downstream.
#
#   # convert the batch aggregate into per-device deepin-format files (merging any existing)
#   python3 dataflow/merge_into_kvfi.py --recv dataflow/results_goahead_family.json --outdir dataflow/merged
#   # merge one recv_param result into one existing deepin_result_path.json in place
#   python3 dataflow/merge_into_kvfi.py --recv <recv.json> --deepin <deepin.json>
#
# deepin schema entry:  {binary: {func: {value_pos, key_pos, pair_pos, ...}}}
# A recv_param handler may carry several tainted params (path/url/query) -> `tainted_params`,
# with `value_pos` set to the primary (last = the request body/query) for KV-consumer compat.
import os, sys, json, argparse
from collections import defaultdict

def load(p):
    with open(p) as f: return json.load(f)

def _iter_sources(recv_data):
    for _binkey, val in recv_data.items():
        sources = val.get("sources", val) if isinstance(val, dict) else val
        for s in sources:
            yield s

def recv_entries(recv_data):
    """Yield (binary, func, entry_dict) in deepin schema from a recv_param result.
    Accepts the batch aggregate {binary: {device, sources:[...]}} or {binary: [sources]}."""
    per = defaultdict(lambda: defaultdict(list))   # binary -> func -> [source,...]
    for s in _iter_sources(recv_data):
        per[s["binary"]][s["handler"]].append(s)
    for binary, funcs in per.items():
        for func, srcs in funcs.items():
            params = sorted({s["param_index"] for s in srcs})
            # primary = highest param index (request body/query tends to be last)
            primary = max(params)
            detail = [{
                "value_pos": s["param_index"],
                "register_string": s.get("register_string"),
                "source_field": s.get("source_field"),
                "evidence_kind": s.get("kind"),
                "primitive": s.get("primitive"),
                "chain": s.get("chain"),
                "full_chain": s.get("full_chain", s.get("chain")),
                "evidence_to_recv": s.get("evidence_to_recv", False),
            } for s in srcs]
            # concrete network-input keys read inside this handler (via getter calls)
            keys = sorted({k for s in srcs for k in s.get("input_keys", [])})
            getters = sorted({g for s in srcs for g in s.get("getters", [])})
            entry = {
                "source_type": "recv_param",
                "value_pos": primary,
                "key_pos": -1, "pair_pos": -1,
                "tainted_params": params,
                "dispatcher": srcs[0].get("dispatcher"),
                "register_fn": srcs[0].get("register_fn"),
                "routes": sorted({s.get("register_string") for s in srcs if s.get("register_string")}),
                "input_keys": keys,
                "getters": getters,
                "recv_param_detail": detail,
            }
            yield binary, func, entry

def getter_entries(recv_data):
    """Yield (binary, getter_fn, entry_dict) as key_value sources: the getter functions
    (e.g. websGetVar) structurally identified inside confirmed handlers, tagged with the
    concrete keys observed at their call sites. This is the SAME source class the original
    KVFI LLM approach produced -> structural analysis recovers it deterministically."""
    per = defaultdict(lambda: defaultdict(set))   # binary -> getter -> {keys}
    routed = defaultdict(lambda: defaultdict(set))  # binary -> getter -> {handler}
    for s in _iter_sources(recv_data):
        for k in s.get("input_keys", []):
            for g in s.get("getters", []):
                per[s["binary"]][g].add(k)
        for g in s.get("getters", []):
            routed[s["binary"]][g].add(s["handler"])
    for binary, getters in per.items():
        for g, keys in getters.items():
            yield binary, g, {
                "source_type": "key_value",
                "origin": "structural",          # vs LLM-classified
                "value_pos": -1,                 # getter RETURNS the value
                "key_pos": 1, "pair_pos": 0,     # websGetVar(wp, "key") convention
                "observed_keys": sorted(keys),
                "used_in_handlers": sorted(routed[binary][g]),
            }

def merge_into(deepin, recv_data, gate_getters=False):
    """Merge recv_param sources and structural getters into `deepin`.

    gate_getters: when True (an LLM/agent layer ran), a structurally-recovered getter is
    kept ONLY if that layer already confirmed it (i.e. it is present in `deepin`); the
    entry is then ENRICHED with the structural keys/handlers. A structural getter the
    LLM/agent did NOT confirm is DROPPED — the string-overlap/dataflow getter heuristic
    has false positives (e.g. handler functions that merely CALL the real getter), and we
    don't want them leaking in unverified. When False (structural-only run, no model
    layer), keep the deterministic structural getter as before."""
    # tag pre-existing (key-value) entries so both classes are labelled
    for bp in deepin:
        for fn in deepin[bp]:
            deepin[bp][fn].setdefault("source_type", "key_value")
    for binary, func, entry in recv_entries(recv_data):
        deepin.setdefault(binary, {})
        if func in deepin[binary]:
            deepin[binary][func].update(entry)   # existing func also a recv_param source
        else:
            deepin[binary][func] = entry
    # structurally-recovered getter functions as key_value sources
    for binary, g, entry in getter_entries(recv_data):
        deepin.setdefault(binary, {})
        if g in deepin[binary]:
            # LLM/agent-confirmed (or already present) -> enrich, don't clobber
            deepin[binary][g].setdefault("origin", "structural")
            deepin[binary][g].setdefault("observed_keys", entry["observed_keys"])
            deepin[binary][g].setdefault("used_in_handlers", entry["used_in_handlers"])
            deepin[binary][g].setdefault("source_type", "key_value")
        elif not gate_getters:
            deepin[binary][g] = entry                # structural-only mode: keep it
        # else: gated and unconfirmed -> DROP (structural getter heuristic false positive)
    return deepin

def device_of(binary):
    parts = binary.split(os.sep)
    if "extenddataset" in parts:
        i = parts.index("extenddataset"); return "/".join(parts[i+1:i+3])
    # fall back to last two dir components
    return "/".join(parts[-3:-1])

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--recv", required=True)
    ap.add_argument("--deepin")             # merge into this single file in place
    ap.add_argument("--outdir")             # OR split per device into this dir
    args = ap.parse_args()
    recv_data = load(args.recv)

    if args.deepin:
        deepin = load(args.deepin) if os.path.exists(args.deepin) else {}
        merged = merge_into(deepin, recv_data)
        with open(args.deepin, "w") as f: json.dump(merged, f, indent=2, ensure_ascii=False)
        n = sum(1 for _ in recv_entries(recv_data))
        print(f"[=] merged {n} recv_param handler-entries into {args.deepin}")
        return

    outdir = args.outdir or "dataflow/merged"
    os.makedirs(outdir, exist_ok=True)
    by_dev = defaultdict(dict)              # device -> {binary: {func: entry}}
    for binary, func, entry in recv_entries(recv_data):
        by_dev[device_of(binary)].setdefault(binary, {})[func] = entry
    for binary, g, entry in getter_entries(recv_data):
        b = by_dev[device_of(binary)].setdefault(binary, {})
        if g not in b:                      # handler entry (if any) wins the slot
            b[g] = entry
    total = 0
    for dev, data in by_dev.items():
        fn = os.path.join(outdir, dev.replace("/", "_") + "_deepin_result_path.json")
        with open(fn, "w") as f: json.dump(data, f, indent=2, ensure_ascii=False)
        cnt = sum(len(v) for v in data.values()); total += cnt
        print(f"  {dev:24} {cnt:4} handlers -> {os.path.basename(fn)}")
    print(f"[=] {total} recv_param handlers across {len(by_dev)} devices -> {outdir}/")

if __name__ == "__main__":
    main()
