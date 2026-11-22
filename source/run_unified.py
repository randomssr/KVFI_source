#!/usr/bin/env python3
# Unified KVFI source-identification entry point.
#
# Runs BOTH source engines and merges them into one deepin_result_path.json:
#   * STRUCTURAL (dataflow/) — deterministic, free, no LLM. Covers the register-table
#     dispatch family (GoAhead/webs & derivatives): recovers getter functions
#     (key_value sources) + request handlers (recv_param sources) + the concrete
#     network-input keys each handler reads.
#   * LLM PIPELINE (the original top-level scripts) — general: identifies key-value
#     getter functions on ANY server/API (uhttpd/GetNameValue, xmldb, cJSON, NVRAM, …).
#
# The two are COMPLEMENTARY: for the register-table family the structural engine answers
# for free; everywhere else the LLM engine is the general path. The union is written to
# result_path/<device>/deepin_result_path.json.
#
# Cost prune: getter functions the structural engine already confirmed are removed from
# the LLM candidate list (final_possible.json), so the LLM does not re-classify them.
# They are folded back in from the structural side (with observed_keys), so coverage is
# unchanged while LLM calls drop on register-table binaries.
#
#   # structural only (free) + write/merge deepin:
#   python3 run_unified.py --rootfs /path/to/rootfs --device dir823
#   # full union (spends LLM budget; needs API keys configured in the LLM scripts):
#   python3 run_unified.py --rootfs /path/to/rootfs --device dir823 --with-llm
#   # single binary, structural only:
#   python3 run_unified.py --binary /path/to/goahead --device dir823
import os, sys, json, argparse, subprocess
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "dataflow"))
from config import settings
import run_dataflow                       # analyze_one, find_binaries, is_elf_exe
import merge_into_kvfi as M               # merge_into, recv_entries, getter_entries

# Pre-LLM stages (IDA + post-processing, NO model calls) that build the candidate list.
# (script, wants_rootfs); wants_rootfs=True -> `script <rootfs> <device>`, else `script <device>`.
PRE_STAGES = [
    ("frontend_string.py",           True),   # keywords.json, cfgkeywords.json
    ("auto_define_funcs_dir.py",     True),   # funcs.json                 [IDA]
    ("analyze_dir_callsite.py",      True),   # final_call_output.json     [IDA]
    ("parse_call_results.py",        False),  # final_possible.json  (candidate getters)
]
# Original OpenAI/DeepSeek LLM stages (need those keys; the .env here has Claude creds,
# so use --with-agent instead unless OpenAI/DeepSeek keys are configured).
OPENAI_STAGES = [
    ("llm_function.py",              False),  # llm_possible.json          [IDA + LLM]
    ("string_compare_before_uri.py", False),  # string_check_result.json
    ("process_llm_uri_check.py",     False),  # uricheck_result.json       [IDA + LLM]
    ("final_llm_pos_analysis.py",    False),  # deepin_result_path.json    [IDA + LLM]
]

def env_with_idausr():
    env = os.environ.copy()
    if os.environ.get("KVFI_IDAUSR"):
        env["IDAUSR"] = os.environ["KVFI_IDAUSR"]
    return env

def run_structural(rootfs, binary):
    """Return {binary: [sources]}, {binary: set(getter_names)}, {binary: registrations}.
    The registrations are the shared dispatch map (§2.7): engine A's structural URI->handler
    discovery, which engine B's URI-dispatch check reuses instead of asking the LLM."""
    if binary:
        bins = [binary]
    else:
        bins = list(run_dataflow.find_binaries(rootfs))
    print(f"[structural] {len(bins)} ELF executable(s)")
    sources = {}
    getters = defaultdict(set)
    registrations = {}   # binary -> {dispatch_sites, handler_routes} (shared front-end, §2.7)
    for i, b in enumerate(bins, 1):
        res = run_dataflow.analyze_one(b)
        if res and (res.get("dispatch_sites") or res.get("sources")):
            hr = {}
            for s in res.get("sources", []):
                h = s.get("handler"); rs = s.get("register_string")
                if h and rs:
                    hr.setdefault(h, set()).add(rs)
            registrations[b] = {"dispatch_sites": res.get("dispatch_sites", {}),
                                "handler_routes": {k: sorted(v) for k, v in hr.items()}}
        if res and res.get("sources"):
            sources[b] = res["sources"]
            for s in res["sources"]:
                for g in s.get("getters", []):
                    getters[b].add(g)
            nk = sum(1 for s in res["sources"] if s.get("input_keys"))
            print(f"  [{i}/{len(bins)}] {os.path.basename(b)}: "
                  f"{len(res['sources'])} sources, {nk} with input_keys, "
                  f"{len(getters[b])} getter(s)")
        else:
            print(f"  [{i}/{len(bins)}] {os.path.basename(b)}: 0")
    return sources, getters, registrations

def inject_getters(devdir, getters):
    """Union the structural getter functions INTO final_possible.json so the LLM/agent
    decompiles and classifies every one of them. We no longer trust the structural getter
    heuristic blindly (it has false positives — handler functions that merely CALL the real
    getter); each getter must be verified from its definition. Confirmed getters are then
    enriched with structural keys at merge time; unconfirmed ones are dropped (see
    merge_into_kvfi.merge_into gate_getters)."""
    fp = os.path.join(devdir, "final_possible.json")
    if not os.path.exists(fp):
        print("[inject] final_possible.json missing — skip"); return
    data = json.load(open(fp))
    added = 0
    for binary, gs in getters.items():
        funcs = data.setdefault(binary, {})
        for g in gs:
            if g not in funcs:
                funcs[g] = {}; added += 1
    json.dump(data, open(fp, "w"), indent=4, ensure_ascii=False)
    print(f"[inject] added {added} structural getter(s) to LLM/agent candidate list "
          f"(all getters get verified; none trusted blind)")

def run_stages(stages, rootfs, device, env, tag):
    for script, wants_rootfs in stages:
        argv = [sys.executable, os.path.join(HERE, script)]
        argv += ([rootfs, device] if wants_rootfs else [device])
        print(f"[{tag}] $ {' '.join(os.path.basename(a) for a in argv)}")
        r = subprocess.run(argv, env=env, cwd=HERE)
        if r.returncode != 0:
            print(f"[{tag}] stage {script} exited {r.returncode} — aborting")
            return False
    return True

def run_llm_pipeline(rootfs, device, devdir, getters, no_prune):
    """Original OpenAI/DeepSeek path: pre-stages -> prune -> OpenAI LLM stages."""
    if not rootfs:
        print("[llm] --with-llm needs --rootfs"); return False
    env = env_with_idausr()
    if not run_stages(PRE_STAGES, rootfs, device, env, "llm"): return False
    if not no_prune:
        inject_getters(devdir, getters)
    return run_stages(OPENAI_STAGES, rootfs, device, env, "llm")

def run_agent_pipeline(rootfs, device, devdir, getters, no_prune, min_conf):
    """Claude path: pre-stages -> prune -> agent_analyze.py (getter identification)."""
    if not rootfs:
        print("[agent] --with-agent needs --rootfs"); return False
    env = env_with_idausr()
    if not run_stages(PRE_STAGES, rootfs, device, env, "agent"): return False
    if not no_prune:
        inject_getters(devdir, getters)
    argv = [sys.executable, os.path.join(HERE, "agent_analyze.py"),
            "--device", device, "--min-conf", str(min_conf)]
    print(f"[agent] $ agent_analyze.py --device {device}")
    return subprocess.run(argv, env=env, cwd=HERE).returncode == 0

def unify(devdir, structural):
    """Merge all engines into result_path/<device>/deepin_result_path.json:
    the OpenAI stage's deepin (if any), the Claude agent getters (agent_possible.json),
    and the structural sources. Pre-existing entries are preserved, never clobbered."""
    deepin_path = os.path.join(devdir, "deepin_result_path.json")
    deepin = json.load(open(deepin_path)) if os.path.exists(deepin_path) else {}
    had_llm = bool(deepin)
    # fold Claude agent getters (deepin-schema already), without clobbering
    agent_p = os.path.join(devdir, "agent_possible.json")
    had_agent = os.path.exists(agent_p)
    if had_agent:
        for b, funcs in json.load(open(agent_p)).items():
            for fn, e in funcs.items():
                deepin.setdefault(b, {}).setdefault(fn, e)
    # When a model layer ran, structural getters must be model-confirmed to survive
    # (gate_getters); unconfirmed structural-only getters are dropped as heuristic FPs.
    merged = M.merge_into(deepin, structural, gate_getters=(had_llm or had_agent))
    json.dump(merged, open(deepin_path, "w"), indent=2, ensure_ascii=False)
    # counts
    kv = rp = withkeys = 0
    for funcs in merged.values():
        for e in funcs.values():
            if e.get("source_type") == "key_value": kv += 1
            elif e.get("source_type") == "recv_param":
                rp += 1
                if e.get("input_keys"): withkeys += 1
    print(f"\n[=] unified -> {deepin_path}")
    print(f"    key_value sources : {kv}   (structural + agent/LLM getters)")
    print(f"    recv_param sources: {rp}   ({withkeys} with localized input keys)")
    print(f"    OpenAI-LLM ran    : {had_llm}   |  Claude-agent ran: {had_agent}")
    return deepin_path

def main():
    ap = argparse.ArgumentParser(description="Unified KVFI source identification")
    ap.add_argument("--rootfs", help="firmware rootfs dir (required for --with-llm)")
    ap.add_argument("--binary", help="analyze a single binary (structural only)")
    ap.add_argument("--device", required=True, help="run label; outputs under result_path/<device>/")
    ap.add_argument("--with-agent", action="store_true",
                    help="run the Claude agent getter-identification layer (uses .env ANTHROPIC_* creds)")
    ap.add_argument("--with-llm", action="store_true",
                    help="run the original OpenAI/DeepSeek LLM pipeline (needs those keys)")
    ap.add_argument("--min-conf", type=float, default=0.6,
                    help="min agent confidence to accept a getter (default 0.6)")
    ap.add_argument("--no-prune", action="store_true",
                    help="do NOT inject structural getters into the candidate list "
                         "(they then stay structural-only, unverified by the model)")
    args = ap.parse_args()
    if not args.rootfs and not args.binary:
        ap.error("need --rootfs or --binary")

    devdir = os.path.join(settings.result_path, args.device)
    os.makedirs(devdir, exist_ok=True)

    # 1. structural (always). Also persist the shared dispatch map (§2.7): engine A's
    # URI->handler discovery, which engine B's URI-dispatch check reads (dispatch_map.py)
    # to answer structurally-provable dispatchers WITHOUT an LLM call.
    structural, getters, registrations = run_structural(args.rootfs, args.binary)
    json.dump(structural, open(os.path.join(devdir, "recv_param_result.json"), "w"),
              indent=2, ensure_ascii=False)
    json.dump(registrations, open(os.path.join(devdir, "dispatch_map.json"), "w"),
              indent=2, ensure_ascii=False)

    # 2. general getter coverage (opt-in): Claude agent and/or the OpenAI pipeline
    if args.with_agent:
        run_agent_pipeline(args.rootfs, args.device, devdir, getters, args.no_prune, args.min_conf)
    if args.with_llm:
        run_llm_pipeline(args.rootfs, args.device, devdir, getters, args.no_prune)

    # 3. unify into deepin_result_path.json
    unify(devdir, structural)

if __name__ == "__main__":
    main()
