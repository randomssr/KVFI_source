#!/usr/bin/env python3
# ONE unified flow over every dataset_by_vendor device, reproducible from stored inputs:
#   pre_llm_candidates.json (string-match candidates)
#   -> agent_analyze.frontend_prune (keywords.json)
#   -> agent_analyze.analyze_binary  (decompile + classify_voted + verify_source: origin+role)
# Compares the accepted getters to key_value.json (gold) and writes a per-device result plus a
# combined table. Resumable: a device whose result file exists is skipped unless --force.
import json, os, sys, re, argparse, time
from concurrent.futures import ThreadPoolExecutor, as_completed
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agent_analyze as A

DBV = os.path.join(HERE, "dataset_by_vendor")
MIN_CONF = 0.6

def chain_guided_getters(ddir):
    """Return binary -> getter -> observed keys from recv-backed handler chains.

    Only field/transitive records are used: framework/table contracts do not prove
    that the handler formal is connected to a network receive primitive.
    """
    path = os.path.join(ddir, "recv_param.json")
    if not os.path.isfile(path):
        return {}
    out = {}
    for binary, handlers in json.load(open(path)).get("binaries", {}).items():
        funcs = out.setdefault(binary, {})
        for entry in handlers.values():
            if entry.get("tier") not in ("field", "transitive"):
                continue
            observed = [k for k in entry.get("input_keys", [])
                        if isinstance(k, str) and len(k) > 1 and not k.isdigit()]
            for getter in entry.get("getters", []):
                funcs.setdefault(getter, set()).update(observed)
    return {binary: {getter: sorted(keys) for getter, keys in funcs.items()}
            for binary, funcs in out.items() if funcs}

def recv_handlers(ddir):
    """Return binary -> registered/recovered request-handler names for provenance audit."""
    path = os.path.join(ddir, "recv_param.json")
    if not os.path.isfile(path):
        return {}
    return {binary: sorted(handlers) for binary, handlers in
            json.load(open(path)).get("binaries", {}).items()}

def _model_tag():
    env = A.load_env()
    m = env.get("ANTHROPIC_MODEL", "claude-sonnet-5")
    return re.sub(r"[^A-Za-z0-9._-]", "-", m)

MODEL_TAG = _model_tag()   # results are tagged by model so different models never clobber
RESDIR = None

def elf_binaries(ddir):
    out = {}
    for f in os.listdir(ddir):
        p = os.path.join(ddir, f)
        if not os.path.isfile(p) or f.endswith((".json", ".i64", ".md", ".csv", ".txt")):
            continue
        try:
            if A._is_elf(p):
                out[f] = p
        except Exception:
            pass
    return out

def run_device(client, model, dev):
    device_started = time.perf_counter()
    ddir = os.path.join(DBV, dev)
    cp = os.path.join(ddir, "pre_llm_candidates.json")
    fcop = os.path.join(ddir, "final_call_output.json")
    kp = os.path.join(ddir, "key_value.json")
    if not (os.path.isfile(cp) and os.path.isfile(fcop)):
        return None
    cand = json.load(open(cp)).get("binaries", {})
    gold = json.load(open(kp)) if os.path.isfile(kp) else {}
    goldfns = set(f for v in gold.values() for f in v)
    kwp = os.path.join(ddir, "keywords.json")
    kw = json.load(open(kwp)) if os.path.isfile(kwp) else {}
    # call-site keys per binary basename
    keys_by_bin = {}
    for bp, br in json.load(open(fcop)).items():
        d = keys_by_bin.setdefault(os.path.basename(bp), {})
        for fn, info in br.get("callsite_result", {}).items():
            ks = [k for k in info.get("parameters", [])
                  if isinstance(k, str) and len(k) > 1 and not k.isdigit()]
            if fn not in d or len(ks) > len(d[fn]):
                d[fn] = ks
    chain_by_bin = {} if os.environ.get("KVFI_NO_CHAIN") else chain_guided_getters(ddir)
    recv_handlers_by_bin = recv_handlers(ddir)
    elfs = elf_binaries(ddir)
    found = {}   # binary basename -> {func: entry}
    found_v1, vote_audit = {}, {}
    n_cand = n_fe = n_general = n_chain = n_chain_added = 0
    binary_times = {}
    binary_llm_times = {}
    for bn in sorted(set(cand) | set(chain_by_bin)):
        info = cand.get(bn, {})
        general_names = list(info.get("candidates", {}).keys())
        general_set = set(general_names)
        chain_funcs = chain_by_bin.get(bn, {})
        names = general_names + sorted(set(chain_funcs) - general_set)
        n_general += len(general_names)
        n_chain += len(chain_funcs)
        n_chain_added += len(set(chain_funcs) - general_set)
        n_cand += len(names)
        # Only keys recovered at the getter's own call sites are valid evidence for
        # semantic origin verification.  Handler-wide strings from recv_param may
        # include defaults, addresses, and unrelated constants, so the recv chain
        # is used to localize candidates rather than relabel those strings as keys.
        keys = {fn: list(vals) for fn, vals in keys_by_bin.get(bn, {}).items()}
        if os.environ.get("KVFI_NO_FRONTEND"):
            surviving = list(names)
        else:
            surviving, _ = A.frontend_prune(general_names, keys, kw)
            # A chain-backed getter is independently localized and therefore does
            # not need to pass the string-matching frontend.
            surviving = list(dict.fromkeys(surviving + sorted(chain_funcs)))
        n_fe += len(surviving)
        binpath = elfs.get(bn) or os.path.join(ddir, bn)
        if not os.path.isfile(binpath):
            print(f"    [skip missing binary] {dev}/{bn}"); continue
        if not surviving:
            continue
        binary_started = time.perf_counter()
        audit = {}
        entries = A.analyze_binary(client, model, binpath, surviving, MIN_CONF,
                                   keys_by_func=keys, trace_out=audit,
                                   recv_handlers=recv_handlers_by_bin.get(bn, []))
        binary_times[bn] = round(time.perf_counter() - binary_started, 3)
        vote_audit[bn] = audit
        v1 = audit.get("entries_v1", {})
        if v1:
            found_v1[bn] = v1
        attempts = []
        for ft in audit.get("functions", {}).values():
            attempts.extend(ft.get("classification", {}).get("attempts", []))
            verification = ft.get("verification", {})
            attempts.extend(verification.get("origin", {}).get("attempts", []))
            attempts.extend(verification.get("role", {}).get("attempts", []))
        binary_llm_times[bn] = {
            "requests": len(attempts),
            "cache_hits": sum(1 for x in attempts if x.get("cache_hit")),
            "actual_request_seconds": round(sum(float(x.get("request_seconds") or 0)
                                                  for x in attempts), 3),
            "logical_request_seconds": round(sum(float(x.get("original_request_seconds") or 0)
                                                   for x in attempts), 3),
        }
        if entries:
            found[bn] = entries
    acc = set(f for e in found.values() for f in e)
    acc_v1 = set(f for e in found_v1.values() for f in e)
    tp = len(acc & goldfns); fp = len(acc - goldfns); fn = len(goldfns - acc)
    tp_v1 = len(acc_v1 & goldfns); fp_v1 = len(acc_v1 - goldfns); fn_v1 = len(goldfns - acc_v1)
    res = {"device": dev, "model": MODEL_TAG, "gold": sorted(goldfns), "n_cand": n_cand,
           "n_general_candidates": n_general, "n_chain_candidates": n_chain,
           "n_chain_added": n_chain_added,
           "n_frontend": n_fe, "found": sorted(acc), "tp": tp, "fp": fp, "fn": fn,
           "fp_funcs": sorted(acc - goldfns), "missed_funcs": sorted(goldfns - acc),
           "found_v1": sorted(acc_v1), "tp_v1": tp_v1, "fp_v1": fp_v1, "fn_v1": fn_v1,
           "fp_funcs_v1": sorted(acc_v1 - goldfns), "missed_funcs_v1": sorted(goldfns - acc_v1),
           "entries": found, "binary_analysis_seconds": binary_times,
           "entries_v1": found_v1, "vote_audit": vote_audit,
           "binary_llm_timing": binary_llm_times,
           "device_elapsed_seconds": round(time.perf_counter() - device_started, 3)}
    json.dump(res, open(os.path.join(RESDIR, dev.replace("/", "__") + ".json"), "w"),
              indent=2, ensure_ascii=False)
    return res

def main():
    global RESDIR
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--only", help="comma-sep device filter substring")
    ap.add_argument("--tag", required=True, help="configuration tag for an isolated result directory")
    ap.add_argument("--jobs", type=int, default=1, help="number of devices analyzed concurrently")
    ap.add_argument("--chain-guided-localization", action="store_true",
                    help="diagnostic: add getters observed on recv-to-handler chains to the backend candidate set")
    ap.add_argument("--no-chain", action="store_true",
                    help="deprecated compatibility flag; backend-only localization is now the default")
    ap.add_argument("--no-provenance", action="store_true",
                    help="disable shared-container producer/origin validation")
    args = ap.parse_args()
    if not args.chain_guided_localization or args.no_chain:
        os.environ["KVFI_NO_CHAIN"] = "1"
    else:
        os.environ.pop("KVFI_NO_CHAIN", None)
    if args.no_provenance:
        os.environ["KVFI_NO_PROVENANCE"] = "1"
    tag = re.sub(r"[^A-Za-z0-9._-]", "-", args.tag)
    root = os.environ.get("KVFI_EVAL_ROOT", os.path.join(DBV, "ablation"))
    RESDIR = os.path.join(root, tag + "__" + MODEL_TAG)
    os.makedirs(RESDIR, exist_ok=True)
    env = A.load_env(); client, model = A.make_client(env)
    client = client.with_options(timeout=180.0, max_retries=2)
    print(f"[unified] model={model}")
    man = json.load(open(os.path.join(DBV, "MANIFEST.json")))
    devs = sorted(set(m["dest"].rsplit("/", 1)[0] for m in man))
    if args.only:
        subs = args.only.split(","); devs = [d for d in devs if any(s in d for s in subs)]
    wall_started = time.perf_counter()

    def evaluate(dev):
        rf = os.path.join(RESDIR, dev.replace("/", "__") + ".json")
        if os.path.isfile(rf) and not args.force:
            res = json.load(open(rf))
        else:
            print(f"\n[device] {dev}", flush=True)
            res = run_device(client, model, dev)
        return dev, res

    TP = FP = FN = TP1 = FP1 = FN1 = 0
    done = 0; all_binary_times = []; llm_requests = cache_hits = 0
    general_candidates = chain_candidates = chain_added = 0
    actual_llm_seconds = logical_llm_seconds = 0.0
    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        futures = [pool.submit(evaluate, dev) for dev in devs]
        for future in as_completed(futures):
            dev, res = future.result()
            if res is None:
                print(f"  [no data] {dev}")
                continue
            TP += res["tp"]; FP += res["fp"]; FN += res["fn"]; done += 1
            general_candidates += res.get("n_general_candidates", res.get("n_cand", 0))
            chain_candidates += res.get("n_chain_candidates", 0)
            chain_added += res.get("n_chain_added", 0)
            TP1 += res.get("tp_v1", 0); FP1 += res.get("fp_v1", 0); FN1 += res.get("fn_v1", 0)
            all_binary_times.extend(res.get("binary_analysis_seconds", {}).values())
            for timing in res.get("binary_llm_timing", {}).values():
                llm_requests += timing.get("requests", 0)
                cache_hits += timing.get("cache_hits", 0)
                actual_llm_seconds += timing.get("actual_request_seconds", 0)
                logical_llm_seconds += timing.get("logical_request_seconds", 0)
            print(f"  {dev}: found {len(res['found'])} tp{res['tp']} fp{res['fp']} fn{res['fn']}"
                  f"{'  FP='+','.join(res['fp_funcs']) if res['fp_funcs'] else ''}"
                  f"{'  MISS='+','.join(res['missed_funcs']) if res['missed_funcs'] else ''}", flush=True)
    P = TP/(TP+FP)*100 if TP+FP else 0; R = TP/(TP+FN)*100 if TP+FN else 0
    P1 = TP1/(TP1+FP1)*100 if TP1+FP1 else 0; R1 = TP1/(TP1+FN1)*100 if TP1+FN1 else 0
    binary_times = sorted(all_binary_times)
    mean_time = sum(binary_times) / len(binary_times) if binary_times else None
    median_time = (binary_times[len(binary_times)//2] if len(binary_times) % 2 else
                   (binary_times[len(binary_times)//2-1] + binary_times[len(binary_times)//2]) / 2) \
                  if binary_times else None
    wall_seconds = round(time.perf_counter() - wall_started, 3)
    print(f"\n===== UNIFIED PIPELINE ({done} devices) =====")
    print(f"Precision {P:.1f}%  Recall {R:.1f}%  (tp={TP} fp={FP} fn={FN})")
    print(f"First-vote Precision {P1:.1f}%  Recall {R1:.1f}%  (tp={TP1} fp={FP1} fn={FN1})")
    print(f"Wall time {wall_seconds:.3f}s; binary mean={mean_time} median={median_time}")
    summary = {"tag": tag, "model": MODEL_TAG, "devices": done,
               "tp": TP, "fp": FP, "fn": FN, "precision": P, "recall": R,
               "v1": {"tp": TP1, "fp": FP1, "fn": FN1,
                      "precision": P1, "recall": R1},
               "jobs": max(1, args.jobs), "wall_seconds": wall_seconds,
               "binary_count": len(binary_times), "binary_mean_seconds": mean_time,
               "binary_median_seconds": median_time, "binary_times_seconds": binary_times,
               "general_candidates": general_candidates,
               "chain_candidates": chain_candidates, "chain_added": chain_added,
               "llm_requests": llm_requests, "cache_hits": cache_hits,
               "cache_misses": llm_requests - cache_hits,
               "actual_llm_request_seconds": round(actual_llm_seconds, 3),
               "logical_llm_request_seconds": round(logical_llm_seconds, 3),
               "temperature": A.TEMPERATURE,
               "classification_votes": A.VOTES, "verification_votes": A.VERIFY_VOTES,
               "frontend_matching": not bool(os.environ.get("KVFI_NO_FRONTEND")),
               "chain_guided_localization": not bool(os.environ.get("KVFI_NO_CHAIN")),
               "callsite_context": not bool(os.environ.get("KVFI_NO_CALLSITE")),
               "origin_role_verification": not bool(os.environ.get("KVFI_NO_VERIFY"))}
    summary["container_provenance"] = not bool(os.environ.get("KVFI_NO_PROVENANCE"))
    with open(os.path.join(RESDIR, "SUMMARY.json"), "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    main()
