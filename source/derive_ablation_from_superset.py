#!/usr/bin/env python3
"""Derive frontend-filtered ablations from the no_frontend three-vote superset."""
import json
import os

import agent_analyze as A


HERE = os.path.dirname(os.path.abspath(__file__))
DBV = os.path.join(HERE, "dataset_by_vendor")
SUPERSET = os.path.join(DBV, "ablation", "no_frontend__deepseek-v4-flash")
OUT = os.path.join(DBV, "ablation", "DERIVED_ABLATION_SUMMARY.json")

# Targeted regression records that are part of the current Full result.  The
# original no_frontend snapshot predates producer recovery for TEW-800/815 and
# contains empty model responses for TEW-820/828.  Keep that snapshot immutable
# and overlay only the independently rerun, three-vote decisions here.
FULL_REGRESSIONS = {
    "TRENDnet/tew_800": os.path.join(
        DBV, "ablation", "container-provenance-regression__deepseek-v4-flash",
        "TRENDnet__tew_800.json"),
    "TRENDnet/tew_815": os.path.join(
        DBV, "ablation", "container-provenance-regression__deepseek-v4-flash",
        "TRENDnet__tew_815.json"),
    "TRENDnet/tew_820": os.path.join(
        DBV, "ablation", "retry-fn-20260811__deepseek-v4-flash",
        "TRENDnet__tew_820.short-context.agent.json"),
    "TRENDnet/tew_828": os.path.join(
        DBV, "ablation", "retry-fn-20260811__deepseek-v4-flash",
        "TRENDnet__tew_828.agent.json"),
}


def accepted_regression_functions(device):
    """Return binary -> accepted functions from a targeted Full regression."""
    path = FULL_REGRESSIONS.get(device)
    if not path or not os.path.isfile(path):
        return {}
    result = json.load(open(path))
    # Unified-evaluation records wrap functions under `entries`; single-function
    # agent records directly map a binary path to its accepted entries.
    entries = result.get("entries", result)
    return {os.path.basename(binary): set(functions)
            for binary, functions in entries.items()}


def keys_by_binary(device_dir):
    path = os.path.join(device_dir, "final_call_output.json")
    result = {}
    for binary_path, binary_result in json.load(open(path)).items():
        funcs = result.setdefault(os.path.basename(binary_path), {})
        for name, info in binary_result.get("callsite_result", {}).items():
            keys = [key for key in info.get("parameters", [])
                    if isinstance(key, str) and len(key) > 1 and not key.isdigit()]
            if name not in funcs or len(keys) > len(funcs[name]):
                funcs[name] = keys
    return result


def frontend_survivors(device_dir):
    candidates = json.load(open(os.path.join(device_dir, "pre_llm_candidates.json"))).get(
        "binaries", {})
    keyword_path = os.path.join(device_dir, "keywords.json")
    keywords = json.load(open(keyword_path)) if os.path.isfile(keyword_path) else {}
    keys = keys_by_binary(device_dir)
    result = {}
    for binary, info in candidates.items():
        names = list(info.get("candidates", {}).keys())
        kept, _ = A.frontend_prune(names, keys.get(binary, {}), keywords)
        result[binary] = set(kept)
    return result


def scores(found, gold):
    return {
        "tp": len(found & gold),
        "fp": len(found - gold),
        "fn": len(gold - found),
        "found": sorted(found),
        "fp_funcs": sorted(found - gold),
        "missed_funcs": sorted(gold - found),
    }


def aggregate(per_device, key):
    tp = sum(row[key]["tp"] for row in per_device)
    fp = sum(row[key]["fp"] for row in per_device)
    fn = sum(row[key]["fn"] for row in per_device)
    return {
        "tp": tp, "fp": fp, "fn": fn,
        "precision": tp / (tp + fp) * 100 if tp + fp else 0,
        "recall": tp / (tp + fn) * 100 if tp + fn else 0,
    }


def main():
    per_device = []
    for filename in sorted(os.listdir(SUPERSET)):
        if not filename.endswith(".json") or filename == "SUMMARY.json":
            continue
        result = json.load(open(os.path.join(SUPERSET, filename)))
        device = result["device"]
        device_dir = os.path.join(DBV, device)
        kept = frontend_survivors(device_dir)
        gold_path = os.path.join(device_dir, "key_value.json")
        if os.path.isfile(gold_path):
            gold_data = json.load(open(gold_path))
            gold = set(name for names in gold_data.values() for name in names)
        else:
            gold = set(result.get("gold", []))
        full_v1 = set()
        full_v3 = set()
        n_frontend = 0
        for binary, audit in result.get("vote_audit", {}).items():
            allowed = kept.get(binary, set())
            n_frontend += len(allowed)
            for name, trace in audit.get("functions", {}).items():
                if name not in allowed:
                    continue
                if trace.get("selected_v1"):
                    full_v1.add(name)
                if trace.get("selected_v3"):
                    full_v3.add(name)
        regression = accepted_regression_functions(device)
        for binary, names in regression.items():
            # A regression may only restore a Full decision for a candidate that
            # passes the same front-end matching used by Full.
            accepted = names.intersection(kept.get(binary, set()))
            full_v1.update(accepted)
            full_v3.update(accepted)
        per_device.append({
            "device": device,
            "frontend_candidates": n_frontend,
            "full_v1": scores(full_v1, gold),
            "full_v3": scores(full_v3, gold),
        })

    summary = {
        "source": SUPERSET,
        "derivation": (
            "Reapply frontend_prune to the no_frontend superset, use the stored "
            "selected_v1/selected_v3 decisions, and overlay the four targeted "
            "three-vote Full regression records listed in full_regressions."
        ),
        "full_regressions": FULL_REGRESSIONS,
        "devices": len(per_device),
        "frontend_candidates": sum(row["frontend_candidates"] for row in per_device),
        "full_v1": aggregate(per_device, "full_v1"),
        "full_v3": aggregate(per_device, "full_v3"),
        "per_device": per_device,
    }
    with open(OUT, "w") as output:
        json.dump(summary, output, indent=2, ensure_ascii=False)
    print(json.dumps({key: value for key, value in summary.items() if key != "per_device"},
                     indent=2, ensure_ascii=False))
    print(OUT)


if __name__ == "__main__":
    main()
