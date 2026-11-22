#!/usr/bin/env python3
# Claude agent analysis layer for KVFI.
#
# Replaces the original OpenAI/DeepSeek LLM stages (llm_function / process_llm_uri_check /
# final_llm_pos_analysis) with a single Claude call per candidate function, driven by the
# ANTHROPIC_* credentials in .env. It identifies key-value GETTER functions — the general
# source class the structural engine can't reach (uhttpd/GetNameValue, xmldb, cJSON,
# NVRAM, …) — and emits them in the deepin_result_path.json schema.
#
# Pipeline position: structural engine confirms the register-table family for free; its
# getters are pruned from the candidate list; this layer classifies the REMAINING
# candidates. Union goes to result_path/<device>/deepin_result_path.json.
#
#   # classify the LLM candidates of a rootfs run (final_possible.json must exist):
#   python3 agent_analyze.py --device dir823
#   # test on specific functions of one binary:
#   python3 agent_analyze.py --binary /path/to/httpd --funcs GetNameValue,websGetVar
#
# Creds: read from process env first, else parsed from .env (supports `export VAR=val`).
import os, re, sys, json, argparse, subprocess, tempfile, hashlib, threading, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import settings

HERE = os.path.dirname(os.path.abspath(__file__))
# callee-aware decompiler: each candidate is decompiled WITH its direct callees, so the
# classifier can see helper semantics (keyed lookup often lives in a helper / hsearch_r /
# json_object_object_get). Restores the original function+callee scheme.
DECOMPILER = os.path.join(HERE, "dataflow", "decompile_with_callees.py")
# callsite decompiler: decompiles a candidate's CALLERS so the classifier can see where the
# searched container comes from (request parse vs response/config object) — container origin.
DECOMPILE_CALLSITES = os.path.join(HERE, "dataflow", "decompile_callsites.py")
CONTAINER_PROVENANCE = os.path.join(HERE, "dataflow", "decompile_container_provenance.py")

def load_env():
    env = {}
    envfile = os.path.join(HERE, ".env")
    if os.path.exists(envfile):
        for line in open(envfile):
            m = re.match(r'(?:export\s+)?([A-Z_]+)=(.*)$', line.strip())
            if m:
                env[m.group(1)] = m.group(2).strip().strip('"').strip("'")
    # process env overrides .env
    for k in ("ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL", "ANTHROPIC_MODEL", "ANTHROPIC_API_KEY"):
        if os.environ.get(k):
            env[k] = os.environ[k]
    return env

def make_client(env):
    import anthropic
    kw = {}
    if env.get("ANTHROPIC_BASE_URL"): kw["base_url"] = env["ANTHROPIC_BASE_URL"]
    if env.get("ANTHROPIC_AUTH_TOKEN"): kw["auth_token"] = env["ANTHROPIC_AUTH_TOKEN"]
    elif env.get("ANTHROPIC_API_KEY"): kw["api_key"] = env["ANTHROPIC_API_KEY"]
    # bound each request: reasoning models (deepseek-v4-pro) occasionally hang; without a
    # timeout a single stuck call blocks the whole run. Retry a couple times on transient errors.
    kw["timeout"] = float(os.environ.get("KVFI_LLM_TIMEOUT", "90"))
    kw["max_retries"] = 2
    return anthropic.Anthropic(**kw), env.get("ANTHROPIC_MODEL", "claude-sonnet-5")

SYS = (
    "You are an expert program-analysis assistant for embedded HTTP servers. Determine "
    "whether `function` is used to GET A VALUE FROM KEY-VALUE PAIRS, where the KEY is an "
    "input-parameter string.\n"
    "RULES:\n"
    "1. The function MAY CALL OTHER FUNCTIONS (helpers or library imports). Understand the "
    "semantics of the called functions and use that to judge the whole function's purpose.\n"
    "2. It is a GETTER if it retrieves the value associated with a key: it searches / "
    "compares / parses to find the entry whose NAME matches the key argument, then returns "
    "that entry's VALUE. The lookup may be over ANY container: a parsed `key=value&...` "
    "string (strtok/strsep + strchr('=') + strcmp), an in-memory name->value table/list/"
    "struct (loop + strcmp/strcasecmp), a hash table (hsearch_r), a JSON object "
    "(json_object_object_get_ex + get_string), an XML tree (mxmlFindElement + mxmlGetText), "
    "or via a primitive (websGetVar / GetNameValue / getenv / boaGetVar). The container may "
    "be PASSED IN as an argument OR be GLOBAL — either counts.\n"
    "3. It must GET a value — NOT set, NOT update, and NOT merely match/compare. A function "
    "that returns a bool/status, or that only CALLS a getter and then acts on the result "
    "(compares it, writes config), is NOT a getter. The value may be RETURNED or written "
    "into an OUT-POINTER argument (`get(src, key, &out)` / `*outptr = value`).\n"
    "3b. LOCATING the entry by key COUNTS as a getter, even if a separate accessor extracts "
    "the scalar afterward. A function that searches a container for the entry whose NAME "
    "matches the key and RETURNS THAT ENTRY — the matching node / element / record / bucket / "
    "handle (e.g. mxmlFindElement returns the XML element named by the key; a hashtable lookup "
    "returns the entry struct; json_object_object_get returns the sub-object) — IS a getter: "
    "the returned item IS the key-selected data, and the caller reads the field off it. This is "
    "NOT the excluded 'merely match/compare' case — a matcher returns a bool/int answering "
    "yes/no or a count; a getter returns the LOCATED ITEM keyed by the input name.\n"
    "4. RETURN TYPE IS UNRELIABLE: a returned `int` may really be a POINTER/handle; bit "
    "shift/mask arithmetic (e.g. `(*(u16*)(v+20)<<16)|*(u16*)(v+18)`) is often the decompiler "
    "reassembling a pointer it failed to type. Judge by the RETRIEVAL, not the C return type. "
    "Args may be untyped (int/void*) and the function unnamed (sub_XXXX) — still judge by shape.\n"
    "5. DO NOT require proof that the key-value source is the CURRENT HTTP REQUEST — request "
    "context is judged SEPARATELY, downstream. A generic key=value / name-value getter counts "
    "even if you cannot see, from this function alone, where the container came from.\n"
    "6. FLAG the origin with is_config: set is_config=true if the value is retrieved from "
    "NVRAM / persistent config / device or system state (nvram_get and wrappers, config_get, "
    "the GetValue settings API, dbReadInt, get_mac / get_ssid / get_lang and similar device-"
    "state getters) or an i18n / static string table. These ARE key-value getters but are "
    "device config, not network input, so they are flagged for exclusion. A getter whose "
    "container is a request/CGI/form/query/json/xml/parsed-string table → is_config=false.\n"
    "7. CONTAINER ORIGIN via CALL-SITE: when CALL-SITE code is provided, use it to judge WHERE "
    "the searched container comes from. If the callers obtain/pass the container by PARSING THE "
    "HTTP REQUEST (cJSON_Parse on the POST body, the CGI form/query table, a webs/uhttpd request "
    "struct, a SOAP name-value item list), the value is NETWORK INPUT → is_config=false. If the "
    "container is a RESPONSE object the device itself built, a config/NVRAM blob, a file it read, "
    "or an internal table — often signalled by keys like err_code/version/status/up_info or by "
    "callers doing GetValue/config_get/nvram_get/fopen to fill it — it is NOT network input → "
    "is_config=true. If the call-site does not reveal the origin, fall back to shape.\n"
    "NOT getters (is_source=false): setters/writers, comparators/matchers returning bool, "
    "output/format functions, POSITIONAL/format parsers that unpack args by `%s`/position "
    "rather than by a named key (sscanf/ejArgs-style, argv[i] indexing), NO-KEY accessors "
    "(no key-string argument), functions whose value comes from getenv/config_get/GetValue, "
    "and functions that merely USE a getter's result (a CONSUMER that calls a getter then "
    "compares/writes/returns status is NOT itself a getter)."
)
# 0-based positions; -1 = return value; None/absent if not applicable.
PROMPT = """Decompiled function `{name}`:
```c
{code}
```
{callsite}Is `{name}` a key-value GETTER per the RULES — does it retrieve the VALUE associated with a
KEY (the key being an input-parameter string), via any container/parse/lookup, possibly
through helper calls, and GET (not set / not update / not merely match) that value, returning
it or writing it into an out-pointer arg? Do NOT require proof the container is the current
HTTP request; do NOT reject on the return C-type. Set is_config=true only if the value comes
from NVRAM / persistent config / device-state / i18n table.
Reply with ONLY a JSON object, no prose:
{{"is_source": true|false,
  "is_config": true|false,
  "value_pos": <int arg index receiving the value; -1 if returned>,
  "key_pos": <int arg index of the key string; -1 if none>,
  "pair_pos": <int arg index of the container/pairs searched; -1 if global or none>,
  "confidence": <0.0-1.0>,
  "evidence": "<how it retrieves the value by key>"}}"""

# Persistent LLM response cache.  A cache file represents one exact request and stores a
# sequence of independent samples, so three-vote self-consistency is preserved on reuse.
# The key covers every input that can affect the response.  Per-key locks permit unrelated
# functions/devices to run concurrently without corrupting a shared cache entry.
LLM_CACHE_DIR = os.environ.get("KVFI_LLM_CACHE_DIR", os.path.join(HERE, "dataset_by_vendor", "llm_cache"))
_CACHE_LOCKS = {}
_CACHE_LOCKS_GUARD = threading.Lock()

def _cache_lock(key):
    with _CACHE_LOCKS_GUARD:
        return _CACHE_LOCKS.setdefault(key, threading.Lock())

def _parse_json_text(txt):
    m = re.search(r'\{.*\}', txt or "", re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None

def _cached_json_sample(client, model, system, user, max_tokens, stage, sample_index):
    """Return (parsed JSON or None, audit record) for one deterministic sample slot."""
    request = {"model": model, "temperature": TEMPERATURE, "max_tokens": max_tokens,
               "system": system, "user": user, "stage": stage}
    canonical = json.dumps(request, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    key = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    path = os.path.join(LLM_CACHE_DIR, key[:2], key + ".json")
    read_cache = os.environ.get("KVFI_CACHE_READ", "1") != "0"
    write_cache = os.environ.get("KVFI_CACHE_WRITE", "1") != "0"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with _cache_lock(key):
        cached = {}
        if os.path.isfile(path):
            try:
                cached = json.load(open(path))
            except Exception:
                cached = {}
        samples = cached.get("samples", []) if isinstance(cached, dict) else []
        if read_cache and sample_index < len(samples):
            saved = samples[sample_index]
            return saved.get("parsed"), {
                "stage": stage, "sample_index": sample_index + 1, "cache_key": key,
                "cache_hit": True, "request_seconds": 0.0,
                "original_request_seconds": saved.get("request_seconds"),
                "parsed": saved.get("parsed"), "raw": saved.get("raw", "")}

        started = time.perf_counter()
        raw, error = "", None
        try:
            msg = client.messages.create(
                model=model, max_tokens=max_tokens, temperature=TEMPERATURE, system=system,
                messages=[{"role": "user", "content": user}])
            raw = "".join(getattr(b, "text", "") for b in msg.content).strip()
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
        elapsed = round(time.perf_counter() - started, 3)
        parsed = _parse_json_text(raw)
        saved = {"sample_index": sample_index + 1, "raw": raw, "parsed": parsed,
                 "request_seconds": elapsed, "error": error}
        if write_cache:
            while len(samples) <= sample_index:
                samples.append(None)
            samples[sample_index] = saved
            payload = {"cache_key": key, "request": request, "samples": samples}
            fd, tmp = tempfile.mkstemp(prefix=".cache_", suffix=".json", dir=os.path.dirname(path))
            try:
                with os.fdopen(fd, "w") as f:
                    json.dump(payload, f, indent=2, ensure_ascii=False)
                os.replace(tmp, path)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
        return parsed, {"stage": stage, "sample_index": sample_index + 1, "cache_key": key,
                        "cache_hit": False, "request_seconds": elapsed,
                        "original_request_seconds": elapsed, "parsed": parsed,
                        "raw": raw, "error": error}

def _provenance_prompt(name, provenance):
    if not provenance or not provenance.get("request_backed"):
        return ""
    producer = provenance.get("selected_producer") or {}
    container = provenance.get("selected_container") or {}
    return (
        "STATIC CONTAINER-PROVENANCE evidence (same binary):\n"
        f"- `{name}` reads shared container {container.get('name')} "
        f"({container.get('address')}).\n"
        f"- producer `{producer.get('name')}` writes that same container.\n"
        f"- producer signals: {', '.join(producer.get('signals') or [])}.\n"
        "These signals establish a per-request URL/form parameter table. Calls such as "
        "nvram_set that consume the getter's return value are downstream writes, not the "
        "origin of the returned value. Judge getter shape normally, but do not classify "
        "this request-backed container as persistent configuration.\n"
    )


def classify(client, model, name, code, callsite="", provenance=None, sample_index=0):
    if len(code) > 12000:
        code = code[:12000] + "\n/* ...truncated... */"
    cs = ""
    if callsite:
        cs = ("CALL-SITE code (how/where `%s` is called — use it to judge the CONTAINER's "
              "origin: request vs response/config):\n```c\n%s\n```\n" % (name, callsite[:10000]))
    pp = _provenance_prompt(name, provenance)
    user_prompt = PROMPT.format(name=name, code=code, callsite=cs)
    if pp:
        user_prompt += "\n" + pp
    return _cached_json_sample(
        client, model, SYS, user_prompt,
        4000, "classification", sample_index)


def decompile_container_provenance(binary, names):
    """Return per-getter producer/container evidence from one headless IDA run."""
    import shutil
    env = os.environ.copy()
    if os.environ.get("KVFI_IDAUSR"):
        env["IDAUSR"] = os.environ["KVFI_IDAUSR"]
    work = tempfile.mkdtemp(prefix="kvfi_prov_")
    local = os.path.join(work, os.path.basename(binary) or "bin")
    names_f = os.path.join(work, "names.json")
    out_f = os.path.join(work, "provenance.json")
    try:
        shutil.copy2(binary, local)
        json.dump(list(names), open(names_f, "w"))
        proc = subprocess.run(
            [settings.ida_path, "-A", f"-S{CONTAINER_PROVENANCE} {names_f} {out_f}", local],
            env=env, capture_output=True, text=True, timeout=1200)
        if os.path.exists(out_f):
            return json.load(open(out_f))
        print(f"  [!] IDA produced no container-provenance output for {binary} "
              f"(exit={proc.returncode}): {(proc.stderr or proc.stdout or '').strip()[-800:]}",
              file=sys.stderr)
    except Exception as e:
        print(f"  [!] container provenance {binary}: {e}", file=sys.stderr)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return {}

def decompile(binary, names):
    """Return {func_name: decompiled_c} via one headless IDA session."""
    env = os.environ.copy()
    if os.environ.get("KVFI_IDAUSR"):
        env["IDAUSR"] = os.environ["KVFI_IDAUSR"]
    work = tempfile.mkdtemp(prefix="kvfi_dec_")
    import shutil
    local = os.path.join(work, os.path.basename(binary) or "bin")
    names_f = os.path.join(work, "names.json")
    out_f = os.path.join(work, "code.json")
    try:
        shutil.copy2(binary, local)
        json.dump(list(names), open(names_f, "w"))
        proc = subprocess.run([settings.ida_path, "-A", f"-S{DECOMPILER} {names_f} {out_f}", local],
                              env=env, capture_output=True, text=True, timeout=1200)
        if os.path.exists(out_f):
            data = json.load(open(out_f))
            # callee-aware decompiler returns {"code": {...}, "_external": {...}};
            # the legacy per-function decompiler returns {func: code} directly.
            return data.get("code", data) if isinstance(data, dict) else {}
        print(f"  [!] IDA produced no decompiler output for {binary} (exit={proc.returncode}): "
              f"{(proc.stderr or proc.stdout or '').strip()[-800:]}", file=sys.stderr)
    except Exception as e:
        print(f"  [!] decompile {binary}: {e}", file=sys.stderr)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return {}

def decompile_callsites(binary, names):
    """Return {func_name: caller_code} — the decompiled CALLERS of each name, so the
    classifier can see the container's origin (request vs response/config)."""
    import shutil
    env = os.environ.copy()
    if os.environ.get("KVFI_IDAUSR"):
        env["IDAUSR"] = os.environ["KVFI_IDAUSR"]
    work = tempfile.mkdtemp(prefix="kvfi_cs_")
    local = os.path.join(work, os.path.basename(binary) or "bin")
    names_f = os.path.join(work, "names.json")
    out_f = os.path.join(work, "cs.json")
    try:
        shutil.copy2(binary, local)
        json.dump(list(names), open(names_f, "w"))
        proc = subprocess.run([settings.ida_path, "-A", f"-S{DECOMPILE_CALLSITES} {names_f} {out_f}", local],
                              env=env, capture_output=True, text=True, timeout=1200)
        if os.path.exists(out_f):
            return json.load(open(out_f))
        print(f"  [!] IDA produced no callsite output for {binary} (exit={proc.returncode}): "
              f"{(proc.stderr or proc.stdout or '').strip()[-800:]}", file=sys.stderr)
    except Exception as e:
        print(f"  [!] callsites {binary}: {e}", file=sys.stderr)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return {}

def _is_elf(path):
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except Exception:
        return False

def resolve_from_libs(binary, missing):
    """A getter that is a dynamically-linked IMPORT (e.g. mxmlFindElement) has no body in
    `binary` — it lives in a shared library shipped alongside it. For each still-missing
    name, grep the sibling files in the firmware dir for the symbol, then decompile its
    real definition (with callees) from the ELF that DEFINES it. Returns {name: code}."""
    missing = set(missing)
    if not missing:
        return {}
    found = {}
    # Search the binary's own dir first, then a shared library pool. The pool lets a lib
    # that ships with one device (e.g. libmxml.so added once) resolve the same import for
    # ANY device that lacks its own copy — grep the symbol, decompile the real def there.
    d = os.path.dirname(binary)
    search_dirs = [d]
    shared = os.environ.get("KVFI_SHARED_LIBS",
                            os.path.join(HERE, "dataset_by_vendor", "_shared_libs"))
    if os.path.isdir(shared) and os.path.abspath(shared) != os.path.abspath(d):
        search_dirs.append(shared)
    for sd in search_dirs:
        for fn in sorted(os.listdir(sd)):
            if not missing:
                break
            p = os.path.join(sd, fn)
            if p == binary or not os.path.isfile(p) or not _is_elf(p):
                continue
            # which still-missing symbols does this ELF contain (fast pre-filter)?
            here = set()
            for name in list(missing):
                try:
                    r = subprocess.run(["grep", "-aql", name, p], capture_output=True)
                    if r.returncode == 0:
                        here.add(name)
                except Exception:
                    pass
            if not here:
                continue
            code = decompile(p, list(here))      # decompile the real defs (+callees) from the lib
            for name, c in code.items():
                if c and c.strip():
                    found[name] = c
                    missing.discard(name)
                    print(f"    [resolved-import] {name} <- {os.path.basename(sd)}/{fn}")
        if not missing:
            break
    return found

def to_entry(verdict):
    return {
        "source_type": "key_value",
        "origin": "agent",
        "value_pos": verdict.get("value_pos", -1),
        "key_pos": verdict.get("key_pos", -1),
        "pair_pos": verdict.get("pair_pos", -1),
        "is_config": bool(verdict.get("is_config")),
        "confidence": verdict.get("confidence"),
        "evidence": verdict.get("evidence"),
    }

def _conf(v):
    try:
        return float(v.get("confidence") or 0)
    except (TypeError, ValueError):
        return 0.0

def is_accepted(v, min_conf):
    # a key-value getter (by shape) that is NOT device config/nvram (that's not network input).
    # Request-context is established separately; we do NOT require it here (shape-based ID,
    # matching the original 4o-mini getter prompt). Config getters are flagged and excluded.
    return bool(v and v.get("is_source") and not v.get("is_config") and _conf(v) >= min_conf)

# self-consistency: how many independent samples to majority-vote per function.
# Single-shot classification is noisy (parse-fails, self-contradictory rejects) and
# occasionally drops genuine getters (e.g. websGetVar). Sampling N times and taking the
# majority verdict makes the METHOD robust to that noise WITHOUT any hand-curated rescue.
VOTES = int(os.environ.get("KVFI_VOTES", "3"))
TEMPERATURE = float(os.environ.get("KVFI_TEMPERATURE", "0.1"))

def classify_voted(client, model, name, code, min_conf, votes=VOTES, callsite="",
                   provenance=None, trace=None):
    """Sample the classifier `votes` times (retrying parse-fails), majority-vote on
    is_accepted. Returns (accepted_bool, representative_verdict, n_yes, n_total)."""
    samples, audit = [], []
    attempts, cap = 0, votes * 3
    while len(samples) < votes and attempts < cap:
        v, rec = classify(client, model, name, code, callsite, provenance,
                          sample_index=attempts)
        audit.append(rec)
        attempts += 1
        if v is not None:
            samples.append(v)
    if not samples:
        if trace is not None:
            trace.update({"attempts": audit, "valid_samples": [],
                          "accepted_v1": False, "accepted_v3": False})
        return False, None, 0, 0
    request_backed = bool(provenance and provenance.get("request_backed"))
    def accepted_sample(v):
        # Provenance only resolves origin.  The model must still identify a genuine
        # getter by shape and confidence; consumers and setters are never rescued.
        if request_backed:
            return bool(v and v.get("is_source") and _conf(v) >= min_conf)
        return is_accepted(v, min_conf)
    yes = [v for v in samples if accepted_sample(v)]
    accepted = len(yes) > len(samples) / 2                      # strict majority
    pool = yes if accepted else [v for v in samples if v not in yes]
    rep = max(pool or samples, key=lambda v: v.get("confidence") or 0)
    if trace is not None:
        trace.update({"attempts": audit, "valid_samples": samples,
                      "accepted_v1": accepted_sample(samples[0]),
                      "accepted_v3": accepted, "yes_votes": len(yes),
                      "valid_vote_count": len(samples),
                      "request_backed_override": request_backed})
    return accepted, rep, len(yes), len(samples)

def _is_stub(code):
    """A body with no real semantics: absent, or a THUNK that just forwards to an imported /
    indirect target (mxmlFindElement -> return off_XXXX()). These need lib resolution."""
    c = (code or "").strip()
    if not c:
        return True
    if "attributes: thunk" in c:
        return True
    # tiny forwarder: `return off_XXXX();` / `return __imp_foo();` / `return j_foo();`
    if len(c) < 160 and re.search(r"return\s+(?:off_[0-9A-Fa-f]+|__imp_\w+|j_\w+)\s*\(", c):
        return True
    return False

# ---------------------------------------------------------------------------
# Frontend filter: prune candidates to those whose call-site keys hit the device's
# frontend keyword set (keywords.json). A candidate survives iff >=1 of its keys (or a
# '/'-split leaf of a SOAP path key) matches a frontend string. 0-hit AND 0-key are both
# dropped (after the callsite indirect-pointer fix no gold getter is 0-key). If the device
# has no/too-few frontend keywords, the filter is skipped (all candidates kept).
def _fe_norm(s):
    return re.sub(r'[^a-z0-9]', '', str(s).lower())

def _flatten_keywords(x, out):
    if isinstance(x, dict):
        for k, v in x.items():
            out.add(str(k)); _flatten_keywords(v, out)
    elif isinstance(x, list):
        for v in x:
            _flatten_keywords(v, out)
    else:
        out.add(str(x))
    return out

def _key_tokens(k):
    toks = {k}
    if "/" in k:
        toks |= {p for p in k.split("/") if len(p) > 1}
    return toks

def frontend_prune(names, keys_by_func, keywords_raw):
    """Return (surviving_names, hits_by_func). keywords_raw = parsed keywords.json (any shape)."""
    fe = {_fe_norm(x) for x in _flatten_keywords(keywords_raw, set())
          if isinstance(x, str) and len(str(x)) > 1}
    if len(fe) < 5:                       # no usable frontend -> skip filter, keep all
        return list(names), {}
    kept, hits = [], {}
    for n in names:
        m = {}
        for k in (keys_by_func or {}).get(n, []):
            for t in _key_tokens(k):
                if _fe_norm(t) in fe:
                    m[k] = t; break
        if m:                             # >=1 frontend hit -> keep (0-hit / 0-key dropped)
            kept.append(n); hits[n] = m
    return kept, hits

# ---------------------------------------------------------------------------
# Post-acceptance verifiers. Stage-1 (classify_voted) is recall-first and admits
# key-value getters by shape; these two stages remove the residual FP classes
# WITHOUT hurting recall (recall-first: reject only on unanimous non-source votes).
# They judge from the call-site KEYS the function is looked up with + stage-1 evidence.
VERIFY_VOTES = int(os.environ.get("KVFI_VERIFY_VOTES", "3"))

SYS_ORIGIN = (
 "A function is a confirmed key->value getter. Decide whether the KEYS it looks up are names a "
 "REMOTE HTTP CLIENT controls (query/POST/form/JSON/XML-body/SOAP-arg fields) — attacker network "
 "INPUT — or names the DEVICE reads from its OWN data a client does NOT send: a RESPONSE it "
 "fetched/built (update check / cloud reply: err_code, newest_ver, up_info, ver_info, status, "
 "retCode); CGI/SERVER ENVIRONMENT (SERVER_NAME, HTTPS, REQUEST_METHOD, REMOTE_ADDR, HTTP_*); "
 "PACKAGE/FILE METADATA labels ('Version: ', 'Filename: ', 'Description: ', 'Source: '); or NVRAM/"
 "persistent CONFIG. Judge from the key NAMES primarily. If the keys clearly include real client "
 "request fields (ssid/password/mac/username/hostname/enable/wan_*/form names), it is client input. "
 'Default client_input=true when keys look like UI/form field names. Reply ONLY JSON: '
 '{"client_input": true|false, "container": "request|response|environment|metadata|config|unknown"}')

SYS_ROLE = (
 "A function is a confirmed key->value getter reading CLIENT REQUEST data. Decide its ROLE: the "
 "PRIMARY getter a handler calls to fetch a named request field (primary=true), or a non-source "
 "role (primary=false): (b) HTTP HEADER / COOKIE / CGI-ENV reader — keys are standard header/env "
 "names (Content-Type, Content-Length, Authorization, WWW-Authenticate, Host, Referer, Cookie, "
 "Accept-Language, User-Agent, HTTP_HOST, SERVER_NAME); or (c) CONSUMER/AGGREGATOR — it does not "
 "return a single keyed value but CALLS another getter for SEVERAL keys it builds and MERGES them "
 "into one composite (e.g. joins wan_ipaddr+wan_gateway), or looks a value up then ACTS on it. "
 "KEEP as primary (default): a getter fetching request fields BY NAME, including one that internally "
 "uses strstr/XML-tag parsing (mxmlFindElement-like), an unnamed sub_XXXX wrapper, or one that "
 "validates/sanitizes the single value before returning it (websGetVarWithValidate). When unsure, "
 'answer primary. Reply ONLY JSON: {"primary": true|false, "role": "primary|header_reader|consumer"}')

def _json_reply(client, model, sys_prompt, user, stage, sample_index):
    return _cached_json_sample(client, model, sys_prompt, user, 1200, stage, sample_index)

def _vote(client, model, sys_prompt, user, key, votes=VERIFY_VOTES, stage="verification"):
    """Return count of votes where verdict[key] is truthy, over `votes` samples (retrying None)."""
    yes, samples, audit = 0, [], []
    attempt = 0
    for _ in range(votes):
        v = None
        for _t in range(3):
            v, rec = _json_reply(client, model, sys_prompt, user, stage, attempt)
            audit.append(rec); attempt += 1
            if v is not None:
                break
        if v is not None:
            samples.append(v)
        if v and v.get(key):
            yes += 1
    return yes, samples, audit

def _is_markup_helper(keys):
    """Deterministic string-helper signal: the getter is called with LITERAL markup tokens
    (XML/HTML tags with angle brackets, '<SSID>', '</Key>') rather than plain field names -> it
    is the low-level tag-slicer the real getter calls, not a source. Key-based because the LLM
    is unstable judging this for XML getters called with plain names (mxmlFindElement)."""
    ks = [k for k in (keys or []) if isinstance(k, str)]
    if not ks:
        return False
    bracket = sum(1 for k in ks if "<" in k or ">" in k)
    return bracket >= max(2, len(ks) // 2)

def verify_source(client, model, name, keys, evidence, votes=VERIFY_VOTES, trace=None,
                  provenance=None):
    """Stage-2 (origin) + stage-3 (role) on an accepted getter. Returns (keep, reason).
    Recall-first: reject only on UNANIMOUS non-source votes; keys absent -> skip that stage."""
    kstr = ", ".join(map(str, (keys or [])[:30]))
    keep_v1 = keep_v3 = True
    detail = {}
    request_backed = bool(provenance and provenance.get("request_backed"))
    if request_backed:
        producer = (provenance.get("selected_producer") or {}).get("name")
        container = (provenance.get("selected_container") or {}).get("name")
        detail["origin"] = {"static_request_provenance": True,
                            "producer": producer, "container": container}
    elif keys:
        u = f"function: {name}\ncall-site keys it looks up: {kstr}\nevidence: {evidence}"
        oy, osamples, oaudit = _vote(
            client, model, SYS_ORIGIN, u + "\n\nAre these keys remote-client request input?",
            "client_input", votes, "origin_verification")
        detail["origin"] = {"samples": osamples, "attempts": oaudit, "yes_votes": oy}
        # No parseable response is an unresolved verification, not a negative
        # vote.  Preserve the already-confirmed getter under the recall-first
        # policy and retain the audit trail for later inspection/retry.
        if osamples:
            keep_v1 = bool(osamples[0].get("client_input"))
            keep_v3 = oy != 0
        else:
            keep_v1 = keep_v3 = True
            detail["origin"]["unresolved"] = True
        if not keep_v3:
            if trace is not None:
                detail.update({"keep_v1": keep_v1, "keep_v3": False,
                               "reason_v1": "source" if keep_v1 else "non-request-container",
                               "reason_v3": "non-request-container"})
                trace.update(detail)
            return False, "non-request-container"
    if _is_markup_helper(keys):
        if trace is not None:
            detail.update({"keep_v1": False, "keep_v3": False,
                           "reason_v1": "markup-helper", "reason_v3": "markup-helper"})
            trace.update(detail)
        return False, "markup-helper"
    u = (f"function: {name}\nkeys it is called with: {kstr or '(none)'}\nevidence: {evidence}\n\n"
         "Is this the PRIMARY request-field getter, or a header-reader / consumer?")
    ry, rsamples, raudit = _vote(client, model, SYS_ROLE, u, "primary", votes,
                                 "role_verification")
    detail["role"] = {"samples": rsamples, "attempts": raudit, "yes_votes": ry}
    if rsamples:
        role_v1 = bool(rsamples[0].get("primary"))
        role_v3 = ry != 0
    else:
        role_v1 = role_v3 = True
        detail["role"]["unresolved"] = True
    keep_v1 = keep_v1 and role_v1
    keep_v3 = keep_v3 and role_v3
    if trace is not None:
        detail.update({"keep_v1": keep_v1, "keep_v3": keep_v3,
                       "reason_v1": "source" if keep_v1 else "role-header-or-consumer",
                       "reason_v3": "source" if keep_v3 else "role-header-or-consumer"})
        trace.update(detail)
    if not keep_v3:
        return False, "role-header-or-consumer"
    return True, "source"

def analyze_binary(client, model, binary, names, min_conf, votes=VOTES, keys_by_func=None,
                   trace_out=None, recv_handlers=None):
    code = decompile(binary, names)
    # candidates with no real local body (absent OR a thunk stub) are dynamically-linked
    # imports (mxmlFindElement, cJSON_GetObjectItem, ...) — resolve their real definition
    # from a sibling shared library so the classifier judges the actual lookup, not a stub.
    missing = [n for n in names if _is_stub(code.get(n))]
    if missing:
        code.update(resolve_from_libs(binary, missing))
    # container-origin context: decompile each candidate's callers so the classifier can see
    # whether the searched container is the request or a response/config object (kills FPs like
    # cJSON on a firmware-update response, dbReadInt on config). Skippable via KVFI_NO_CALLSITE.
    callsites = {}
    if not os.environ.get("KVFI_NO_CALLSITE"):
        callsites = decompile_callsites(binary, [n for n in names if code.get(n)])
    provenance = {}
    if not os.environ.get("KVFI_NO_PROVENANCE"):
        provenance = decompile_container_provenance(binary, [n for n in names if code.get(n)])
        # Handler registration/recv evidence supports the lifecycle interpretation.  It
        # is recorded for audit, but request_backed is established by the table producer.
        registered = set(recv_handlers or [])
        if registered:
            for p in provenance.values():
                p["recv_handler_intersection"] = sorted(
                    registered.intersection(p.get("getter_callers") or []))
    print(f"  decompiled {len(code)}/{len(names)} candidate(s) of {os.path.basename(binary)}"
          f"  (+callsites {len(callsites)}, provenance "
          f"{sum(1 for p in provenance.values() if p.get('request_backed'))}, votes={votes})")
    entries, entries_v1 = {}, {}
    function_traces = {}
    for name in names:
        c = code.get(name)
        if not c:
            continue
        cls_trace = {}
        prov = provenance.get(name) or {}
        accepted, v, ny, nt = classify_voted(client, model, name, c, min_conf, votes,
                                              callsite=callsites.get(name, ""), provenance=prov,
                                              trace=cls_trace)
        accepted_v1 = bool(cls_trace.get("accepted_v1"))
        first_v = (cls_trace.get("valid_samples") or [None])[0]
        keep, keep_v1, reason = True, True, "source"
        verify_trace = {}
        if nt == 0:
            print(f"    [parse-fail] {name}")
        elif accepted or accepted_v1:
            # recall-first post-verification: drop residual FP classes (response/env/metadata/
            # config containers, HTTP-header/cookie readers, markup helpers, aggregator consumers).
            if not os.environ.get("KVFI_NO_VERIFY"):
                keys = (keys_by_func or {}).get(name, [])
                evidence_v = v if accepted else first_v
                keep, reason = verify_source(client, model, name, keys,
                                             (evidence_v or {}).get("evidence") or "",
                                             trace=verify_trace, provenance=prov)
                keep_v1 = bool(verify_trace.get("keep_v1"))
            if accepted and keep:
                entries[name] = to_entry(v)
                if prov.get("request_backed"):
                    entries[name]["is_config"] = False
                    entries[name]["origin"] = "agent+container-provenance"
                    entries[name]["request_provenance"] = {
                        "container": prov.get("selected_container"),
                        "producer": (prov.get("selected_producer") or {}).get("name"),
                        "signals": (prov.get("selected_producer") or {}).get("signals", []),
                        "recv_handlers": prov.get("recv_handler_intersection", []),
                    }
                print(f"    [source] {name:24} key_pos={v.get('key_pos')} "
                      f"conf={v.get('confidence')} vote={ny}/{nt}")
            elif accepted:
                print(f"    [verify-drop:{reason}] {name:24} vote={ny}/{nt}")
            if accepted_v1 and keep_v1 and first_v:
                entries_v1[name] = to_entry(first_v)
                if prov.get("request_backed"):
                    entries_v1[name]["is_config"] = False
                    entries_v1[name]["origin"] = "agent+container-provenance"
        else:
            why = "config-getter" if v and v.get("is_source") and v.get("is_config") else \
                  ("not-getter" if v else "parse-fail")
            print(f"    [{why}] {name:24} vote={ny}/{nt} {(v.get('evidence') or '')[:60] if v else ''}")
        function_traces[name] = {
            "classification": cls_trace,
            "verification": verify_trace,
            "selected_v1": name in entries_v1,
            "selected_v3": name in entries,
            "container_provenance": prov,
        }
    if trace_out is not None:
        trace_out.update({"functions": function_traces, "entries_v1": entries_v1,
                          "entries_v3": entries})
    return entries

def main():
    ap = argparse.ArgumentParser(description="Claude agent getter-identification layer")
    ap.add_argument("--device")
    ap.add_argument("--binary")
    ap.add_argument("--funcs", help="comma-separated function names (with --binary)")
    ap.add_argument("--min-conf", type=float, default=0.6)
    ap.add_argument("--out", help="write deepin entries here (default: device dir)")
    args = ap.parse_args()

    env = load_env()
    if not (env.get("ANTHROPIC_AUTH_TOKEN") or env.get("ANTHROPIC_API_KEY")):
        sys.exit("no ANTHROPIC_AUTH_TOKEN / ANTHROPIC_API_KEY in env or .env")
    client, model = make_client(env)
    print(f"[agent] model={model} endpoint={env.get('ANTHROPIC_BASE_URL','default')}")

    result = {}   # binary -> {func: entry}
    if args.binary:
        names = [s for s in (args.funcs or "").split(",") if s]
        if not names:
            sys.exit("--binary needs --funcs f1,f2,...")
        e = analyze_binary(client, model, args.binary, names, args.min_conf)
        if e: result[args.binary] = e
        out = args.out or os.path.splitext(args.binary)[0] + ".agent.json"
    elif args.device:
        devdir = os.path.join(settings.result_path, args.device)
        fp = os.path.join(devdir, "final_possible.json")
        if not os.path.exists(fp):
            sys.exit(f"{fp} missing — run the pre-LLM stages first")
        candidates = json.load(open(fp))
        # call-site keys per binary/func (for the post-acceptance verifiers) from the
        # string-match output; keyed by basename so it survives rootfs path differences.
        keys_by_bin = {}
        fco = os.path.join(devdir, "final_call_output.json")
        if os.path.exists(fco):
            for bp, br in json.load(open(fco)).items():
                d = keys_by_bin.setdefault(os.path.basename(bp), {})
                for fn, info in br.get("callsite_result", {}).items():
                    ks = [k for k in info.get("parameters", [])
                          if isinstance(k, str) and len(k) > 1 and not k.isdigit()]
                    if fn not in d or len(ks) > len(d[fn]):
                        d[fn] = ks
        for binary, funcs in candidates.items():
            if not os.path.exists(binary):
                print(f"  [skip missing] {binary}"); continue
            e = analyze_binary(client, model, binary, list(funcs.keys()), args.min_conf,
                               keys_by_func=keys_by_bin.get(os.path.basename(binary)))
            if e: result[binary] = e
        out = args.out or os.path.join(devdir, "agent_possible.json")
    else:
        ap.error("need --device or --binary")

    json.dump(result, open(out, "w"), indent=2, ensure_ascii=False)
    n = sum(len(v) for v in result.values())
    print(f"[=] {n} getter source(s) across {len(result)} binary(ies) -> {out}")

if __name__ == "__main__":
    main()
