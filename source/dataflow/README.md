# recv_param source identification (dataflow/)

Adds a second taint-source class to KVFI: **request-handler parameters that carry
network data** (`recv`/`read` → … → a handler function's argument). Complements the
existing key-value-getter sources.

> **Unified entry point:** `../run_unified.py` runs BOTH engines and merges them into one
> `deepin_result_path.json` — the deterministic structural engine here (free, covers the
> register-table family) plus the original LLM pipeline (general, covers any server/API).
> Getter functions the structural engine confirms are pruned from the LLM candidate list
> so the LLM does not re-classify them (cost saving, coverage unchanged). See "Unified
> pipeline" below.

Scope (Option A): the **register-table dispatch family** — servers that wire request
handlers with `register_fn(url_string, …, handler_fnptr, …)` and invoke them through a
handler table (GoAhead/webs and derivatives; ~18%+ of the dataset, concentrated in
D-Link / Tenda / TrendNet / ZyXEL). Config/plugin servers (lighttpd, nginx, uhttpd) are
out of scope; monolithic parsers (boa, custom httpd) need struct-field taint (future).

## How it works (all deterministic, no function names required)

1. **Discover registrations** — calls that pass both a string literal and a function
   pointer: `register_fn(url, …, handler)`. The handlers are candidate source functions.
2. **Resolve dispatch** — find the global handler table the register writes, the
   dispatcher that reads it and performs the indirect `(*handler)(…)` call, and the
   expression passed for each handler argument.
3. **Confirm via backward closure** — for each handler argument that is a request-struct
   field `wp[N]`, check that some writer of field `N` reaches a `recv`/`read` primitive
   on the call graph. If so, that parameter is a confirmed network-tainted source.
4. **Emit** the `(handler, param_index)` source plus the full `recv → … → handler` chain.
5. **Localize inputs** — inside each confirmed handler, find getter-style calls on the
   tainted request param carrying a string key (`websGetVar(wp, "devName")`) and record
   `(getter_fn, key)`. This recovers the SAME source class the original KVFI LLM pipeline
   produced — the key-value getter function plus its concrete keys — deterministically,
   and grouped per handler. Response/status literals (`ok`, `error`) and output calls
   (`websWrite`/`websError`) are filtered out. Emitted as `input_access` /
   per-source `input_keys` + `getters`.

The two source classes are therefore **complementary, not competing**: the getter-based
key-value sources (broad, any server/API — what the LLM pipeline covers) and the
handler-parameter recv_param sources (register-table family — what this module adds).
For the register-table family this module produces *both* deterministically; for other
servers (uhttpd/`GetNameValue`, XML/`xmldb_get_value`, cJSON, NVRAM …) the LLM getter
identification remains the general path.

The design and validation notes: this reproduces, from the bare `dir823/goahead` binary
with no names given, `websHNAPFuncHandler`'s `a7 = wp->query` and its chain
`recv → socketRead → websGetInput → parse(writes wp->query) → dispatch → handler`.

## Usage

```bash
# one binary
python3 dataflow/run_dataflow.py --binary /path/to/goahead
# whole firmware rootfs (writes results/<device>/recv_param_result.json)
python3 dataflow/run_dataflow.py --dir /path/to/rootfs --device dir823
```

`config.py` / `settings.toml` supply `ida_path`. If IDA user-plugins crash headless
runs, export `KVFI_IDAUSR=<empty dir>` to bypass them.

## Unified pipeline (`../run_unified.py`)

Single entry point that runs the structural engine **and** the original LLM pipeline and
merges both into one `result_path/<device>/deepin_result_path.json`:

```bash
# structural only (free, no LLM) — writes/creates the deepin file from structural sources
python3 run_unified.py --rootfs /path/to/rootfs --device dir823
# full union (structural + LLM getter identification; spends LLM budget, needs API keys)
python3 run_unified.py --rootfs /path/to/rootfs --device dir823 --with-llm
# single binary, structural only
python3 run_unified.py --binary /path/to/goahead --device dir823
```

Three general-getter engines can feed the union; pick per what keys you have:

- `--with-agent` — **Claude agent layer** (`../agent_analyze.py`), driven by the `.env`
  `ANTHROPIC_*` creds. Pre-stages `frontend_string → auto_define_funcs_dir →
  analyze_dir_callsite → parse_call_results` build the candidate list; `[prune]` removes
  structural-confirmed getters; then one Claude call per remaining candidate classifies it
  as a key-value getter (`value_pos/key_pos/pair_pos/is_nvram`, read from the real
  decompiled code — often more precise than the structural heuristic). Emits
  `agent_possible.json` (`origin:"agent"`). This is the working path for the current `.env`
  (Claude/gateway creds).
- `--with-llm` — the **original OpenAI/DeepSeek pipeline** (`llm_function →
  string_compare_before_uri → process_llm_uri_check → final_llm_pos_analysis`). Needs
  OpenAI + DeepSeek keys (the empty string literals in those scripts).
- neither — **structural only**, free.

The merge preserves every engine's entry and never clobbers: when the same getter is found
by more than one engine the fields combine (e.g. the agent's precise `key_pos` + the
structural `observed_keys`). `[prune]` (skippable with `--no-prune`) keeps the paid engines
from re-classifying getters the free structural engine already confirmed — coverage
unchanged, fewer model calls on the register-table family.

`agent_analyze.py` also runs standalone: `python3 agent_analyze.py --binary <bin> --funcs
f1,f2` classifies specific functions; `--device <dev>` classifies a run's
`final_possible.json`. It batch-decompiles candidates in one IDA session via
`dataflow/decompile_funcs.py`.

## Merge into main KVFI

`merge_into_kvfi.py` folds recv_param sources into KVFI's `deepin_result_path.json`
schema (`{binary: {func: {value_pos, key_pos, pair_pos, ...}}}`) so downstream taint
analysis consumes them alongside key-value sources. Each entry is tagged
`source_type` (`recv_param` vs `key_value`); a recv_param handler's `value_pos` is its
primary tainted param, with all tainted params in `tainted_params` and per-param chains
in `recv_param_detail`.

It also emits, from the localization step, the **getter functions themselves as
`key_value` sources** (`origin: "structural"`, `key_pos=1, pair_pos=0, value_pos=-1`,
plus `observed_keys` and `used_in_handlers`) — the same source class the original LLM
pipeline finds, so a register-table binary yields a unified result with no LLM call. When
a getter already exists in an incoming deepin file (LLM-classified), the merge only
back-fills fields it lacks and never clobbers the richer LLM entry.

```bash
# convert the batch aggregate to per-device deepin-schema files
python3 dataflow/merge_into_kvfi.py --recv dataflow/results_goahead_family.json --outdir dataflow/merged
# OR merge into one existing deepin_result_path.json in place (existing entries tagged key_value)
python3 dataflow/merge_into_kvfi.py --recv <recv.json> --deepin results/<device>/deepin_result_path.json
```

## Files

- `analyze_binary.py` — headless IDA analyzer for one binary (steps 1–4 above).
- `run_dataflow.py` — driver; single binary or a whole rootfs; analyzes a temp copy so
  the dataset stays clean and no pre-existing `.i64` is opened.
- `merge_into_kvfi.py` — fold results into KVFI's `deepin_result_path.json` schema.
- `results_goahead_family.json` — 28-binary batch result (26 hit, 2380 sources).
- `valueflow_wip.py` — WIP inter-procedural value-flow (see header); not wired in. The
  reachability-based chains in `analyze_binary.py` are exact for some binaries and
  approximate for others (goahead-family read paths route recv data through a
  struct-internal buffer + an arg-less `memcpy` the decompiler can't recover, which caps
  full-precision chains). Sources are correct regardless; only chain evidence is affected.

## Known limitations (deferred refinements)

- **Reachability over-approximation** — step 3 uses call-graph reachability to `recv`,
  not precise value-flow. The primary field (query) chain is exact; secondary fields
  (path/url) may confirm via a weaker path. A value-flow / writer-selection pass
  (optionally LLM-assisted) tightens this.
- **Duplicate / bogus registrations** — needs dedup; single-char "strings" from
  misparsed immediates should be filtered.
- **Nested dispatch** (`websFormDefine` / `websAspDefine`): handled transitively — when a
  dispatcher passes one of its OWN confirmed-tainted params to registered leaf handlers
  (e.g. `websFormHandler` forwards `wp->query` to every `form*` handler), those leaf
  params are confirmed as sources. This is where the feature subsumes form-handler
  identification (a Tenda httpd yields its ~117 `form*` handlers this way).
  *Remaining gap:* servers that register `websFormDefine`/`websAspDefine` but NO
  `websUrlHandlerDefine` (e.g. dir605L) never bootstrap the form dispatcher's request
  param, so they still yield 0 — they need the dispatcher's request param confirmed
  independently (from its call site or its own body reading recv).
