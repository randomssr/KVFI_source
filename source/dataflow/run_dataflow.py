#!/usr/bin/env python3
# Driver for the recv_param source analyzer.
# Runs analyze_binary.py (headless IDA) on one binary or every ELF executable in a
# firmware directory, and aggregates confirmed recv_param sources.
#
#   python3 run_dataflow.py --binary /path/to/goahead [--out out.json]
#   python3 run_dataflow.py --dir /path/to/rootfs --device dir823
#
# Notes
#  * Analyzes the RAW binary (IDA builds its own database), so it does not need a
#    pre-existing .i64 and is independent of the IDA version that produced one.
#  * If your IDA user-plugins crash headless runs, export KVFI_IDAUSR=<empty dir>
#    to bypass them (this driver forwards it as IDAUSR).
import os, sys, json, argparse, subprocess, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import settings

HERE = os.path.dirname(os.path.abspath(__file__))
ANALYZER = os.path.join(HERE, "analyze_binary.py")

def is_elf_exe(path):
    try:
        with open(path, "rb") as f:
            head = f.read(20)
    except Exception:
        return False
    if head[:4] != b"\x7fELF":
        return False
    # e_type at offset 16 (2 bytes, endianness per EI_DATA at offset 5)
    le = head[5] == 1
    etype = int.from_bytes(head[16:18], "little" if le else "big")
    return etype in (2, 3)  # ET_EXEC / ET_DYN

def analyze_one(binary):
    import shutil
    env = os.environ.copy()
    if os.environ.get("KVFI_IDAUSR"):
        env["IDAUSR"] = os.environ["KVFI_IDAUSR"]
    # analyze a copy in a temp dir: keeps the dataset clean and avoids opening a
    # pre-existing .i64 that a newer IDA may have produced (version mismatch).
    work = tempfile.mkdtemp(prefix="kvfi_df_")
    local = os.path.join(work, os.path.basename(binary) or "bin")
    out_path = os.path.join(work, "out.json")
    try:
        shutil.copy2(binary, local)
        cmd = [settings.ida_path, "-A", f"-S{ANALYZER} {out_path}", local]
        subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=1200)
        if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
            with open(out_path) as f:
                res = json.load(f)
            for s in res.get("sources", []):   # record the real path, not the temp copy
                s["binary"] = binary
            return res
    except Exception as e:
        print(f"  [!] {binary}: {e}", file=sys.stderr)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return None

# System/3rd-party libraries that never carry request handlers — skip them so that
# INCLUDING application .so (cgi modules like cste_modules/*.so, libcste*) doesn't drag in
# every libc/ssl/… in the firmware. Substring match on the basename, lowercased.
SYSLIB = (
    "libc.", "libc-", "ld-", "ld.so", "libpthread", "libdl", "librt", "libm.", "libm-",
    "libgcc", "libstdc++", "libssl", "libcrypto", "libz.", "libnl", "libuclibc", "libubox",
    "libubus", "libresolv", "libnss", "libcurl", "libxml", "libpcre", "libsqlite", "libcares",
    "libjson", "libblobmsg", "libiwinfo", "libgmp", "libncurses", "libreadline", "libffi",
    "libexpat", "libpng", "libjpeg", "libcrypt", "libmosquitto", "libpcap", "libevent",
    "libexif", "libupnp", "libfreetype", "libglib", "libgobject", "libintl", "libiconv",
    "libform", "libmenu", "libpanel", "libtinfo", "libbz2", "liblzo", "liblzma", "libmulti",
    "libapmib", "libebtc", "libavcodec", "libavformat", "libavutil", "libpthread-",
)
def _is_syslib(fn):
    n = fn.lower()
    return any(s in n for s in SYSLIB)

def find_binaries(root):
    for dirpath, _, files in os.walk(root):
        for fn in files:
            p = os.path.join(dirpath, fn)
            if fn.endswith((".i64", ".idb")):
                continue
            is_so = fn.endswith(".so") or ".so." in fn
            if is_so and _is_syslib(fn):          # analyze APP .so, skip system libs
                continue
            if os.path.islink(p):
                continue
            if is_elf_exe(p):
                yield p

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary")
    ap.add_argument("--dir")
    ap.add_argument("--device")
    ap.add_argument("--out")
    args = ap.parse_args()

    all_sources = {}   # binary -> [sources]
    if args.binary:
        res = analyze_one(args.binary)
        if res and res.get("sources"):
            all_sources[args.binary] = res["sources"]
        out = args.out or (os.path.splitext(args.binary)[0] + ".recv_param.json")
    elif args.dir:
        if not args.device:
            print("--device required with --dir", file=sys.stderr); sys.exit(2)
        bins = list(find_binaries(args.dir))
        print(f"[*] {len(bins)} ELF executables under {args.dir}")
        for i, b in enumerate(bins, 1):
            print(f"[{i}/{len(bins)}] {b}")
            res = analyze_one(b)
            if res and res.get("sources"):
                all_sources[b] = res["sources"]
                print(f"      -> {len(res['sources'])} recv_param sources")
        outdir = os.path.join(settings.result_path, args.device)
        os.makedirs(outdir, exist_ok=True)
        out = os.path.join(outdir, "recv_param_result.json")
    else:
        print("need --binary or --dir", file=sys.stderr); sys.exit(2)

    with open(out, "w") as f:
        json.dump(all_sources, f, indent=2, ensure_ascii=False)
    n = sum(len(v) for v in all_sources.values())
    print(f"[=] {n} recv_param sources across {len(all_sources)} binaries -> {out}")

if __name__ == "__main__":
    main()
