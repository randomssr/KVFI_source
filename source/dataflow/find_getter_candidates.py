# Relaxed getter-candidate finder (diagnostic): list functions that are CALLED WITH A
# STRING-LITERAL ARG anywhere in the binary, with call count and sample keys. No
# call-count threshold and no name filtering (only true libc names dropped), so it
# surfaces getters the production candidate filter (count>3, name/blacklist) would miss.
#   idat64 -A -S"find_getter_candidates.py <out.json> [topN]" <binary>
import idaapi, idautils, idc, ida_hexrays, ida_auto, ida_pro, json
from collections import defaultdict

LIBC = {"strcmp","strncmp","strcasecmp","strncasecmp","strstr","strchr","strrchr",
        "strtok","strtok_r","memcmp","memcpy","memset","sprintf","snprintf","sscanf",
        "printf","fprintf","syslog","strcat","strncat","strcpy","strncpy","strlen",
        "atoi","atol","strtoul","strtol","fopen","open","system","popen","getenv",
        "setenv","printf_chk","free","malloc"}

def deco(ea):
    try: return ida_hexrays.decompile(ea)
    except Exception: return None

def callee_ea(e):
    x=e.x
    while x is not None and x.op==ida_hexrays.cot_cast: x=x.x
    return x.obj_ea if (x is not None and x.op==ida_hexrays.cot_obj) else None

def strlit(e):
    if e is None: return None
    if e.op==ida_hexrays.cot_obj:
        s=idc.get_strlit_contents(e.obj_ea)
        if s: return s.decode("utf-8","ignore")
    if e.op==ida_hexrays.cot_str: return e.string
    for c in (getattr(e,'x',None),getattr(e,'y',None),getattr(e,'z',None)):
        if isinstance(c,ida_hexrays.cexpr_t):
            r=strlit(c)
            if r: return r
    return None

class V(ida_hexrays.ctree_visitor_t):
    def __init__(s): ida_hexrays.ctree_visitor_t.__init__(s,ida_hexrays.CV_FAST); s.calls=[]
    def visit_expr(s,e):
        if e.op==ida_hexrays.cot_call: s.calls.append(e)
        return 0

def main():
    ida_auto.auto_wait(); ida_hexrays.init_hexrays_plugin()
    out_path=idc.ARGV[1]; topN=int(idc.ARGV[2]) if len(idc.ARGV)>2 else 20
    cnt=defaultdict(int); keys=defaultdict(set)
    for fea in idautils.Functions():
        cf=deco(fea)
        if not cf: continue
        v=V(); v.apply_to(cf.body,None)
        for e in v.calls:
            cea=callee_ea(e)
            if cea is None: continue
            nm=(idc.get_name(cea) or "").split("@")[0]
            if not nm or nm in LIBC or nm.lstrip("._") in LIBC: continue
            args=list(e.a) if e.a is not None else []
            ks=[strlit(a) for a in args]
            ks=[k for k in ks if k and 2<=len(k)<=40 and not any(o<32 for o in map(ord,k))]
            if ks:
                cnt[nm]+=1
                for k in ks[:1]: keys[nm].add(k)
    ranked=sorted(cnt.items(), key=lambda x:-x[1])[:topN]
    out={nm:{"strcall_count":c,"sample_keys":sorted(keys[nm])[:8]} for nm,c in ranked}
    json.dump(out, open(out_path,"w"), ensure_ascii=False, indent=1)
    ida_pro.qexit(0)

main()
