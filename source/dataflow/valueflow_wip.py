# Option 2-full value-flow — WORK IN PROGRESS (not wired into analyze_binary.py)
#
# Status: viable foundation, NOT complete.
#  DONE:  library-call prototypes via SetType (fixes empty ctree args for recv/memcpy),
#         net_out fixpoint scaffold, field-write value-check. First-level recv wrappers
#         (functions calling recv directly into an out-param) are correctly identified.
#  TODO:  multi-level inter-procedural propagation through diverse wrapper idioms
#         (socketRead -> websGetInput -> parser) — 2nd level does not yet propagate;
#         needs per-idiom handling of local-buffer forwarding / ret vs out-param.
#  Run:   idat64 -A -S"valueflow_wip.py <out.json> <field_elem_index>" <binary>
#
import idaapi, idautils, idc, ida_hexrays, ida_auto, ida_pro, json
Hx = ida_hexrays
RECV_OUT = {"recv":1,"recvfrom":1,"recvmsg":1,"read":1,"readv":1,"SSL_read":1,"SSL_read_ex":1}
COPY = {"memcpy":(0,1),"memmove":(0,1),"strcpy":(0,1),"strncpy":(0,1),"strlcpy":(0,1),
        "strcat":(0,1),"strncat":(0,1),"bcopy":(1,0),"snprintf":(0,2),"sprintf":(0,1)}
def deco(ea):
    try: return Hx.decompile(ea)
    except Exception: return None
def rawname(ea):
    f=idaapi.get_func(ea); return idaapi.get_func_name(f.start_ea) if f else (idc.get_name(ea) or hex(ea))
def norm(ea):
    n=rawname(ea)
    if n.startswith("j_"): n=n[2:]
    n=n.split("@")[0].lstrip(".")
    return n
def val_base(e):
    while e is not None and e.op==Hx.cot_cast: e=e.x
    if e is None: return None
    if e.op==Hx.cot_var: return e.v.idx
    if e.op==Hx.cot_ref: return val_base(e.x)
    return None
def write_base(e):
    if e is None: return None
    if e.op==Hx.cot_var: return e.v.idx
    if e.op in (Hx.cot_ptr,Hx.cot_memptr,Hx.cot_memref,Hx.cot_cast,Hx.cot_ref,Hx.cot_idx,Hx.cot_add):
        return write_base(e.x)
    return None
def field_elem(lhs):
    if lhs.op==Hx.cot_idx and lhs.y.op==Hx.cot_num: return lhs.y.numval(), val_base(lhs.x)
    if lhs.op==Hx.cot_ptr and lhs.x.op==Hx.cot_add and lhs.x.y.op==Hx.cot_num: return lhs.x.y.numval()//4, val_base(lhs.x.x)
    return None,None
def lvars_in(e):
    out=set()
    def rec(x):
        if x is None: return
        if x.op==Hx.cot_var: out.add(x.v.idx); return
        for c in (getattr(x,'x',None),getattr(x,'y',None),getattr(x,'z',None)):
            if isinstance(c,Hx.cexpr_t): rec(c)
    rec(e); return out
def calls_in(e):
    out=[]
    def rec(x):
        if x is None: return
        if x.op==Hx.cot_call: out.append(x)
        for c in (getattr(x,'x',None),getattr(x,'y',None),getattr(x,'z',None)):
            if isinstance(c,Hx.cexpr_t): rec(c)
    rec(e); return out
def callee_ea(e):
    x=e.x
    while x is not None and x.op==Hx.cot_cast: x=x.x
    return x.obj_ea if (x is not None and x.op==Hx.cot_obj) else None
class Collect(Hx.ctree_visitor_t):
    def __init__(s): Hx.ctree_visitor_t.__init__(s,Hx.CV_FAST); s.asg=[]; s.call=[]; s.ret=[]
    def visit_expr(s,e):
        if e.op==Hx.cot_asg: s.asg.append((e.x,e.y))
        elif e.op==Hx.cot_call: s.call.append(e)
        return 0
    def visit_insn(s,i):
        if i.op==Hx.cit_return and i.creturn and i.creturn.expr is not None: s.ret.append(i.creturn.expr)
        return 0
def argmap(cf):
    m={}; idx=0
    for i,lv in enumerate(cf.lvars):
        if lv.is_arg_var: m[i]=idx; idx+=1
    return m
def analyze_fn(cf, net_out):
    c=Collect(); c.apply_to(cf.body,None)
    taint=set()
    def cname(e):
        ce=callee_ea(e); return norm(ce) if ce is not None else None
    def rhs_net(rhs):
        if lvars_in(rhs) & taint: return True
        for rc in calls_in(rhs):
            nm=cname(rc)
            if nm in net_out and "ret" in net_out[nm]: return True
        return False
    for _ in range(12):
        ch=False
        for e in c.call:
            outs=net_out.get(cname(e))
            if not outs: continue
            args=list(e.a) if e.a is not None else []
            for chan in outs:
                if isinstance(chan,int) and chan<len(args):
                    t=write_base(args[chan])
                    if t is not None and t not in taint: taint.add(t); ch=True
        for lhs,rhs in c.asg:
            if lhs.op==Hx.cot_var and rhs_net(rhs) and lhs.v.idx not in taint:
                taint.add(lhs.v.idx); ch=True
        for e in c.call:
            nm=cname(e)
            if nm in COPY:
                di,si=COPY[nm]; args=list(e.a) if e.a is not None else []
                st=lvars_in(args[si]) if si<len(args) else set()
                if (st & taint) and di<len(args):
                    b=write_base(args[di])
                    if b is not None and b not in taint: taint.add(b); ch=True
        if not ch: break
    return c, taint, rhs_net
def out_channels(cf, net_out):
    c,taint,rhs_net=analyze_fn(cf,net_out); am=argmap(cf); chans=set()
    for r in c.ret:
        if lvars_in(r)&taint: chans.add("ret")
    for i,pos in am.items():
        if i in taint: chans.add(pos)
    for lhs,rhs in c.asg:
        if lhs.op!=Hx.cot_var and rhs_net(rhs):
            b=write_base(lhs)
            if b in am: chans.add(am[b])
    for e in c.call:
        ce=callee_ea(e)
        if ce is None: continue
        nm=norm(ce)
        if nm in COPY:
            di,si=COPY[nm]; args=list(e.a) if e.a is not None else []
            st=lvars_in(args[si]) if si<len(args) else set()
            if (st & taint) and di<len(args):
                b=write_base(args[di])
                if b in am: chans.add(am[b])
    return chans
def has_field_write(cf, net_out, target_elem):
    c,taint,rhs_net=analyze_fn(cf,net_out)
    for lhs,rhs in c.asg:
        el,b=field_elem(lhs)
        if el==target_elem and rhs_net(rhs): return True
    for e in c.call:
        ce=callee_ea(e)
        if ce is None: continue
        nm=norm(ce)
        if nm in COPY:
            di,si=COPY[nm]; args=list(e.a) if e.a is not None else []
            st=lvars_in(args[si]) if si<len(args) else set()
            if not (st&taint) or di>=len(args): continue
            d=args[di]
            if d.op==Hx.cot_add and d.y.op==Hx.cot_num and d.y.numval()//4==target_elem: return True
            if d.op==Hx.cot_ref and d.x.op==Hx.cot_idx and d.x.y.op==Hx.cot_num and d.x.y.numval()==target_elem: return True
    return False
PROTOS={"recv":"int recv(int, void *, int, int);",
        "recvfrom":"int recvfrom(int, void *, int, int, void *, void *);",
        "recvmsg":"int recvmsg(int, void *, int);",
        "read":"int read(int, void *, int);","readv":"int readv(int, void *, int);",
        "SSL_read":"int SSL_read(void *, void *, int);",
        "memcpy":"void *memcpy(void *, void *, int);","memmove":"void *memmove(void *, void *, int);",
        "strcpy":"char *strcpy(char *, char *);","strncpy":"char *strncpy(char *, char *, int);",
        "strlcpy":"int strlcpy(char *, char *, int);","strcat":"char *strcat(char *, char *);",
        "strncat":"char *strncat(char *, char *, int);","bcopy":"void bcopy(void *, void *, int);",
        "snprintf":"int snprintf(char *, int, char *);","sprintf":"int sprintf(char *, char *);"}
def main():
    ida_auto.auto_wait(); Hx.init_hexrays_plugin()
    outpath=idc.ARGV[1]; target_elem=int(idc.ARGV[2])
    for nm,decl in PROTOS.items():        # populate ctree args for library calls
        ea=idc.get_name_ea_simple(nm)
        if ea!=idc.BADADDR: idc.SetType(ea, decl)
    net_out={k:{v} for k,v in RECV_OUT.items()}
    funcs=list(idautils.Functions())
    for _ in range(8):
        changed=False
        for fea in funcs:
            cf=deco(fea)
            if not cf: continue
            ch=out_channels(cf,net_out)
            key=norm(fea)
            if ch and not ch.issubset(net_out.get(key,set())):
                net_out[key]=net_out.get(key,set())|ch; changed=True
        if not changed: break
    writers=[]
    for fea in funcs:
        cf=deco(fea)
        if not cf: continue
        if has_field_write(cf,net_out,target_elem): writers.append(norm(fea))
    wrappers={k:sorted(str(x) for x in v) for k,v in net_out.items() if k not in RECV_OUT}
    out={"target_elem":target_elem,"num_net_out":len(net_out),
         "sample_wrappers":dict(list(wrappers.items())[:40]),"confirmed_writers":writers}
    json.dump(out,open(outpath,"w"),indent=2,ensure_ascii=False)
    ida_pro.qexit(0)
main()
