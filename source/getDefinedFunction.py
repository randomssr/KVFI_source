# ida python count custom functions
import sys
import json
import ida_bytes
import ida_ua
import idautils
from idautils import *
import idaapi
from idaapi import *
import idc
from idc import *
import ida_auto
import ida_pro

def is_extern_segment(address):
    for seg in idautils.Segments():
        # if segment_.perm & idaapi.SEGPERM_READ and not segment_.perm & idaapi.SEGPERM_WRITE:
        if idc.get_segm_name(seg) == "extern" or idc.get_segm_name(seg) == ".extern":
            if idc.get_segm_start(seg) <= address <= idc.get_segm_end(seg):
                return True
    return False

def is_mips_stub_segment(address):
    for seg in idautils.Segments():
        # if segment_.perm & idaapi.SEGPERM_READ and not segment_.perm & idaapi.SEGPERM_WRITE:
        if idc.get_segm_name(seg) == ".MIPS.stubs":
            if idc.get_segm_start(seg) <= address <= idc.get_segm_end(seg):
                return True
    return False

def define_missing_functions():
    # iterate segments
    num_segments = idaapi.get_segm_qty()
    for i in range(num_segments):
        seg = idaapi.getnseg(i)
        if seg:
            seg_name = idaapi.get_segm_name(seg)
            seg_start = seg.start_ea
            seg_end = seg.end_ea
            seg_type = idaapi.get_segm_class(seg)
            # only process .text
            if seg_name== ".text" or seg_type == "CODE":
                print(f"Processing segment: {seg_name} ({hex(seg_start)} - {hex(seg_end)})")
                addr = seg_start
                while addr < seg_end:
                    # check whether the addr is in code and is a function
                    if idc.is_code(ida_bytes.get_full_flags(addr)):
                        # if the addr is not recovered as a function, create it
                        if not idc.get_func_name(addr):
                            print(f"Creating function at: {hex(addr)}")
                            idc.create_insn(addr)        # note as code
                            ida_funcs.add_func(addr)    # create function
                    addr = idc.next_head(addr)  
            
    ida_auto.auto_wait()

def main():
    ida_auto.auto_wait()
    output_path = idc.ARGV[1]
    # output_path = "output.json"
    funcs = set()
    funclibs = set()
    functhunks = set()
    define_missing_functions()
    for func_ea in Functions():
        funcname = idc.get_func_name(func_ea)
        flags = idc.get_func_attr(func_ea, FUNCATTR_FLAGS)
        if flags & FUNC_LIB or flags & FUNC_THUNK:
            continue
        # if flags & FUNC_LIB:
        #     funclibs.add(funcname)
        # elif flags & FUNC_THUNK:
        #     functhunks.add(funcname)
        
        if is_extern_segment(func_ea) or is_mips_stub_segment(func_ea):
            continue 
        funcs.add(funcname)
    # print(len(funcs))
    outs = {}
    outs["funcnum"] = len(funcs)
    outs["funcnames"] = list(funcs)
    # print(outs)
    with open(output_path, "w") as f:
        json.dump(outs, f)
    print(f"lib {funclibs}")
    print(f"func thunks {functhunks}")  
    # Exit IDA Pro
    idc.save_database(idc.get_idb_path())
    ida_pro.qexit(0)
    

if __name__ == "__main__":
    main()