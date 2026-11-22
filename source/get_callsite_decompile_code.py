# get call site code
import os
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
import ida_ida
import ida_funcs
import ida_typeinf
import ida_hexrays
import ida_nalt

def is_got_segment(address):
    for seg in idautils.Segments():
        # if segment_.perm & idaapi.SEGPERM_READ and not segment_.perm & idaapi.SEGPERM_WRITE:
        if idc.get_segm_name(seg) == ".got":
            if idc.get_segm_start(seg) <= address <= idc.get_segm_end(seg):
                return True
    return False

def is_address_in_symbol_table(address):
    struct_id = ida_nalt.get_strid(address)
    struct_name = ida_typeinf.get_tid_name(struct_id)
    # if struct_name == "Elf32_Sym"
    # print(f"struct name {struct_name} {hex(address)}")
    if struct_name and "Sym" in struct_name:
        return True
    
    return False

def get_function_from_name(function_name):
    # get function object
    func_addr = idc.get_name_ea_simple(function_name)
    if func_addr == idc.BADADDR:
        print(f"Function name {function_name} not found")
        return None
    # get the function object
    func = idaapi.get_func(func_addr)
    return func

def mips_get_strings_func_from_addiu(insn):
    #  addiu   $a0, (aForm2ipqostcde - 0x480000) addiu   $a1, (sub_46E230 - 0x470000)
    str_parameter = ""
    func_parameter = ""
    op3 = idc.print_operand(insn.ea, 2)
    op3_v = idc.get_operand_value(insn.ea, 2)
    op2 = idc.print_operand(insn.ea, 1)
    op2_v = idc.get_operand_value(insn.ea, 1)
    possible_string, possible_value = op3, op3_v
    if not op3.strip():
        possible_string, possible_value = op2, op2_v
    print(f"op2 {op2} value {hex(op2_v)} op3 is{op3}is{op3_v}")
    # print(f"possible  {possible_string} {hex(possible_value)}")
    if possible_string.startswith("(") and "-" in possible_string:
        #  addiu   $a0, (aForm2ipqostcde - 0x480000)  # "form2IPQoSTcDel"   addiu   $a1, (sub_46E230 - 0x470000)
        base_addr = possible_string.strip("()").split("-")[1].strip()
        if "0x" in base_addr or "0X" in base_addr:
            base_addr = int(base_addr,16)
            aim_addr = base_addr + possible_value
            print(f"aim addr {hex(aim_addr)}")
            if len(hex(aim_addr)) > 18:
                aim_addr = int("0x"+hex(aim_addr)[-16:],16)
            print(f"aim addr {hex(aim_addr)}")
            # string
            if idc.get_strlit_contents(aim_addr, -1, idaapi.STRTYPE_C):
                str = idc.get_strlit_contents(aim_addr, -1, idaapi.STRTYPE_C)
                str = str.decode('utf-8', errors='ignore')
                str_parameter = str
                # print(f"can found sring {str}")
            # function
            if idaapi.get_func(aim_addr):
                func_parameter = idaapi.get_func(aim_addr)
                str_parameter = ""
                
    return str_parameter, func_parameter

def find_callsite_decompiled_code(function_name,caller_func_ea):
    # get callsite
    func = get_func(caller_func_ea)
    if not func:
        print(f"Invalid funciton address at {hex(func.start_ea)}") 
        return set()
    func_decompile = ida_hexrays.decompile(func.start_ea)
    if func_decompile is None:
        print(f"Failed to decompile function at {hex(func.start_ea)}")
        return set()
    # pseudocode = func_decompile.get_pseudocode()
    param_line = set()
    for line in str(func_decompile).split("\n"):
        if f"{function_name}(" in line or f"{function_name} (" in line:
            # print(f"inline {line}")
            param_line.add(line.strip())
    return param_line

def check_call_site(func_ea, function_name):
    # get cross reference
    caller_function = set()
    xrefs = list(XrefsTo(func_ea))

    newxrefs = []
    for xref in xrefs:
        if is_address_in_symbol_table(xref.frm):
            pass
        elif is_got_segment(xref.frm):
            pass
        else:
            newxrefs.append(xref)
    for xref in newxrefs:
        from_ea = xref.frm
        insn = idautils.DecodeInstruction(from_ea)
        # print(f"typppppppp {xref.type} {hex(from_ea)}")
        if (xref.type >= 16 and xref.type <= 21):
            disasm = idc.GetDisasm(from_ea)
            # print(f"disasm {disasm} {hex(from_ea)}")
            if 'BL' in disasm or "BLX" in disasm or "B" in disasm:
                # ARM get caller
                caller_func = idaapi.get_func(from_ea)
                if caller_func:
                    caller_function.add(caller_func.start_ea)
            elif 'jal' in disasm or "jalr" in disasm or "bal" in disasm or "j" in disasm:
                # MIPS get caller
                caller_func = idaapi.get_func(from_ea)
                if caller_func:
                    caller_function.add(caller_func.start_ea)
                
        elif xref.type == 1 and insn:
            disasm = idc.GetDisasm(from_ea)
            if "addiu" in disasm:
                # MIPS caller 
                # xref.type  == 1
                _str, _func = mips_get_strings_func_from_addiu(insn)
                if _func:
                    if idaapi.get_func_name(_func.start_ea) == function_name:
                        print(f"xref code in {hex(from_ea)} {idaapi.get_func_name(_func.start_ea)}")
                        caller_func = idaapi.get_func(from_ea)
                        if caller_func:
                            caller_function.add(caller_func.start_ea)
            elif "la" in disasm or "li" in disasm or "LDR" in disasm:
                # MIPS la      $v0, igdSetDefaultConnectionService
                # ARM LDR             R3, =sub_ECB8
                # LDR             R3, =(fromSysStatusHandle_ptr - 0xFF3B8)
                # LDR             R3, [R4,R3] ; fromSysStatusHandle
                src_value = idc.get_operand_value(insn.ea, 1)
                nest_value = idaapi.get_dword(src_value)
                # print(f"src value {hex(src_value)}")
                src_operand = idc.print_operand(insn.ea, 1)
                if "LDR" in disasm and "[" in src_operand and "," in src_operand:
                    _temps = []
                    _temps.append(src_operand.strip("[]").split(",")[0].strip())
                    _temps.append(src_operand.strip("[]").split(",")[1].strip())
                    prev_ea = idc.prev_head(insn.ea)
                   
                    if prev_ea == idc.BADADDR:
                        continue
                    prev_insn = idautils.DecodeInstruction(prev_ea)
                    prev_disasm = idc.GetDisasm(prev_ea)
                    if "LDR" in prev_disasm:
                        prev_op1 = idc.print_operand(prev_insn.ea, 1)
                        prev_op0 = idc.print_operand(prev_insn.ea, 0)
                        prev_value1 = idc.get_operand_value(prev_insn.ea, 1)
                        if prev_op0 in _temps:
                            if "=" in prev_op1 and "-" in prev_op1 and "(" in prev_op1:
                                base_addr = prev_op1.strip("()").split("-")[1].strip()
                    
                                nest_addr = idaapi.get_dword(prev_value1)
                                src_value = nest_addr+int(base_addr,16) 
                                if len(hex(src_value)) > 10:
                                    src_value = int(hex(src_value)[-8:],16)
                                if is_got_segment(src_value):
                                    src_value = idaapi.get_dword(src_value)
                                print(f"LDRTLDR {hex(src_value)}  {nest_addr}")
                if idaapi.get_func(src_value) or idaapi.get_func(nest_value):
                # if func:
                    caller_func = idaapi.get_func(from_ea)
                    if caller_func:
                        caller_function.add(caller_func.start_ea)
    return caller_function 
   
def find_function_parent(function_name):
    # get parent function
    func = get_function_from_name(function_name)
    final_result = []
    if not func:
        print(f"We could not find funtion {function_name}")
        return

    # first layer caller subAAA->getsvar,get sub_AAA
    caller = check_call_site(func.start_ea, function_name)
    for caller_funcea in caller:
        
        called_code = find_callsite_decompiled_code(function_name, caller_funcea)
        print(f"processing {idaapi.get_func_name(caller_funcea)} {called_code}")
        print(len(called_code))
        final_result.append(called_code)
        # break
    # find most call
    # for i in final_result:
    #     print(i)
    #     print(f"{len(i)} ")
        
    print(final_result)
    largest_set = max(final_result, key=lambda s: len(s))
    return largest_set

def main():
    ida_auto.auto_wait()
    funcname = idc.ARGV[1]
    output_path = idc.ARGV[2]
    # funcname = "NK_query_entry_get"
    # output_path = "output.json"
    res = find_function_parent(funcname)
    final_result = {funcname:list(res)}
    # final_result = {funcname: res}
    with open(output_path, "w") as f:
        json.dump(final_result, f, indent=4, ensure_ascii=False)
    # Exit IDA Pro
    ida_pro.qexit(0)

if __name__ == "__main__":
    main()