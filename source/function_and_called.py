import idaapi
import idautils
import idc
import ida_auto
import ida_hexrays
import ida_ida
import ida_pro
import json
from idc import *
from idautils import *
from idaapi import *

Import_funcs = []

def is_text_segment(address):
    for seg in idautils.Segments():
        # if segment_.perm & idaapi.SEGPERM_READ and not segment_.perm & idaapi.SEGPERM_WRITE:
        if idc.get_segm_name(seg) == ".text":
            if idc.get_segm_start(seg) <= address <= idc.get_segm_end(seg):
                return True
    return False

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

def is_got_segment(address):
    for seg in idautils.Segments():
        # if segment_.perm & idaapi.SEGPERM_READ and not segment_.perm & idaapi.SEGPERM_WRITE:
        if idc.get_segm_name(seg) == ".got":
            if idc.get_segm_start(seg) <= address <= idc.get_segm_end(seg):
                return True
    return False

def mips_called_function(function_name):
    func_ea = idc.get_name_ea_simple(function_name)
    func_end = idaapi.get_func(func_ea).end_ea
    instructions = list(idautils.FuncItems(func_ea))
    need_disam = set()
   
    index = 0
    for insn_ea in instructions:
        index += 1
        # operand mnem
        insn = idautils.DecodeInstruction(insn_ea)
        mnem = insn.get_canon_mnem()
        # print(f"iterate {hex(insn_ea)} {mnem}0{idc.print_operand(insn.ea,0)}1{idc.print_operand(insn.ea,1)}")
        # call check
        # MIPS
        if mnem in ["jal", "jalr", "jr", "bal"]:
            if mnem in ["jalr"]:
                operand = idc.print_operand(insn.ea,1)
            elif mnem in ["jr"]:
                operand = idc.print_operand(insn.ea,0)
            elif mnem in ["jal", "bal"]:
                # bal     websError
                # jal     sub_41A1F0
                operand_value = idc.get_operand_value(insn.ea,0)
                if idaapi.get_func(operand_value):
                    need_disam.add(operand_value)
                    continue       
            print(f"mnemmmm {mnem} {operand}")
            if operand.startswith('$'):
            # analyze the source of reg
                reg = operand[1:]
                # print(f"refffff {reg}")
                print(f"jalr found at 0x{insn.ea:X}, with register operand: {reg}")
                # trace backward
                for _j in range(index-2,0,-1):
                    _insn = idautils.DecodeInstruction(instructions[_j])
                    if idc.print_insn_mnem(_insn.ea) in ["la", "lw", "dla"] :
                        # 'la' 
                        load_addr = idc.print_operand(_insn.ea, 0)
                        # print(f"loadddd {load_addr} {hex(_insn.ea)}")
                        if load_addr == operand:
                            # find target addr of la
                            target_addr_name = idc.print_operand(_insn.ea, 1)
                            target_addr = idc.get_operand_value(_insn.ea,1)
                            func1 = idaapi.get_func(target_addr)
                            if func1 and target_addr == func1.start_ea:
                                need_disam.add(func1.start_ea)
                                break
                    elif idc.print_insn_mnem(_insn.ea) in ["move"]:
                        if idc.print_operand(_insn.ea, 0) == operand:
                            operand = idc.print_operand(_insn.ea, 1)
                    elif idc.print_insn_mnem(_insn.ea) in ["addiu", "daddiu"]:
                        # addiu   $t9, (sub_45A954 - 0x460000)
                        load_addr = idc.print_operand(_insn.ea, 0)
                        if load_addr == operand:
                            _str, _func = mips_get_strings_func_from_addiu(_insn)
                            if _func:
                                called_func_addr = _func.start_ea
                                need_disam.add(called_func_addr)
                                # print(f"addiu found function {hex(insn.ea)}")
                                break
    res_disasm = []
    res_disasm.append(func_ea)
    res_disasm.extend(list(need_disam))
    print(" ".join(hex(i) for i in res_disasm))
    print(f"need dis {hex(next(iter(res_disasm)))}")
    return res_disasm    

def arm_called_function(function_name):
    func_ea = idc.get_name_ea_simple(function_name)
    instructions = list(idautils.FuncItems(func_ea))
    need_disam = set()
   
    index = 0
    for insn_ea in instructions:
        index += 1
        insn = idautils.DecodeInstruction(insn_ea)
        mnem = insn.get_canon_mnem()
        # call check
        # ARM
        # print(f"insn {hex(insn.ea)} {mnem}")
        if mnem in ["BL", "BLX", "B"]:
            target_addr_name = idc.print_operand(insn.ea, 0)
            target_addr = idc.get_operand_value(insn.ea, 0)
            # print("ffffff",target_addr_name,hex(target_addr))
            _func1 = idaapi.get_func(target_addr)
            if _func1 and target_addr == _func1.start_ea:
                need_disam.add(_func1.start_ea)
                print(f"  Found function call address: {target_addr_name} {hex(_func1.start_ea)}")
        elif mnem in ["LDR"]:
            # THUNK function
            # j_get_cgi
            # ADR     R12, 0x122B88
            # ADD     R12, R12, #0x69000
            # LDR     PC, [R12,#(get_cgi_ptr - 0x18BB88)]! ; get_cgi
            op0 = idc.print_operand(insn.ea, 0)
            op1 = idc.print_operand(insn.ea, 1)
            op1_value = idc.get_operand_value(insn.ea,1)
            if op0 == "PC" and "#" in op1 and "-" in op1:
                base_addr = op1.split("-")[1].split(")")[0].strip()
                base_addr = int(base_addr, 16)
                called_addr = base_addr + op1_value
                if is_got_segment(called_addr):
                    called_addr = idaapi.get_dword(called_addr)
                    if idaapi.get_func(called_addr):
                        # called_func_addr = called_addr
                        # called_func_name = idc.get_func_name(called_func_addr)
                        need_disam.add(called_addr)

    res_disasm = []
    res_disasm.append(func_ea)
    res_disasm.extend(list(need_disam))
    print(" ".join(hex(i) for i in res_disasm))
    return res_disasm    

def list_imported_functions():
    # get functions from import table
    import_functions = []
    nimps = idaapi.get_import_module_qty()
    
    for i in range(nimps):
        name = idaapi.get_import_module_name(i)
        if not name:
            continue
        def imp_cb(ea, name, ord):
            if not name:
                name = f"Ordinal_{ord}"
            import_functions.append(name)
            # print(f"  {name} at address {hex(ea)}")
            return True
        
        idaapi.enum_import_names(i, imp_cb)
    return import_functions


def get_disasm(need_asm, Import_funcs,arm):
    result = ""
    external_funcs = set()
    # process THUNK function
    if len(need_asm) == 2:
        # print(f"{hex(need_asm[0])} {hex(need_asm[1])}")
        func_ea = need_asm[0]
        func = idaapi.get_func(func_ea)
        flags = idc.get_func_attr(func_ea, FUNCATTR_FLAGS)
        if flags & FUNC_THUNK:
            cfunc = ida_hexrays.decompile(idaapi.get_func(need_asm[1]))
            callname = idaapi.get_func_name(func_ea)
            calledname = idaapi.get_func_name(need_asm[1])
            if cfunc:
                result = str(cfunc).replace(calledname, callname)
                return result, external_funcs
    extra_need_asm = set()
    for i in range(1, len(need_asm)):
          func_ea = need_asm[i]  
          print(f"ssssssss {hex(func_ea)}")
          func = idaapi.get_func(func_ea)
          flags = idc.get_func_attr(func_ea, FUNCATTR_FLAGS)    
          if flags & FUNC_THUNK:
                if arm == "mips":
                    _tempcalled = mips_called_function(idc.get_func_name(func_ea))
                    if(len(_tempcalled) > 1):
                        _called = _tempcalled[1]
                        extra_need_asm.add(_called)
                else:
                    _tempcalled = arm_called_function(idc.get_func_name(func_ea))
                    if(len(_tempcalled) > 1):
                        _called = _tempcalled[1]
                        extra_need_asm.add(_called)
    need_asm.extend(list(extra_need_asm))
    print(f"need_asm {need_asm}")
    for func_ea in need_asm:
        func = idaapi.get_func(func_ea)
        if not func:
            print(f"Failed to get function at address {hex(func_ea)}.")
            continue 
        if idaapi.get_func_name(func_ea) in Import_funcs:
            external_funcs.add(idaapi.get_func_name(func_ea))
            continue
        # ida_auto.auto_wait()
 
        cfunc = ida_hexrays.decompile(func)
        if cfunc:
            decompiled_code = str(cfunc) +"\n"
            if "__imp_" in decompiled_code:
                # print(f"jjjjj {decompiled_code}")
                for _f in Import_funcs:
                    funcname = idaapi.get_func_name(func_ea)
                    # if funcname in _f:
                    #     print(f"addddd {_f}")
                    if _f.split("@")[0] == funcname:
                        # hsearch_r@@GLIBC_2.4	
                        # print(f"add {_f}")
                        external_funcs.add(funcname)
                        break
            else:
                result = decompiled_code + result
    # print(result)
    return result, external_funcs
            
def main():
    ida_auto.auto_wait()
    function_name = idc.ARGV[1]
    output_path = idc.ARGV[2]
    Import_funcs = list_imported_functions()
    # print(Import_funcs)
    procname = ida_ida.inf_get_procname()
    is32 = 0
    if ida_ida.inf_is_32bit_exactly():
        is32 = 1
    print(f"procname {procname} is32 {is32}")
    func_ea = idc.get_name_ea_simple(function_name)
    flags = idc.get_func_attr(func_ea, FUNCATTR_FLAGS)
    arm = ""
    if procname in ["mips", "MIPS", "mipsl", "MIPSL", "mipsb", "MIPSB", "octeonb"]:
        need_asm = mips_called_function(function_name)
        arm = "mips"
        print(f"need asm {need_asm}")
        if flags & FUNC_THUNK and len(need_asm) > 1:
            called_ea = need_asm[1]
            called_name = idc.get_func_name(called_ea)
            need_asm = mips_called_function(called_name)
    elif procname in ["arm","ARM"]:
        arm = "arm"
        need_asm = arm_called_function(function_name)
        if flags & FUNC_THUNK and len(need_asm) > 1:
            called_ea = need_asm[1]
            called_name = idc.get_func_name(called_ea)
            need_asm = arm_called_function(called_name)

    dis_code, external_funcs = get_disasm(need_asm, Import_funcs, arm)
    if flags & FUNC_THUNK:
        dis_code = dis_code.replace(called_name, function_name)
    finalresult = {}
    finalresult["code"] = dis_code
    finalresult["external_funcs"] = list(external_funcs)
    with open(output_path, "w") as f:
        json.dump(finalresult, f, indent=4,ensure_ascii=False)
      # Exit IDA Pro
    ida_pro.qexit(0)

if __name__ == "__main__":
    main()