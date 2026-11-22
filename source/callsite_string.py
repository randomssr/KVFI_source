# analyze each call site, and perform coarse-grained screening
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

Add_offset = {}
Thunk_map = {}
import_funcs = []

def is_rodata_segment(address):
    for seg in idautils.Segments():
        # if segment_.perm & idaapi.SEGPERM_READ and not segment_.perm & idaapi.SEGPERM_WRITE:
        if idc.get_segm_name(seg) == ".rodata":
            if idc.get_segm_start(seg) <= address <= idc.get_segm_end(seg):
                return True
    return False

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

def is_bss_segment(address):
    for seg in idautils.Segments():
        # if segment_.perm & idaapi.SEGPERM_READ and not segment_.perm & idaapi.SEGPERM_WRITE:
        if idc.get_segm_name(seg) == ".bss":
            if idc.get_segm_start(seg) <= address <= idc.get_segm_end(seg):
                return True
    return False

def is_got_segment(address):
    for seg in idautils.Segments():
        # if segment_.perm & idaapi.SEGPERM_READ and not segment_.perm & idaapi.SEGPERM_WRITE:
        if idc.get_segm_name(seg) == ".got":
            if idc.get_segm_start(seg) <= address <= idc.get_segm_end(seg):
                return True
    return False

def is_text_segment(address):
    for seg in idautils.Segments():
        if idc.get_segm_name(seg) == ".text":
            if idc.get_segm_start(seg) <= address <= idc.get_segm_end(seg):
                return True
    return False

def is_data_segment(address):
    for seg in idautils.Segments():
        if idc.get_segm_name(seg) == ".data":
            # print(f" addressb {address} start {idc.get_segm_start(seg)}")
            if idc.get_segm_start(seg) <= address <= idc.get_segm_end(seg):
                return True
    return False

def is_code_segment(address):
    num_segments = idaapi.get_segm_qty()
    for i in range(num_segments):
        seg = idaapi.getnseg(i)
        if seg:
            seg_name = idaapi.get_segm_name(seg)
            seg_start = seg.start_ea
            seg_end = seg.end_ea
            seg_type = idaapi.get_segm_class(seg)
        # .text segment
            if seg_name== ".text" or seg_type == "CODE":
               if address >= seg_start and address <= seg_end:
                    return True
    return False
                

def get_prev_insns(ea, count = 10):
    # get the previous count instructions starting from ea(ea included)
    insns = []
    insns.append(idautils.DecodeInstruction(ea))
    for i in range(count):
        prev_ea = idc.prev_head(ea)
        if prev_ea == idc.BADADDR:
            break
        insn = idautils.DecodeInstruction(prev_ea)
        if insn:
            insns.append(insn)
            ea = prev_ea
        else:
            break
    return insns

def is_function_wrapper(func_ea):
    """
    check whether the function is a simple jump function
    """
    # THUNK
    flags = idc.get_func_attr(func_ea, FUNCATTR_FLAGS)
    if flags & FUNC_THUNK:
        return True
    func = get_func(func_ea)
    if not func:
        print(f"Invalid funciton address at {hex(func.start_ea)}") 
        return False
    func_decompile = decompile(func.start_ea)
    if func_decompile is None:
        print(f"Failed to decompile function at {hex(func.start_ea)}")
        return 0
    pseudocode = func_decompile.get_pseudocode()
    if pseudocode.size() <= 4:
        return True
    
    return False

def arm_resolve_operand(operand, insn, _byteod):
    # resolve operand to get string 
    operand = operand.strip()
    # print(f"we are resolving {operand}")
    if operand.startswith("#"):
        # immidiate #0
        return None
    elif operand.startswith("="):
        # =aIpv6InterfaceI
        addr = idc.get_operand_value(insn.ea,1)
        # print(f"testing addr {hex(addr)}")
        # check whether it is string
        if not is_rodata_segment(addr):
            # pointer_address = idaapi.get_dword(addr)
            pointer_address = int.from_bytes(idaapi.get_bytes(addr, 4), byteorder=_byteod)
            # print(f"pointer addrss {hex(pointer_address)}")
        else:
            pointer_address = addr
        if "-" in operand:
            gotbaseaddr = int(operand.strip("()").split("-")[1].strip(),16)
            dst_add = pointer_address+gotbaseaddr
            if len(hex(dst_add)) > 10:
                pointer_address = int(hex(dst_add)[-8:], 16)
            else:
                pointer_address = dst_add
            
        # print(f"addr {hex(addr)} address {hex(pointer_address)}")
        # if is_rodata_segment(pointer_address):
        if idc.get_strlit_contents(pointer_address, -1, idaapi.STRTYPE_C):
            string = idc.get_strlit_contents(pointer_address, -1, idaapi.STRTYPE_C)
            if string:
                # print("value is string ",string.decode('utf-8', errors='ignore'))
                return string.decode('utf-8', errors='ignore')
    elif operand.startswith("pc"):
        # ldr r0, [pc, #offset]
        # print(f"pc insn is {idc.GetDisasm(insn.ea)}")
        insn_ea = idc.prev_head(insn.ea)
        insn = idautils.DecodeInstruction(insn_ea)
        if insn:
            if len(insn.Operands) > 1:
                offset = insn.Operands[1].value
                addr = insn.ea + 8 + offset  # ARM PC=current ins+8
                if idaapi.is_strlit(idc.get_full_flags(addr)):
                    string = idc.get_strlit_contents(addr, -1, idaapi.STRTYPE_C)
                    if string:
                        return string.decode('utf-8', errors='ignore')
    else:
        # read string
        addr = idc.get_operand_value(insn.ea,1)
        if not is_rodata_segment(addr):
            # pointer_address = idaapi.get_dword(addr)
            pointer_address = int.from_bytes(idaapi.get_bytes(addr, 4), byteorder=_byteod)
        else:
            pointer_address = addr
        # print(f"addr {hex(addr)} address {hex(pointer_address)}")
        if is_rodata_segment(pointer_address):
            string = idc.get_strlit_contents(pointer_address, -1, idaapi.STRTYPE_C)
            if string:
                return string.decode('utf-8', errors='ignore')
    return None


def mips_get_strings_func_from_addiu(insn):
    # analyze addiu addiu   $a0, (aForm2ipqostcde - 0x480000) addiu   $a1, (sub_46E230 - 0x470000)
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
    aim_addr = -1
    # print(f"possible  {possible_string} {hex(possible_value)}")
    if possible_string.startswith("(") and "-" in possible_string:
        # addiu   $a0, (aForm2ipqostcde - 0x480000)  # "form2IPQoSTcDel"   addiu   $a1, (sub_46E230 - 0x470000)
        # addiu   $a0, aLanMac     # "lan_mac"
        base_addr = possible_string.strip("()").split("-")[1].strip()
        if "0x" in base_addr or "0X" in base_addr:
            base_addr = int(base_addr,16)
            aim_addr = base_addr + possible_value
            print(f"aim addr {hex(aim_addr)}")
            if len(hex(aim_addr)) > 18:
                aim_addr = int("0x"+hex(aim_addr)[-16:],16)
    elif "0x" not in possible_string:
        aim_addr = possible_value
    if aim_addr != -1:
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


def mips_get_strings(insn, index):
    operand = idc.get_operand_value(insn.ea, index)
    op_src = idc.print_operand(insn.ea, index)
    _str = ""
    # print(f"checking {hex(insn.ea)}")
    if "addiu" in insn.get_canon_mnem():
        _str, _func = mips_get_strings_func_from_addiu(insn)
    else:
        if idaapi.get_func(operand):
            return ""
        mnem = insn.get_canon_mnem()
        if mnem in ("lw", "lwl", "lwr", "lwu", "ld"):
            # INDIRECT string arg: `lw $aN, off_X` loads the WORD at off_X into the register,
            # and that word is a POINTER to the string (double indirection; common in PIC MIPS
            # via .got / pointer tables, e.g. websGetVar($req,"topicurl") -> lw $a1, off_X #
            # "topicurl"). Reading a string DIRECTLY at off_X is wrong (it returns the pointer
            # bytes as garbage like 'p'); the register value is the pointer, so dereference the
            # word and read the string there. Note: idc.__EA64__ is True for 32-bit MIPS loaded
            # as a 64-bit IDB, so we can't trust it for pointer size — try 4-byte then 8-byte and
            # accept the first that lands on a valid C string.
            if ida_bytes.is_mapped(operand):
                for readfn in (idc.get_wide_dword, idc.get_qword):
                    ptr = readfn(operand)
                    if ida_bytes.is_mapped(ptr) and not idaapi.get_func(ptr):
                        s2 = idc.get_strlit_contents(ptr, -1, idaapi.STRTYPE_C)
                        if s2:
                            _str = s2.decode('utf-8', errors='ignore')
                            break
        else:
            # li / lui / la: the register gets the string ADDRESS directly.
            s = idc.get_strlit_contents(operand, -1, idaapi.STRTYPE_C)
            if s:
                _str = s.decode('utf-8', errors='ignore')
    # print(f"insn {hex(insn.ea)} str {_str} {hex(operand)} {op_src}")       
    return _str.strip()

def mips64_analyze_register_stack_parameters(from_ea, func_ea,block_startea):
    # a0-a7 + stack
    params = {}
    insns = list(get_prev_insns(from_ea, count=30))

    # print(f"insns first is  {hex(insns[0].ea)} func {hex(func_ea)}")
    # mips delete calling ins
    del insns[1]
    str_parameters = set()
    src_set = set()
    dst_set = set()
    for insn in insns:
        if insn.ea < func_ea:
            break
        if insn.ea in block_startea:
            break
        if insns.index(insn) != len(insns) -1:
            next_insn = insns[insns.index(insn) + 1]
            next_mnem = next_insn.get_canon_mnem()
            if next_mnem in ["jal", "jalr", "bal"]:
                break
        mnem = insn.get_canon_mnem()
        op1 = idc.print_operand(insn.ea, 0)
        op2 = idc.print_operand(insn.ea, 1)
        if "$gp" in op1:
            break 
        # print(f"mnem {mnem} {hex(insn.ea)}")
        if mnem in ["move", "mov", "movn"]:
            # move    $s3, $a2
            if op1 in src_set:
                src_set.discard(op1)
                src_set.add(op2)
            elif op1 in dst_set:
                break
            else:
                dst_set.add(op1)
                src_set.add(op2)
        elif mnem in ["lb", "lbu", "lh", "lhu", "ll", "lw", "lwl", "lwr", "lwu", "li", "lui", "ld", "la", "dla", "dli"]:
            # in ["lw", "li", "lui",  "la"]  
            # print(f"srcsrc1111 {hex(src_value)}")
            # ld      $a0, (ap_global_ctx - 0x1200DD2B0)($v0)
            # ld      $a0, 0xC8+var_30($sp)
            if "add"+op1 in src_set:
                print(f"ffffffffff src {src_set} {mnem}")
                src_set.discard(op1)
                continue
            if op1 in src_set:
                src_set.discard(op1)
                if "($sp" not in op2:
                    # li      $a0, aMethodlistidVo
                    src_value = idc.get_operand_value(insn.ea, 1)
                    src_set.add((insn, 1))
            elif op1 in dst_set:
                break
            else:
                dst_set.add(op1)
                if "($sp" not in op2:
                    # li      $a0, aMethodlistidVo
                    src_value = idc.get_operand_value(insn.ea, 1)
                    print(f"srcsrc {hex(src_value)}")
                    src_set.add((insn, 1))
        
        elif mnem.startswith("add") or mnem.startswith("sub") or mnem.startswith("dadd") or mnem.startswith("dsub") or mnem.startswith("mul") or mnem.startswith("div"):
            op3 = idc.print_operand(insn.ea, 2)
            # print(f" mmm {mnem}is{op3}at")
            # daddiu  $a1, (aSslModule_0 - 0x1200B0000)  # "ssl_module"
            if op3:
                # addiu   $s4, $sp, 0x24+var_C
                if op1 in src_set:
                    src_set.discard(op1)
                    src_set.add(op2)
                    if op3.startswith("(") and "-" in op3 and "add" in mnem:
                        # addiu   $a0, (aForm2ipqostcde - 0x480000)  # "form2IPQoSTcDel"   addiu   $a1, (sub_46E230 - 0x470000)
                        src_set.add((insn, 2))
                        src_set.discard(op2)
                        src_set.add("add"+op2)
                elif op1 in dst_set:
                    break
                else:
                    dst_set.add(op1)
                    src_set.add(op2)
                    if op3.startswith("(") and "-" in op3 and "add" in  mnem:
                        print(f"aaaaaffff {op3}")
                        src_set.discard(op2)
                        src_set.add("add"+op2)
                        #  addiu   $a0, (aForm2ipqostcde - 0x480000)  # "form2IPQoSTcDel"   addiu   $a1, (sub_46E230 - 0x470000)
                        src_set.add((insn, 2))
            else:
                # addiu   $sp, 0x40  addu    $v1, $v0 
                # addiu   $a0, aLanMac     # "lan_mac"
                if op1 in src_set:
                    if (op2.startswith("(") and "-" in op2 and "add" in mnem) or "0x" not in op2:
                        #    addiu   $a2, (aUrnSchemasUpnp_0 - 0x430000)
                        src_set.add((insn, 1))
                        src_set.discard(op1)
                        src_set.add("add"+op1)
                    else:
                        src_set.add(op2)
                elif op1 in dst_set:
                    break
                else:
                    dst_set.add(op1)
                    src_set.add(op1)
                    if (op2.startswith("(") and "-" in op2 and "add" in mnem) or "0x" not in op2:
                        #   addiu   $a2, (aUrnSchemasUpnp_0 - 0x430000)
                        src_set.add((insn, 1))
                        src_set.discard(op1)
                        src_set.add("add"+op1)
                    else:
                        src_set.add(op2)
        elif mnem in ["ssb", "sc", "sh", "sw", "swl", "swr", "sd"]:
            # store  sd $s3, 0xC8+var_s18($sp)
            if op2.startswith("0x") and op2.endswith("($sp)"):
                src_set.add(op1)
                
        elif mnem in ["j"]:
            break
        if insn.ea in block_startea:
            break
    print(f"src set {src_set} dst set {dst_set}")
    return src_set

def mips_analyze_function_calls_with_strings(func_ea, callsite_ea,block_startea):
    # mips 32 a0-a3 stack 64 a0-a7 stack
    final_string_set = set()
    source_set = mips64_analyze_register_stack_parameters(callsite_ea, func_ea,block_startea)
    for src in source_set:
        if isinstance(src, tuple):
            # (insn, index(from 0))
            _str = mips_get_strings(src[0], src[1])
            if _str:
                final_string_set.add(_str)
    # print(f"final string set {final_string_set}")
    if final_string_set:
        return (1, final_string_set)
    return (0,{})

def arm32_analyze_reg_stack_parameters(callsite_ea, func_ea, block_startea):
    src_set = set()
    dst_set = set()
    lh_dict = {}
    insns = get_prev_insns(callsite_ea, count=20)
    
    for insn in insns:
        if insn.ea < func_ea:
            break
        
        op1 = idc.print_operand(insn.ea, 0)
        op2 = idc.print_operand(insn.ea, 1)
        mnem = insn.get_canon_mnem()
        if mnem in ["push", "PUSH"]:
            #  PUSH {R6}
            if op1.startswith("{"):
                regs = op1.strip("{}").split(",")
                for reg in regs:
                    reg = reg.strip()
                    src_set.add(reg)
            else:
                src_set.add(op1)

        elif mnem.startswith("STR"):
            #  STR R6, [SP,#0x20F8+var_20F4]
            if "SP" in op2 and "[" in op2:
                src_set.add(op1)
                   
        elif mnem.startswith("stm") or mnem.startswith("STM"):
            # stmdb stmia stmib stmda stmfa stmea stmfd stmed  stmdb sp!,{r0-r12,lr}
            if "sp" in op1.lower():
                regs = op2.strip("{}").split(",")
                for reg in regs:
                    reg = reg.strip()
                    src_set.add(reg)
        
       
        elif mnem.startswith("MOV"):
            # MOVW            R2, #:lower16:aAdmin ; "admin"
            # MOVT            R2, #:upper16:aAdmin ; "admin"
            op2_value = idc.get_operand_value(insn.ea, 1)
            # print(f"nnnnnnnn {mnem} {hex(insn.ea)} {op2} {hex(idc.get_operand_value(insn.ea, 1))}")
            if "#:lower16" in op2:
                temp_op1 = "l"+op1
                if "h"+op1 not in lh_dict:
                    lh_dict[temp_op1] = hex(op2_value)[2:]
                else:
                    destvalue = int(lh_dict["h"+op1]+hex(op2_value)[2:],16)
                    src_set.add(("mov",destvalue))
                    dst_set.add(op1)
                    lh_dict.pop("h"+op1)
                    print(f"mov get {hex(destvalue)}")
            elif "#:upper16" in op2:
                temp_op1 = "h"+op1
                if "l"+op1 not in lh_dict:
                    lh_dict[temp_op1] = hex(op2_value)[2:]
                else:
                    destvalue = int(hex(op2_value)[2:]+lh_dict["l"+op1],16)
                    src_set.add(("mov",destvalue))
                    dst_set.add(op1)
                    lh_dict.pop("l"+op1)
                    print(f"mov get {hex(destvalue)}")
            else:       
                # MOV             R0, #aReadfromclient_0 MOV R0 #0xAAAAAA
                if op1 in src_set:
                    src_set.discard(op1)
                    src_set.add(op2)
                    if "#" in op2:
                        src_set.add(("mov", idc.get_operand_value(insn.ea, 1)))
                elif op1 in dst_set:
                    break
                else:
                    dst_set.add(op1)
                    src_set.add(op2)
                    if "#" in op2:
                        src_set.add(("mov", idc.get_operand_value(insn.ea, 1)))
            # print(f"lh_dict {lh_dict}")  
        elif mnem in ["ADD", "add", "SUB", "sub"]:
            op3 = idc.print_operand(insn.ea, 2)
            if op1 in src_set:
                src_set.discard(op1)
                src_set.add(op2)
                if not op3.startswith("#"):
                    src_set.add(op3)
            elif op1 in dst_set:
                break
            else:
                dst_set.add(op1)
                src_set.add(op2)
                if not op3.startswith("#"):
                    src_set.add(op3)
                    
        elif mnem in ["LDR", "ldr"]:
            if op1 in src_set:
                src_set.discard(op1)
                if "[" and "]" in op2:
                    # [R11,$var_40] 
                    pass
                elif "=(" in op2:
                    # =(aChangeTheMaskC - 0xFE3B8) 
                    src_value = idc.get_operand_value(insn.ea, 1)
                    src_set.add((insn,op2))
                elif "=" in op2:
                    # LDR             R1, =0x1307E
                    src_set.add((insn,op2))
            elif op1 in dst_set:
                break
            else:
                dst_set.add(op1)
                if "[" and "]" in op2:
                    # [R11,$var_40] 
                    pass
                elif "=(" in op2:
                    # =(aChangeTheMaskC - 0xFE3B8) 
                    src_value = idc.get_operand_value(insn.ea, 1)
                    src_set.add((insn,op2))
                elif "=" in op2:
                    # LDR             R1, =0x1307E
                    src_set.add((insn,op2))
                    
        elif mnem in ["bl", "BL"]:
            break 
        if insn.ea in block_startea:
            break
        
    return src_set

def arm64_analyze_reg_stack_parameters(callsite_ea, func_ea, block_startea):
    # analyze the arguments at call sites
    src_set = set()
    dst_set = set()
    lh_dict = {}
    adrp_dict = {}
    insns = get_prev_insns(callsite_ea, count=20)
    
    for insn in insns:
        if insn.ea < func_ea:
            break
        op1 = idc.print_operand(insn.ea, 0)
        op2 = idc.print_operand(insn.ea, 1)
        mnem = insn.get_canon_mnem()
        if mnem in ["push", "PUSH"]:
            #  PUSH {R6}
            if op1.startswith("{"):
                regs = op1.strip("{}").split(",")
                for reg in regs:
                    reg = reg.strip()
                    src_set.add(reg)
            else:
                src_set.add(op1)

        elif mnem.startswith("STR"):
            #  STR R6, [SP,#0x20F8+var_20F4]
            if "SP" in op2 and "[" in op2:
                src_set.add(op1)
        
        elif mnem in ["STP"]:
            # STP             X23, X24, [SP,#0x13580+var_13550] 
            op3 = idc.print_operand(insn.ea, 2)
            if "SP" in op3 and "[" in op3:
                src_set.add(op1)
                src_set.add(op2)
                           
        elif mnem.startswith("stm") or mnem.startswith("STM"):
            # stmdb stmia stmib stmda stmfa stmea stmfd stmed  stmdb sp!,{r0-r12,lr}
            if "sp" in op1.lower():
                regs = op2.strip("{}").split(",")
                for reg in regs:
                    reg = reg.strip()
                    src_set.add(reg)
        
        elif mnem.startswith("MOV"):
            # MOVW            R2, #:lower16:aAdmin ; "admin"
            # MOVT            R2, #:upper16:aAdmin ; "admin"
            op2_value = idc.get_operand_value(insn.ea, 1)
            # print(f"nnnnnnnn {mnem} {hex(insn.ea)} {op2} {hex(idc.get_operand_value(insn.ea, 1))}")
            if "#:lower16" in op2:
                temp_op1 = "l"+op1
                if "h"+op1 not in lh_dict:
                    lh_dict[temp_op1] = hex(op2_value)[2:]
                else:
                    destvalue = int(lh_dict["h"+op1]+hex(op2_value)[2:],16)
                    src_set.add(("mov",destvalue))
                    dst_set.add(op1)
                    lh_dict.pop("h"+op1)
                    print(f"mov get {hex(destvalue)}")
            elif "#:upper16" in op2:
                temp_op1 = "h"+op1
                if "l"+op1 not in lh_dict:
                    lh_dict[temp_op1] = hex(op2_value)[2:]
                else:
                    destvalue = int(hex(op2_value)[2:]+lh_dict["l"+op1],16)
                    src_set.add(("mov",destvalue))
                    dst_set.add(op1)
                    lh_dict.pop("l"+op1)
                    print(f"mov get {hex(destvalue)}")
            else:       
                # MOV             R0, #aReadfromclient_0 MOV R0 #0xAAAAAA
                if op1 in src_set:
                    src_set.discard(op1)
                    src_set.add(op2)
                    if "#" in op2:
                        src_set.add(("mov", idc.get_operand_value(insn.ea, 1)))
                elif op1 in dst_set:
                    break
                else:
                    dst_set.add(op1)
                    src_set.add(op2)
                    if "#" in op2:
                        src_set.add(("mov", idc.get_operand_value(insn.ea, 1)))
            # print(f"lh_dict {lh_dict}")  
        
        elif mnem in ["ADD", "add", "SUB", "sub"]:
            # ADD             X0, X0, #aPoeScheduleCgi@PAGEOFF
            op3 = idc.print_operand(insn.ea, 2)
            if op1 in src_set:
                src_set.discard(op1)
                src_set.add(op2)
                if not op3.startswith("#"):
                    src_set.add(op3)
                else:
                    if mnem in ["SUB", "sub"]:
                        continue
                    # adrp_dict[op2] = hex(idc.get_operand_value(insn.ea, 2))[2:]
                    
                    if op1 not in adrp_dict and "@PAGE" in op3:
                        # ADD X1, X1, #aSSDPortListIsE@PAGEOFF
                        adrp_dict[op2] = {}
                        adrp_dict[op2]["name"] = op3.split("@")[0]
                        adrp_dict[op2]["value"] = idc.get_operand_value(insn.ea, 2)
                    elif op1 not in adrp_dict and "@PAGE" not in op3:
                        # first ADD X2, X2, #0x120 then ADD X2, X23, #qword_427220@PAGEOFF
                        adrp_dict[op2] = {}
                        adrp_dict[op2]["name"] = ""
                        adrp_dict[op2]["value"] = idc.get_operand_value(insn.ea, 2)
                    elif op1 in adrp_dict:
                        if op2 != op1:
                            adrp_dict[op2] = {}
                        # print(f"ssssss {hex(insn.ea)} {op1} {adrp_dict[op1]}")
                        adrp_dict[op2]["value"] = adrp_dict[op1]["value"] + idc.get_operand_value(insn.ea, 2)
                        if adrp_dict[op1]["name"]:
                            adrp_dict[op2]["name"] = adrp_dict[op1]["name"]
                        else:
                            adrp_dict[op2]["name"] = op3.split("@")[0]
                        if op2 != op1:
                            adrp_dict.pop(op1)
                    print(f"add # ea  {hex(insn.ea)} {hex(idc.get_operand_value(insn.ea, 2))} {adrp_dict}")
                    # src_set.add(("mov",idc.get_operand_value(insn.ea, 2)))
            elif op1 in dst_set:
                break
            else:
                dst_set.add(op1)
                src_set.add(op2)
                if not op3.startswith("#"):
                    src_set.add(op3)
                else:
                    if mnem in ["SUB", "sub"]:
                        continue
                    # src_set.add(("mov",idc.get_operand_value(insn.ea, 2)))
                    # adrp_dict[op2] = hex(idc.get_operand_value(insn.ea, 2))[2:]
                    if op1 not in adrp_dict and "@PAGE" in op3:
                        # ADD X1, X1, #aSSDPortListIsE@PAGEOFF
                        adrp_dict[op2] = {}
                        adrp_dict[op2]["name"] = op3.split("@")[0]
                        adrp_dict[op2]["value"] = idc.get_operand_value(insn.ea, 2)
                    elif op1 not in adrp_dict and "@PAGE" not in op3:
                        # first ADD X2, X2, #0x120 then ADD X2, X23, #qword_427220@PAGEOFF
                        adrp_dict[op2] = {}
                        adrp_dict[op2]["name"] = ""
                        adrp_dict[op2]["value"] = idc.get_operand_value(insn.ea, 2)
                    # elif op1 in adrp_dict:
                    #     adrp_dict[op2] = {} 
                    #     adrp_dict[op2]["value"] = adrp_dict[op1]["value"] + idc.get_operand_value(insn.ea, 2)
                    #     adrp_dict[op2]["name"] = adrp_dict[op1]["name"]
                    #     adrp_dict.pop(op1)
                    print(f"add # ea {hex(insn.ea)} {hex(idc.get_operand_value(insn.ea, 2))} {adrp_dict}")
        
        elif mnem in ["ADRP"]:
            # print(f"adrp soffs {hex(insn.ea)} {hex(idc.get_operand_value(insn.ea, 1))}")
            # ADRP used with ADD or LDR
            # ADRP X1, #off_438FF0@PAGE  LDR X1, [X1,#off_438FF0@PAGEOFF]
            # ADRP X0, #aPoeScheduleCgi@PAGE ADD  X0, X0, #aPoeScheduleCgi@PAGEOFF
            print(f"adrp {hex(insn.ea)} {op1} {adrp_dict}")
            Add_offset[op2.split("@")[0]] = idc.get_operand_value(insn.ea, 1)
            if op1 in adrp_dict:
                dest_addr = idc.get_operand_value(insn.ea, 1) + adrp_dict[op1]["value"]
                src_set.add(("mov",dest_addr))
                print(f"calculte into  {hex(insn.ea)} {hex(dest_addr)}")
                adrp_dict.pop(op1)
                src_set.discard(op1)

        elif mnem in ["ADRL"]:
            # ADRL            X21, aSwPoeSchedule
            if op1 in src_set:
                src_set.discard(op1)
                src_set.add(op2)
                # print(f"adrl insn {hex(insn.ea)} {hex(idc.get_operand_value(insn.ea, 1))}")
                src_set.add(("mov", idc.get_operand_value(insn.ea, 1)))
            elif op1 in dst_set:
                break
            else:
                dst_set.add(op1)
                src_set.add(op2)
                # print(f"adrl insn {hex(insn.ea)} {hex(idc.get_operand_value(insn.ea, 1))}")
                src_set.add(("mov", idc.get_operand_value(insn.ea, 1)))
                
        elif mnem in ["LDR", "ldr"]:
            if op1 in src_set:
                src_set.discard(op1)
                if "[" and "]" in op2:
                    # [R11,$var_40] 
                    # LDR             X1, [X1,#off_438FF0@PAGEOFF]
                    if "#" in op2 and "@PAGE" in op2:
                        _op = op2.strip("[]").split(",")[0]
                        src_set.add(_op)
                        # adrp_dict[_op] = hex(idc.get_operand_value(insn.ea, 1))[2:]
                        adrp_dict[_op] = {"name": op2.strip("[]").split(",")[1].split("@")[0], "value": idc.get_operand_value(insn.ea, 1)}
                        print(f"ldr insn {hex(insn.ea)} operand {hex(idc.get_operand_value(insn.ea, 1))} {adrp_dict}")
                    
                elif "=(" in op2:
                    # =(aChangeTheMaskC - 0xFE3B8) 
                    src_value = idc.get_operand_value(insn.ea, 1)
                    src_set.add((insn,op2))
                elif "=" in op2:
                    # LDR             R1, =0x1307E
                    src_set.add((insn,op2))
            elif op1 in dst_set:
                break
            else:
                dst_set.add(op1)
                if "[" and "]" in op2:
                    # [R11,$var_40] 
                    # LDR             X1, [X1,#off_438FF0@PAGEOFF]
                    if "#" in op2 and "@PAGE" in op2:
                        _op = op2.strip("[]").split(",")[0]
                        src_set.add(_op)
                        # adrp_dict[_op] = hex(idc.get_operand_value(insn.ea, 1))[2:]
                        adrp_dict[_op] = {"name": op2.strip("[]").split(",")[1].split("@")[0], "value": idc.get_operand_value(insn.ea, 1)}
                        print(f"ldr insn {hex(insn.ea)} operand {hex(idc.get_operand_value(insn.ea, 1))} {adrp_dict}")
                elif "=(" in op2:
                    # =(aChangeTheMaskC - 0xFE3B8) 
                    src_value = idc.get_operand_value(insn.ea, 1)
                    src_set.add((insn,op2))
                elif "=" in op2:
                    # LDR             R1, =0x1307E
                    src_set.add((insn,op2))
        
        elif mnem in ["LDP"]:
            # LDP             X27, X28, [SP,#0x13580+var_13530] 
            if op1 in src_set:
                src_set.discard(op1)
            elif op1 in dst_set:
                break
            else:
                dst_set.add(op1)
            if op2 in src_set:
                src_set.discard(op2)
            elif op2 in dst_set:
                break
            else:
                dst_set.add(op2)
                   
        elif mnem in ["bl", "BL"]:
            break 
        for op in adrp_dict:
            if adrp_dict[op]["name"] in Add_offset:
                name = adrp_dict[op]["name"]
                dest_addr = Add_offset[name] + adrp_dict[op]["value"]
                src_set.add(("mov", dest_addr))
                d1 = adrp_dict[op]["value"]
                d2 = Add_offset[name]
                print(f"through global add {name} {hex(d2)} {hex(d1)} {hex(dest_addr)}")
        if insn.ea in block_startea:
            break
    return src_set



def arm_analyze_function_calls_with_strings(func_ea, callsite_ea, _byteod, is32, block_startea):
    # arm 32 r0-r3 stack arm 64 X0-X7 stack
    if is32:
        src_values = arm32_analyze_reg_stack_parameters(callsite_ea, func_ea, block_startea)
    else:
        src_values = arm64_analyze_reg_stack_parameters(callsite_ea, func_ea, block_startea)
    collect_strings = set()
    if src_values:
        
        for value in src_values:
            # print(f"register params are {value} {type(value)}")
            if isinstance(value,tuple):
                # print(f"tuple {value}")
                if value[0] == "mov":
                    # print(f"moxing addr {hex(value[1])}")
                    if idc.get_strlit_contents(value[1], -1, idaapi.STRTYPE_C):
                        _str = idc.get_strlit_contents(value[1], -1, idaapi.STRTYPE_C).decode('utf-8', errors='ignore')
                        collect_strings.add(_str)
                else:
                    _str = arm_resolve_operand(value[1],value[0], _byteod)
                    if _str and isinstance(_str,str):
                        # print(f"reg reg string {_str}")
                        collect_strings.add(_str)
    if collect_strings:
        print(f" call at {hex(callsite_ea)} collect strings {collect_strings}")
        return (1,collect_strings)
    return (0,collect_strings)


def arm_analyze_call_site(func_addr, resultjson, _byteod, is32):
    # Get the function object
    func = idaapi.get_func(func_addr)
    if not func:
        print(f"Failed to get function at address {hex(func_addr)}.")
        return
    call_function_name = idc.get_func_name(func_addr)
    # if call_function_name != "j_get_cgi":
    #     return
    Add_offset = {}
    index = 0
    instructions = list(idautils.FuncItems(func.start_ea))
    hascall = 0
    called_set = set()
    block_startea = set()
    global import_funcs
    for block in idaapi.FlowChart(func):
        # print(f"block {hex(block.start_ea)}")
        block_startea.add(block.start_ea)
    # whether it is a wrapper of library function
    isextern = 0
    # Iterate through instructions in the function
    for addr in instructions:
        insn = idautils.DecodeInstruction(addr)
        # print(f"insn current {hex(insn.ea)}")
        if addr > func.end_ea:
            break
        called_func_name = ""
        # Check if the instruction is a call (ARM uses 'BL' and 'BLX' for calls)
        if insn.get_canon_mnem() in ['BL', 'BLX', 'B']:
            called_func_addr = idc.get_operand_value(addr, 0)
            called_func_name = idc.get_func_name(called_func_addr)
            print(f"find call {hex(addr)} {called_func_name}")
        elif insn.get_canon_mnem() in ["LDR"]:
            # THUNK
            # j_get_cgi
            # ADR     R12, 0x122B88
            # ADD     R12, R12, #0x69000
            # LDR     PC, [R12,#(get_cgi_ptr - 0x18BB88)]! ; get_cgi
            # op1 [R4,#-4]
            op0 = idc.print_operand(addr, 0)
            op1 = idc.print_operand(addr, 1)
            op1_value = idc.get_operand_value(addr,1)
            if op0 == "PC" and "#" in op1 and "-" in op1 and " " in op1:
                # print(f"op1 {op1}")
                # LDR             PC, [R12,#(NCONF_get_string_ptr - 0xA37EC)]! ; __imp_NCONF_get_string
                base_addr = op1.split("-")[1].split(")")[0].strip()
                base_addr = int(base_addr, 16)
                called_addr = base_addr + op1_value
                if is_got_segment(called_addr):
                    called_addr = idaapi.get_dword(called_addr)
                    if idaapi.get_func(called_addr):
                        called_func_addr = called_addr
                        called_func_name = idc.get_func_name(called_func_addr)
                # print(f"base {hex(base_addr)} {hex(op1_value)}")
        if called_func_name and called_func_name != call_function_name:
            hascall = 1
            called_set.add(called_func_name)
            
            if is_function_wrapper(func_addr) and (called_func_name.startswith("__imp_") or called_func_name in import_funcs):
                isextern = 1
            elif is_function_wrapper(func_addr) :
                Thunk_map[called_func_name] = call_function_name
                # print(f"mpmpmpmp {call_function_name} {called_func_name}")
            # print(f"find callname {called_func_name}")
            hasstring, _str_set = arm_analyze_function_calls_with_strings(func_addr, instructions[index-1], _byteod, is32, block_startea)
            if hasstring:
                # print(f"{hex(addr)} has string parameter")
                if called_func_name not in resultjson:
                    resultjson[called_func_name] = {}
                    resultjson[called_func_name]["count"] = 0
                    resultjson[called_func_name]["parameters"] = set()
                
                resultjson[called_func_name]["count"] += 1
                if _str_set:
                    resultjson[called_func_name]["parameters"] |= _str_set
        index += 1
    # print(f"callset {called_set}")
    return called_set, isextern
            
            
def mips_analyze_call_site(func_addr, resultjson):
    # MIPS 
    # Get the function object
    # print(f"processing {hex(func_addr)}")
    global import_funcs
    isextern = 0
    func = idaapi.get_func(func_addr)
    if not func:
        print(f"Failed to get function at address {hex(func_addr)}.")
        return
    funcname = idc.get_func_name(func_addr)
    # if idc.get_func_name(func_addr) != "":
    #     return
    # Iterate through instructions in the function
    instructions = list(idautils.FuncItems(func.start_ea))
    hascall = 0
    block_startea = set()
    for block in idaapi.FlowChart(func):
        # print(f"block {hex(block.start_ea)}")
        block_startea.add(block.start_ea)
    called_set = set()
    for index in range(len(instructions)):
        addr = instructions[index]
        
        insn = idautils.DecodeInstruction(addr)
        if addr > func.end_ea:
            break
        called_func_addr = 0
 
        # Check if the instruction is a call 
        if insn.get_canon_mnem() in ['jal','bal']:
            # jal func   
            
            called_func_addr = idc.get_operand_value(addr, 0)
            print(f"11111found function call {hex(insn.ea)} {hex(called_func_addr)}")
        elif insn.get_canon_mnem() in ["jalr", "jr"]:
            # jalr $t1
            if insn.get_canon_mnem() == "jalr":
                operand = idc.print_operand(insn.ea,1)
            else:
                operand = idc.print_operand(insn.ea, 0)
            if operand.startswith('$'):
                reg = operand[1:]
                for _j in range(index+1, 0, -1):
                    if _j == index or _j == len(instructions):
                        continue
                    # print(f"sss {_j} {index} {len(instructions)}")
                    _insn = idautils.DecodeInstruction(instructions[_j])
                    if idc.print_insn_mnem(_insn.ea) in ["move"]:
                        if idc.print_operand(_insn.ea, 0) == operand:
                            operand = idc.print_operand(_insn.ea, 1)
                    if idc.print_insn_mnem(_insn.ea) in  ['la', 'lw', "dla"]:
                        # 'la' 
                        load_addr = idc.print_operand(_insn.ea, 0)
                        # print(f"loadddd {load_addr} {operand}")
                        if load_addr == operand:
                            _func_addr = idc.get_operand_value(_insn.ea,1)
                            # print(f"insn {hex(_insn.ea)} {hex(_func_addr)}")
                            if idaapi.get_func(_func_addr):
                                # print(f"found function calll {hex(_insn.ea)} {hex(_func_addr)}")
                                called_func_addr = _func_addr  
                                break
                    elif idc.print_insn_mnem(_insn.ea) in ["addiu", "daddiu"]:
                        # addiu   $t9, (sub_45A954 - 0x460000)
                        load_addr = idc.print_operand(_insn.ea, 0)
                        if load_addr == operand:
                            _str, _func = mips_get_strings_func_from_addiu(_insn)
                            if _func:
                                called_func_addr = _func.start_ea
                                # print(f"found function calll {hex(_insn.ea)} {hex(called_func_addr)}")
                                # print(f"addiu found function {hex(insn.ea)}")
                                break
                        
        
        if called_func_addr != 0:
            hascall = 1
            # mips delay slot
            next_addr = instructions[index+1]
            called_func_name = idc.get_func_name(called_func_addr)
            
            called_set.add(called_func_name)
            if is_function_wrapper(func_addr) and (called_func_name.startswith("__imp_") or called_func_name in import_funcs):
                isextern = 1
            elif is_function_wrapper(func_addr) and (not called_func_name.startswith("__imp_")):
                Thunk_map[called_func_name] = funcname
                print(f"mpmpmpmp {funcname} {called_func_name}")
            # if called_func_name != "httpRpmConfAdd":
                # print(f"calling {called_func_name} {hex(called_func_addr)} at {hex(addr)} {hex(next_addr)} {hex(func_addr)}") 
                # continue
            print(f"calling {called_func_name} {hex(called_func_addr)} at {hex(addr)} {hex(next_addr)} {hex(func_addr)}") 
            # analyze arguments
            hasstring, _str_set = mips_analyze_function_calls_with_strings(func_addr, next_addr,block_startea)
            if hasstring:
                print(f"{hex(addr)} has string parameter")
                if called_func_name not in resultjson:
                    resultjson[called_func_name] = {}
                    resultjson[called_func_name]["count"] = 0
                    resultjson[called_func_name]["parameters"] = set()
                
                resultjson[called_func_name]["count"] += 1
                resultjson[called_func_name]["parameters"] |= _str_set
    if is_function_wrapper(func_addr) and len(called_set) == 0:
        # calling function using addiu
        # cJSON_GetObjectItem:                     # CODE XREF: sub_41D5A0+BC↑p
        # LOAD:00483450                                          # sub_41D5A0+D0↑p ...
        # LOAD:00483450                 lui     $t7, 0x49  # 'I'
        # LOAD:00483454                 lw      $t9, off_493F40
        # LOAD:00483458                 jr      $t9
        # LOAD:0048345C                 addiu   $t8, $t7, (off_493F40 - 0x490000)
        # off_493F40:     .word __imp_cJSON_GetObjectItem
        for index in range(len(instructions)):
            addr = instructions[index]
            
            insn = idautils.DecodeInstruction(addr)
            if addr > func.end_ea:
                break
            if insn.get_canon_mnem() in ["addiu"]:
                op3_addr = idc.get_operand_value(insn.ea,2)
                op3_name = idc.print_operand(insn.ea,2)
                if "(" in op3_name and ")" in op3_name and " - " in op3_name:
                    op3_addr = int(op3_name.strip("()").split("-")[1].strip(),16) + op3_addr
                    if len(hex(op3_addr)) > 18:
                        op3_addr = int(hex(op3_addr)[-16:],16)
                print(f"op3_addr", hex(op3_addr))
                if "__imp_" in idc.print_operand(op3_addr,0) or idc.print_operand(op3_addr,0) in import_funcs:
                    isextern = 1
                
    return called_set, isextern   
            
def arm_global_use_in_function(func_addr, _byteod):
    func = idaapi.get_func(func_addr)
    if not func:
        print(f"Failed to get function at address {hex(func_addr)}.")
        return
    instructions = list(idautils.FuncItems(func.start_ea))
    has_global_value = 0
    # Iterate through instructions in the function
    for addr in instructions:
        insn = idautils.DecodeInstruction(addr)
        mnem = insn.get_canon_mnem()
        op1 = idc.print_operand(insn.ea, 1)
        op1_value = idc.get_operand_value(insn.ea, 1)
        op2 = idc.print_operand(insn.ea, 2)
        op2_value = idc.get_operand_value(insn.ea, 2)
        
        if "GLOBAL_OFFSET_TABLE" in op1 or "GLOBAL_OFFSET_TABLE" in op2:
            continue
        if mnem in ["LDR"]:
            print(f"op1 value {op1} {hex(op1_value)}")
            if is_code_segment(op1_value):
                print(f"op1 value {op1} {hex(op1_value)}")
                if "=(" in op1 and "-" in op1:
                    
                    base_addr = op1.strip("()").split("-")[1].strip()
                    data = idaapi.get_bytes(op1_value, 4)
                    if data:
                        value = int.from_bytes(data, byteorder=_byteod)
                        dst_value = value+int(base_addr,16)
                        print(f"ldr {mnem} {hex(insn.ea)} {op1} {hex(op1_value)} {hex(dst_value)}")
                        if is_got_segment(dst_value):
                            # got_value = idaapi.get_dword(dst_value)
                            got_value = int.from_bytes(idaapi.get_bytes(dst_value, 4), byteorder=_byteod)
                            
                            if got_value:
                                # got_value = int.from_bytes(got_data, byteorder=_byteod)
                                print(f"datttt {hex(got_value)}")
                                if is_bss_segment(got_value) or is_data_segment(got_value):
                                    # print(f"there is global value ")
                                    print(f" get value {hex(value)} {hex(dst_value)} {hex(got_value)}")
                                    has_global_value = 1
                                    break
                        elif is_bss_segment(dst_value) or is_data_segment(dst_value):
                            print(f" get value {hex(value)} {hex(dst_value)}")
                            has_global_value = 1
                            break
                else:
                    # off_1321C       DCD off_2C304
                    # data = idaapi.get_dword(op1_value)
                    data = int.from_bytes(idaapi.get_bytes(op1_value, 4), byteorder=_byteod)
                    if data:
                        print(f"ldr {mnem} {hex(insn.ea)} {op1} {hex(op1_value)} {hex(data)}")
                        if is_data_segment(data) or is_bss_segment(data):
                            has_global_value = 1
                            break
                    
            elif is_bss_segment(op1_value):
                has_global_value = 1
                break
        elif mnem in ["MOV"]:
            op1 = idc.print_operand(insn.ea, 1)
            op1_value = idc.get_operand_value(insn.ea, 1)
            if op1.startswith("#"):
                # MOV             R3, #dword_29F24
                if is_bss_segment(op1_value):
                    has_global_value = 1
                    break
    # if has_global_value:
    #     print(f"function has global")
    return has_global_value

def mips_global_use_in_function(func_addr):
    func = idaapi.get_func(func_addr)
    if not func:
        print(f"Failed to get function at address {hex(func_addr)}.")
        return
    instructions = list(idautils.FuncItems(func.start_ea))
    has_global_value = 0
    dst_addr = 0
    # Iterate through instructions in the function
    for addr in instructions:
        insn = idautils.DecodeInstruction(addr)
        mnem = insn.get_canon_mnem()
        op2 = idc.print_operand(insn.ea, 1)
        op2_value = idc.get_operand_value(insn.ea, 1)
        op3 = idc.print_operand(insn.ea, 2)
        op3_value = idc.get_operand_value(insn.ea, 2)
        if "GLOBAL_OFFSET_TABLE" in op2 or "GLOBAL_OFFSET_TABLE" in op3:
            continue
        if mnem in ["lw", "dlw"]:
            #  lw      $v0, dword_56A790
            dst_addr = op2_value
            if ")(" in op2 and "-" in op2:
                # lw (dword_56A6C4 - 0x570000)($s2)
                base_addr = op2.split(")(")[0].split("-")[1].strip()
                dst_addr = int(base_addr,16) + op2_value
                
        elif mnem in ["addiu", "daddiu"]:
            # addiu   $a0, $v0, (dword_56A790 - 0x570000)
            if op3:
                if "-" in op3 and "(" in op3:
                    base_addr = op3.strip("()").split("-")[1].strip()
                    dst_addr = op3_value + int(base_addr, 16)
                    # print(f"addiu {hex(op3_value)} {op3} {base_addr}")
                    
        elif mnem in ["li", "dli"]:
            # li      $a1, unk_55C518
            dst_addr = op2_value
        if len(hex(dst_addr)) > 18:
            dst_addr = int(hex(dst_addr)[-16:], 16)
        if is_bss_segment(dst_addr) or is_data_segment(dst_addr):
            has_global_value = 1
            print(f"{mnem} {hex(insn.ea)} {op2} {hex(op2_value)}")
            break
    print(f"hasssss {has_global_value}")      
    return has_global_value
              

def extract_type_and_name(param_str):
    cleaned = ''.join(c for c in param_str if c.isprintable()).strip()
    parts = cleaned.split()
    
    if len(parts) < 2:
        return (None, None)
    
    var_part = parts[-1]        #  '*'
    type_parts = parts[:-1]     # 
    
    stars = ''
    var_name = var_part
    while var_name.startswith('*'):
        stars += '*'
        var_name = var_name[1:]

    if stars:
        type_name = ' '.join(type_parts) + ' ' + stars
    else:
        type_name = ' '.join(type_parts)

    type_name = type_name.strip()
    return type_name, var_name

def analyze_function_parameter_types(func_ea):
    # find parameter count >=2
    func = get_func(func_ea)
    if not func:
        print(f"Invalid funciton address at {hex(func.start_ea)}") 
    # ida_auto.analyze_area(func.start_ea, func.end_ea)
    ida_auto.auto_mark_range(func.start_ea, func.end_ea, ida_auto.AU_CODE)  
    # ida_auto.auto_wait()  
    func_decompile = ida_hexrays.decompile(func.start_ea)
    # ida_auto.auto_wait()
    # print(f"Decompiled function: {func_decompile}")
    xref_list = ida_xref.get_first_cref_to(func_ea)
    if func_decompile is None:
        print(f"Failed to decompile function at {hex(func.start_ea)}")
        return 0
    ida_hexrays.mark_cfunc_dirty(func.start_ea)
    
    # get parameters
    # pseudocode 
    pseudocode = func_decompile.get_pseudocode()
    # print(str(pseudocode))
    param_line = ""
    for i in range(pseudocode.size()):
        line = pseudocode.at(i).line
        if "(" in line and ")" in line:
            param_line = line
            break
    if not param_line:
        print("No parameter line found.")
        return 0
    
    # parse parameters
    param_str = param_line.split("(")[1].split(")")[0].strip()
    if param_str == "":
        print("No parameters")
        return 0
    params = param_str.split(",")
    # print("Parameters:", params)
    paramlen = 0
    haschar = 0
    for param in params:
       (_type, _name) = extract_type_and_name(param)
    
       if _type is None:
           continue
       paramlen += 1
       if "char *" in _type or "char*" in _type:
           haschar = 1
    return paramlen
    # if paramlen >= 2 and haschar == 1:
    # if paramlen >= 2:
    #     return 1
    # return 0

def get_exported_functions():
    # get functions in export table
    exported_functions = []
    # Iterate through all exported entries
    # print(idautils.Entries())
    for i, entry in enumerate(idautils.Entries()):
        if len(entry) == 4:
            ordinal, ea, name, _ = entry
        elif len(entry) == 3:
            ordinal, ea, name = entry
        else:
            continue  # Skip entries that do not match expected formats
        func_name = idaapi.get_func_name(ea)
        if func_name:
            exported_functions.append(func_name)
        # print the name and address of each exported function
        # print(f"Exported Function {i}: {name} at address {hex(ea)}, ordinal {ordinal}")

    # print(exported_functions)
    return exported_functions

def list_imported_functions():
    # get functions in import table
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


def define_missing_functions():
    num_segments = idaapi.get_segm_qty()
    for i in range(num_segments):
        seg = idaapi.getnseg(i)
        if seg:
            seg_name = idaapi.get_segm_name(seg)
            seg_start = seg.start_ea
            seg_end = seg.end_ea
            seg_type = idaapi.get_segm_class(seg)
            # process text
            if seg_name== ".text" or seg_type == "CODE":
                print(f"Processing segment: {seg_name} ({hex(seg_start)} - {hex(seg_end)})")

                # iterate
                addr = seg_start
                while addr < seg_end:
                    # check addr
                    if idc.is_code(ida_bytes.get_full_flags(addr)):
                        # create function
                        if not idc.get_func_name(addr):
                            print(f"Creating function at: {hex(addr)}")
                            idc.create_insn(addr)        
                            ida_funcs.add_func(addr)    
                    addr = idc.next_head(addr)  
            
    ida_auto.auto_wait()

def main():
    ida_auto.auto_wait()
    output_path = idc.ARGV[1]
    # output_path = "aaa.json"
    callsite_resultjson = {}
    define_result = {}
    define_missing_functions()
    othersource = {}
    decompile_error = set()
    global import_funcs
    import_funcs = list_imported_functions()
    for func_ea in Functions():
        flags = idc.get_func_attr(func_ea, FUNCATTR_FLAGS)
        if flags & FUNC_LIB:
            continue
        funcname = idc.get_func_name(func_ea)   

        if is_extern_segment(func_ea) or is_mips_stub_segment(func_ea):
            continue 

        paramlen = analyze_function_parameter_types(func_ea)
        procname = ida_ida.inf_get_procname()
        
        is32 = 0
        if ida_ida.inf_is_32bit_exactly():
            is32 = 1
        if ida_ida.inf_is_be():
            byteorder = "big"
        else:
            byteorder = "little"
        # print(f"procname {procname} is32 {is32}")
        if procname in ["mips", "MIPS", "mipsl", "MIPSL", "mipsb", "MIPSB", "octeonb"]:
            # octeonb is mips64
            called_set, isextern = mips_analyze_call_site(func_ea, callsite_resultjson)
          
            if isextern == 0 and ((paramlen >= 2) or ((paramlen >= 1 or (funcname in callsite_resultjson and len(callsite_resultjson[funcname]["parameters"]) > 0)) and (mips_global_use_in_function(func_ea) or len(called_set)>0))):
                funcname = idc.get_func_name(func_ea)
                if funcname:
                    define_result[funcname] = paramlen
            
        elif procname in ["arm","ARM", "ARMB"]:
            called_set, isextern = arm_analyze_call_site(func_ea, callsite_resultjson, byteorder, is32)
            
            print(f"paramlen {paramlen} {isextern}")
            if isextern == 0 and  ((paramlen >= 2) or ((paramlen >= 1 or (funcname in callsite_resultjson and len(callsite_resultjson[funcname]["parameters"]) > 0)) and (arm_global_use_in_function(func_ea, byteorder) or len(called_set)>0))):
                funcname = idc.get_func_name(func_ea)
                if funcname:
                    define_result[funcname] = paramlen
        if paramlen == 0 and funcname in callsite_resultjson and len(callsite_resultjson[funcname]["parameters"]) > 0:
            decompile_error.add(funcname)
        for _tempname in called_set:
            if ("nvram" in _tempname.lower() or "env" in _tempname.lower()) and ("get" in _tempname.lower() or "set" in _tempname.lower()):
                othersource[funcname] = list(called_set)
                break
              
        # print(callsite_resultjson)
    for func in callsite_resultjson:
        callsite_resultjson[func]["parameters"] = list(callsite_resultjson[func]["parameters"])
    # save the result
    result = {}
    result["define_result"] = define_result
    result["callsite_result"] = callsite_resultjson
    result["exported_functions"] = get_exported_functions()
    result["import_functions"] = import_funcs
    # record the corrsponding relations of THUNK
    result["thunk_map"] = Thunk_map
    result["wrapped_source"] = othersource
    result["decompile_error"] = list(decompile_error)
    with open(output_path, "w") as f:
        json.dump(result, f, indent=4, ensure_ascii=False)
    # Exit IDA Pro
    idc.save_database(idc.get_idb_path())
    ida_pro.qexit(0)

if __name__ == "__main__":
    main()