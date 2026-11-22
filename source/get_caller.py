# get grandparent function sub_AAA(sub_AAA->sub_BBB->funcname)
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
import ida_nalt
import ida_typeinf
import ida_ida
import ida_search
import copy
from callsite_string import mips_get_strings_func_from_addiu

Data_variable_addr_range = {}
Data_addr_list = []
Object_uri_dispatch_list = []


def is_got_segment(address):
    for seg in idautils.Segments():
        # if segment_.perm & idaapi.SEGPERM_READ and not segment_.perm & idaapi.SEGPERM_WRITE:
        if idc.get_segm_name(seg) == ".got":
            if idc.get_segm_start(seg) <= address <= idc.get_segm_end(seg):
                return True
    return False

def is_rodata_segment(address):
    for seg in idautils.Segments():
        # if segment_.perm & idaapi.SEGPERM_READ and not segment_.perm & idaapi.SEGPERM_WRITE:
        if idc.get_segm_name(seg) == ".rodata":
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
            # only text
            if seg_name== ".text" or seg_type == "CODE":
               if address >= seg_start and address <= seg_end:
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

def get_data_segment_boundary():
    # data boundary
    for seg in idautils.Segments():
        if idc.get_segm_name(seg) == ".data":
            return (idc.get_segm_start(seg), idc.get_segm_end(seg))
    return (None, None)

def get_function_from_name(function_name):
    # get function object by name
    func_addr = idc.get_name_ea_simple(function_name)
    if func_addr == idc.BADADDR:
        print(f"Function name {function_name} not found")
        return None
    # get the function object
    func = idaapi.get_func(func_addr)
    return func

def list_data_segment_variables(segment_name=".data"):
    # Get the start and end addresses of the segment by its name
    segment = idaapi.get_segm_by_name(segment_name)
    if not segment:
        print(f"Segment '{segment_name}' not found.")
        return

    start_ea = segment.start_ea
    end_ea = segment.end_ea

    # print(f"Listing variables in segment '{segment_name}':")
    name_list = []
    addr_list = []
    # Iterate through all addresses in the segment
    for ea in range(start_ea, end_ea):
        # Get the name of the variable at the address
        name = idc.get_name(ea)
        # Check if the address has a name (indicating a variable)
        if name:
            # Get the type of the variable
            var_type = idc.get_type(ea)
            if not var_type:
                var_type = "<unknown>"

            # Print the variable name, address, and type
            # print(f"Variable: {name}, Address: {hex(ea)}, Type: {var_type}")
            name_list.append(name)
            Data_addr_list.append(ea)
    Data_addr_list.append(end_ea)
    for i in range(len(name_list)):
        Data_variable_addr_range[name_list[i]] = (Data_addr_list[i],Data_addr_list[i+1])
    # print(" ".join(map(hex,Data_addr_list)))

def is_continious_pattern(arr):
    # continuous 1，-1 in data
    allowed_error = len(arr) / 10
    error_count = 0
    if not arr:
        return False
    if arr[0] not in [1, -1]:
        return False
    for i in range(1, len(arr)):
        if abs(arr[i] - arr[i-1])  != 2:
            error_count += 1
            if error_count > allowed_error:
                return False
    return True


def is_repeated_substring_with_tolerance(s):
    """
    repeated substring in s
    """
    # strip 0
    s = s.rstrip("0")
    n = len(s)

    # iterate
    str_list = []
    error_list = []
    for i in range(1, n // 2 + 1):
        # get substring
        substring = s[:i]
        substring1 = ""
        substring2 = ""
        # case handle
        if '0' in substring and len(substring) == substring.count('0'):
            continue
        # calculte error
        # error = sum(1 for a, b in zip(s, repeated) if a != b)
        repeated_count = n // i
        tolerance = n // i // 5
        # tolerance = n // 10
        # calculate strings not consistent with substring
        error_count = 0
        if substring.count('22') == 1 and substring.count('11') >= 1:
            # 2->0，22，02，20
            substring1 = substring.replace("22","20")
            substring2 = substring.replace("22","02")
        for j in range(repeated_count):
            if substring1 != "":
                if s[j * i:(j + 1) * i] != substring and s[j * i:(j + 1) * i] != substring1 and s[j * i:(j + 1) * i] != substring2:
                    if "220" in substring and ("222" in s[j * i:(j + 1) * i] or "202" in s[j * i:(j + 1) * i] or "022" in s[j * i:(j + 1) * i]):
                        continue
                    print(s[j * i:(j + 1) * i])
                    error_count += 1
            else:
                if s[j * i:(j + 1) * i] != substring:
                    error_count += 1
            if error_count > tolerance:
                break
        # print(f"sub {substring} repa {repeated} error {error_count} tole {tolerance}")
        # error is permited
        if error_count <= tolerance:
            return True, substring
        # str_list.append(substring)
        # error_list.append(error_count)

    return False, ""

def object_get_data_object(addr):
    # get data object containing addr
    for index in range(len(Data_addr_list)-1):
        if addr >= Data_addr_list[index] and addr < Data_addr_list[index+1]:
            return (Data_addr_list[index], Data_addr_list[index+1])
    return (-1, -1)

def is_function_wrapper(func_ea):
    """
    wrapper function checking
    :param func_ea: startea of functions
    :return: true if it is
    """
    # THUNK function
    flags = idc.get_func_attr(func_ea, FUNCATTR_FLAGS)
    if flags & FUNC_THUNK:
        return True
    else:
        return False

def get_content_from_struct(struct_id, current_addr):
    data_values = []
    object_content = []
    string_list = set() 
    for (offset, name, size) in idautils.StructMembers(struct_id):
        # print(f'Member {name} at offset {offset} of size {size}')
        # 
        value = idc.get_wide_dword(current_addr)
        # print(f"addr value {hex(current_addr)} {hex(value)}")
        func = idaapi.get_func(value)
        # if not value:
        #     break
        
        if func:
            data_values.append(1)
            object_content.append(idc.get_func_name(value))
        elif idc.get_strlit_contents(value):
            str = idc.get_strlit_contents(value).decode('utf-8', errors='ignore').strip()
            # print(f"find sttring {str}")
            if str:
                data_values.append(-1)
                string_list.add(str)
                string_offset = offset
                object_content.append(str)
            else:
                object_content.append(value)
        else:
            data_values.append(0)
            object_content.append(value)
        current_addr = current_addr + size
    return data_values, object_content, string_list

def search_immediate(num):
    # using api
    start_addr = ida_ida.inf_get_min_ea()
    addr, oeprand = ida_search.find_imm(start_addr, SEARCH_DOWN|SEARCH_NEXT,num)
    if addr != BADADDR:
        return addr
    return 0

def search_immediate_from_insn(num):
    # search immediate
    for seg in idautils.Segments():
        # iter
        for head in idautils.Heads(seg, idc.get_segm_end(seg)):
            # op_count = idc.GetOpCount(head)
            
            for i in range(idaapi.UA_MAXOP):
                # LDR             R10, =0x13F74
                # if head == 0xDEE4:
                # if head >= 0x13F74 and head <= 0x1401c:
                    # print(f"eeeeddddd {hex(head)} {idaapi.UA_MAXOP} {hex(idc.get_operand_value(head,i))}")
                # if idc.get_operand_type(head, i) == idc.o_imm and idc.get_operand_value(head, i) == num:
                if idc.get_operand_value(head, i) == num or hex(num)[2:] in idc.print_operand(head, i) or idaapi.get_dword(idc.get_operand_value(head, i)) == num : 
                    print(f"Found immediate value {num} at address {hex(head)}")
                    return head
    return 0

def convert_bytes_to_string(start_ea, end_ea):
    """
    convert bytes into string
    :param start_ea: start ea of bytes
    :param end_ea: end ea of bytes
    """
    current_ea = start_ea
    str = ""
    while current_ea < end_ea:
        # read byte
        byte_value = ida_bytes.get_byte(current_ea)
        # stop if 0
        if byte_value == 0:
            break
        # to char
        char = chr(byte_value)
        # print(f"Address: {hex(current_ea)}, Byte: {hex(byte_value)}, Char: {char}")
        str += char
        current_ea += 1
    return str

def get_value(value):
    func = idaapi.get_func(value)
    str = ""
    if func:
        data_str = "2"
        data_content = idc.get_func_name(value)
    
    elif idc.get_strlit_contents(value):
        str = idc.get_strlit_contents(value).decode('utf-8', errors='ignore')
        data_str = "1"
        data_content = idc.get_strlit_contents(value).decode('utf-8', errors='ignore')
    else:
        data_str = "0"
        data_content = value
    return data_content, data_str, str

def construct_xref_data_struct(func_ea, xref_ea):
    # func_ea target function
    # xref_ea if 0, need recovery
    
    # func_ea search immediate
    # print(f"xref in symbol table {hex(xref_ea)} {idc.print_operand(xref_ea, 0)}")
    if is_address_in_symbol_table(xref_ea):
        xref_ea = 0
    if xref_ea == 0:
        _addr = search_immediate(func_ea)
        print(f"search into f {hex(_addr)}")
        if not ida_bytes.is_code(_addr):
            xref_ea = _addr
    if xref_ea == 0 or is_address_in_symbol_table(xref_ea):
        return {}
    # if xref_ea != 0x92d54:
    #     return
    isuri = 0
    for obj in Object_uri_dispatch_list:
        if xref_ea >= obj[0] and xref_ea < obj[1]:
            print(f"already in the object {hex(obj[0])}")
            return {}
            
    object_start, object_end = object_get_data_object(xref_ea)
    print(f"xref {hex(func_ea)} to {hex(xref_ea)} find object at {hex(object_start)} is{idc.get_name(xref_ea)}")
    data_content = []
    data_str = ""
    string_set = set()
    if ida_ida.inf_is_32bit_exactly():
        is32 = 1
        step = 4
        getcontent = idaapi.get_dword
    else:
        is32 = 0
        step = 8
        getcontent = idaapi.get_qword
    start_xref_addr = 0
    if object_start == -1:
        # can not find object 
        # search boundary
        current_addr = xref_ea - step
        while current_addr:
            # forward
            _content, _data, _str = get_value(getcontent(current_addr))
            data_content.append(_content)
            data_str += _data
            string_set.add(_str)
            xrefs = list(XrefsTo(current_addr))
            if len(xrefs) > 0:
                object_start = current_addr
                start_xref_addr = xrefs[0].frm
                break
                # aMSetipinterfac DCB "<m:SetIPInterfaceInfoResponse xmlns:m=",0x22,"urn:NETGEAR-ROUTER"
                # LOAD:00094AD8                                         ; DATA XREF: sub_2D52C+200↑o
                # LOAD:00094AD8                                         ; sub_2D52C+210↑o ...
                # LOAD:00094B11                 DCB ":service:WANIPConnection:1",0x22,"></m:SetIPInterfaceInfoRespons"
                # LOAD:00094B4A                 DCB "e>",0xD,0xA
                # LOAD:00094B4E                 DCB "<ResponseCode>000</ResponseCode>",0xD,0xA,0
                # LOAD:00094B71                 ALIGN 4
                # LOAD:00094B74                 DCD 0x73C0C
                # delete such string content
            current_addr -= step
        # check '0'
        index = len(data_str) - 1
        havereduce = 0
        templen0 = 0
        while index >= 0 and data_str[index] == "0" :
            templen0 += 1
            index -= 1
        index = len(data_str) - 1
        if data_str.count("0"*templen0) == 1:
            while index >= 0 and data_str[index] == "0":
                # if data_content: 
                data_content.pop()
                object_start += step
                havereduce = 1
                index -= 1
            if havereduce:
                start_xref_addr = -1
            data_str = data_str[:index]
        print(f"delete {data_str} to {index}")
        # reverse
        data_content.reverse()
        str_list = list(data_str)
        str_list.reverse()
        data_str = "".join(str_list)
        
        current_addr = xref_ea
        while current_addr:
            # backward
            xrefs = list(XrefsTo(current_addr))
            if len(xrefs) > 0:
                object_end = current_addr
                break
            _content, _data, _str = get_value(getcontent(current_addr))
            data_content.append(_content)
            data_str += _data
            string_set.add(_str)
            current_addr += step
        
        # print(f"encounting start {hex(object_start)} end {hex(object_end)}")
    else:
        if object_start % 4 != 0:
            object_start -= object_start%4
        xrefs = list(XrefsTo(object_start))
        if len(xrefs) > 0:
            for x in xrefs:
                if is_address_in_symbol_table(x.frm):
                    continue
                elif is_code_segment(x.frm):
                    start_xref_addr = x.frm
                    break
            # start_xref_addr = xrefs[0].frm
            print(f"xref object {hex(start_xref_addr)} {hex(object_start)}")
        current_addr = object_start
        while current_addr < object_end:
            _content, _data, _str = get_value(getcontent(current_addr))
            # print(f"aaaaaaaaaa {hex(current_addr)} {hex(getcontent(current_addr))}")
            data_content.append(_content)
            data_str += _data
            string_set.add(_str)
            current_addr += step
        # print(f"find object start {hex(object_start)} end {hex(object_end)} string {data_str}")
        # aSEnvelopeXmlns DCB "<s:Envelope xmlns:s=",0x22,"http://schemas.xmlsoap.org/soap/enve"
        # LOAD:00013E2A                 DCB "lope/",0x22," s:encodingStyle=",0x22,"http://schemas.xmlsoap.org"
        # LOAD:00013E5C                 DCB "/soap/encoding/",0x22,"><s:Body><s:Fault><faultcode>s:Client</fa"
        # LOAD:00013E95                 DCB "ultcode><faultstring>UPnPError</faultstring><detail><UPnPError x"
        # LOAD:00013ED5                 DCB "mlns=",0x22,"urn:schemas-upnp-org:control-1-0",0x22,"><errorCode"
        # LOAD:00013F07                 DCB ">%d</errorCode><errorDescription>%s</errorDescription></UPnPErro"
        # LOAD:00013F47                 DCB "r></detail></s:Fault></s:Body></s:Envelope>",0
        # LOAD:00013F73                 DCB 0
        # LOAD:00013F74                 DCD 0x12F0F
        # LOAD:00013F78                 DCD sub_D7A4
        index = 0
        hasreduce = 0
        templen0 = 0
        while index < len(data_str) and data_str[index] == "0":
            templen0 += 1
            index += 1
        index = 0
        if data_str.count("0"*templen0) == 1:
            while index < len(data_str) and data_str[index] == "0":
                data_content = data_content[1:]
                object_start += step
                hasreduce = 1
                index += 1
        data_str = data_str[index:]
        if hasreduce:
            start_xref_addr = -1
            print(f"reducehave {index}")
        # print(f"22222find object start {hex(object_start)} end {hex(object_end)} string {data_str}")
    # print(f"whole string is {hex(object_start)} {data_str}")
    # print(f"data content {data_content}")
    print(f"crefcref {start_xref_addr} {hex(object_start)}")

    if start_xref_addr != -1:
        # off_517D90:     .word aForwardingAdd     # DATA XREF: cgi_setobject+218↑r
            # .data:00517D90                                          # cgi_setobject+228↑o
            # .data:00517D90                                          # "forwarding_add"
            # .data:00517D94                 .word 0x31
            # .data:00517D98                 .word sub_42882C
        if start_xref_addr == 0:
            # immediate search 
             _dest = search_immediate(object_start)
             if _dest:
                 start_xref_addr = _dest
             else:
                #  continue trace backward
                # ; int dword_13F74[]
                # LOAD:00013F74 dword_13F74     DCD 0x12F0F
                # LOAD:00013F78 off_13F78       DCD sub_D7A4
                current_addr = object_start - step
                while current_addr:
                    
                    _content, _data, _str = get_value(getcontent(current_addr))
                    data_content.insert(0, _content)
                    data_str = _data + data_str
                    string_set.add(_str)
                    hascur = 1
                    
                    print(f"added in{hex(current_addr)}")
                    _dest = search_immediate(current_addr)
                    if _dest:
                        object_start = current_addr
                        break
                    current_addr -= step
                    
        # print(f" sttttss {hex(start_xref_addr)} {hex(object_start)} {hex(object_end)} {data_str}")
        
           
    # if len(string_set) > 0 and "1" in data_str and "2" in data_str:
    if "2" in data_str:
        repeat, substring = is_repeated_substring_with_tolerance(data_str)
        print(f"whole string is {data_str}")
        print(f"substring is {substring}")
        print(f"data content {data_content[:100]}")
        # if repeat and "1" in substring and "2" in substring and substring.count("2") == 1:
        # if repeat and "1" in substring and "2" in substring:
        if repeat and "2" in substring:
            print(f"is repearted {hex(object_start)} end {hex(object_end)}")
            Object_uri_dispatch_list.append((object_start, object_end))
            isuri = 1
            # string == character array
            #  off_44D200:     .word sub_409D18         # DATA XREF: _ftext+178↑r
            # LOAD:0044D204 aGetsysstatuscf:.ascii "getSysStatusCfg
            if "1" not in substring and len(substring) > 3:
                # character array
                current_addr = object_start
                index = 0
                count = substring.count("0")
                new_data_content = []
                while current_addr < object_end and index < len(data_content) and index < len(data_str):
                    # print(f"data ", data_content[index], " data ", data_str[index])
                    if data_str[index] == "0":
                        str = convert_bytes_to_string(current_addr, current_addr+count*step)
                        print(f"str {str} {hex(current_addr)} {count}")
                        if str:
                            new_data_content.append(str)
                            string_set.add(str)
                        current_addr += count*step
                        index += count
                    #     print(f"strstr {str}")
                    #     break
                    elif data_str[index] == "2":
                        new_data_content.append(data_content[index])
                        current_addr += step
                        index += 1
                    
                data_content = copy.deepcopy(new_data_content)
                        
    # find usage
    if isuri == 1:
        object_content_dict = {}
        _name = idc.get_name(object_start, idaapi.GN_VISIBLE)
        object_content_dict[_name] = data_content
        caller_function = {}
        data_xrefs = list(XrefsTo(object_start))
        print(f"is inspecting {hex(object_start)} {data_xrefs}")
        dest_addrs = []
        for dref in data_xrefs:
            dest_addrs.append(dref.frm)
        if not data_xrefs:
            # immediate search
            _dest = search_immediate(object_start)
            if _dest:
                dest_addrs.append(_dest)
            else:
                _dest = search_immediate_from_insn(object_start)
                if _dest:
                    dest_addrs.append(_dest)
        print("data rxrefff", " ".join(hex(i) for i in dest_addrs))
        # if len(dest_addrs) == 1 and ida_bytes.is_data(dest_addrs[0]):
        if len(dest_addrs) == 1 and not is_code_segment(dest_addrs[0]):
            # off_51E920:     .word aLogin, 0, sub_48F9EC, 0, 0, 0, 0, 0, aSetclientinfo
            # off_51F890:     .word aLogin, off_51E920
            # nested data
            _start, _end = object_get_data_object(dest_addrs[0])
            current_addr = _start
            o_content = []
            while current_addr < _end:
                # _a, _b = object_get_data_object(idaapi.get_dword(current_addr))
                # nested data
                print(f"hhhhhh {hex(idaapi.get_dword(current_addr))} {hex(object_start)} {hex(object_end)}")
                _v =idaapi.get_dword(current_addr)
                if _v >= object_start and _v < object_end:
                    o_content.append(hex(_v))
                elif idc.get_strlit_contents(_v):
                    str = idc.get_strlit_contents(_v).decode('utf-8', errors='ignore').strip()
                    if str:
                        o_content.append(str)
                    else:
                        o_content.append(hex(idaapi.get_dword(current_addr)))
                    print(f"stttttttt {str}")
                else:
                    o_content.append(hex(_v))
                current_addr += 4

            # upper
            object_start = _start
            _name = idc.get_name(_start, idaapi.GN_VISIBLE)
            object_content_dict[_name] = o_content
            dest_addrs = []
            _refs = list(XrefsTo(object_start))
            for dref in _refs:
                dest_addrs.append(dref.frm)
            if not data_xrefs:
                _d = search_immediate(object_start)
                if _d:
                    dest_addrs.append(_d)
        print(f"ddddest {dest_addrs}")
        for drefea in dest_addrs:
            print(f"hhhhhh {hex(drefea)}")
            if is_code_segment(drefea):
                # find object start
                print(f"data xref to {hex(object_start)} {hex(drefea)}  ")
                dref_func = idaapi.get_func(drefea)
                print(f"fffffff {hex(drefea)} {dref_func}")
                if dref_func:
                    print(f"data xref to {idaapi.get_func_name(dref_func.start_ea)}")
                    caller_function["isuri"] = 1
                    caller_function["uristring"] = string_set
                    caller_function["urifunction"] = {}
                    caller_function["urifunction"]["funcname"] = idaapi.get_func_name(dref_func.start_ea) 
                    # caller_function["urifunction"]["arrayname"] = var_name
                    caller_function["urifunction"]["arraycontent"] = object_content_dict
                    
                    return caller_function
            # break
    return {}

def check_call_site(func_ea, function_name, _byteod):
    print(f"function_name {function_name}")
    # cross-reference
    caller_function = {}
    caller_function[function_name] = set()
    xrefs = list(XrefsTo(func_ea))

    callsite_with_string = 0
    hascode = 0
    object_content_dict = {}
    process_data = 0
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
        # xref type
        # print(f"typppppppp {xref.type} {hex(from_ea)}")
        if (xref.type >= 16 and xref.type <= 21):
            disasm = idc.GetDisasm(from_ea)
            # print(f"disasm {disasm} {hex(from_ea)}")
            if 'BL' in disasm or "BLX" in disasm or "B" in disasm:
                # ARM get caller
                caller_func = idaapi.get_func(from_ea)
                if caller_func:
                    caller_function[function_name].add(idaapi.get_func_name(caller_func.start_ea))
            elif 'jal' in disasm or "jalr" in disasm or "bal" in disasm or "j" in disasm:
                # MIPS get caller
                caller_func = idaapi.get_func(from_ea)
                if caller_func:
                    caller_function[function_name].add(idaapi.get_func_name(caller_func.start_ea))
            hascode = 1
                
        elif xref.type == 1 and insn:
            # print(f"code process {hex(xref.frm)}  ")
            
            disasm = idc.GetDisasm(from_ea)
            if "addiu" in disasm:
                # MIPS caller is pointer
                # xref.type  == 1
                _str, _func = mips_get_strings_func_from_addiu(insn)
                if _func:
                    if idaapi.get_func_name(_func.start_ea) == function_name:
                        print(f"xref code in {hex(from_ea)} {idaapi.get_func_name(_func.start_ea)}")
                        caller_func = idaapi.get_func(from_ea)
                        if caller_func:
                            caller_function[function_name].add(idaapi.get_func_name(caller_func.start_ea))
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
                    
                    print(f"inspecting previous {hex(prev_ea)}")
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
                        caller_function[function_name].add(idaapi.get_func_name(caller_func.start_ea))
            hascode = 1    
        
        if xref.type >= 1 and xref.type <= 5  and len(newxrefs) == 1:
            # URI in data
            # aVerCheckUpgrad+0xA ; DATA XREF: sub_ED50+33C↑o
            # .data:000E2CAC                                         ; sub_ED50:off_FD68↑o ...
            # .data:000E2CAC                                         ; "upgrade.cgi"
            # .data:000E2CB0                 DCD sub_27CF8
            # .data:000E2CB4                 DCD aUpgradeCheckCg     ; "upgrade_check.cgi"
            # .data:000E2CB8                 DCD sub_2785C
            print(f"process {hex(xref.frm)} ")
            process_data = xref.frm
        
            isuri = 0
          
    if len(newxrefs) == 0 or process_data:
        # print(f"No cross references to function at {hex(func_ea)}")
        # print(f"search immediate at {construct_xref_data(func_ea)}")
        calljson = construct_xref_data_struct(func_ea, process_data)
        # print(f"call json {list(calljson.keys())}" , calljson["isuri"], calljson["urifunction"]["funcname"])
        for key in calljson:
            caller_function[key] = calljson[key]
    
    print(f"function name {function_name} called by {caller_function}")
    return caller_function 
    
def find_function_parent(function_name, _byteod):
    # grandparent
    func = get_function_from_name(function_name)
    final_result = {}
    final_result["URIDATA"] = []
    if not func:
        print(f"We could not find funtion {function_name}")
        return
    print(f"first xref")
    # first layer caller subAAA->getsvar,get sub_AAA
    caller = check_call_site(func.start_ea, function_name, _byteod)
    # do not consider first layer
    # if "isuri" in caller and caller["isuri"] == 1:
    #     final_result["isUriDispatch"] = 1
    #     return final_result
    # if function_name in caller:
    #     final_result[function_name] = caller[function_name]
    for _cname in caller[function_name]:
        # _cname sub_AAA
        _func = get_function_from_name(_cname)
        if _func:
            _function_name = _cname
            
            # second layer caller sub_BBB->subAAA->getsvar,get sub_BBB
            print(f"second xref {_function_name} {hex(_func.start_ea)}")
            _cal = check_call_site(_func.start_ea, _function_name, _byteod)
            if "isuri" in _cal and _cal["isuri"] == 1:
                tempjson = {}
                tempjson["isUriDispatch"] = 1
                tempjson["UriStrings"] = list(_cal["uristring"])
                tempjson["urifunction"] = _cal["urifunction"]
                final_result["URIDATA"].append(tempjson)
                # return final_result
            if not _cal:
                continue
            if _function_name in _cal:
                final_result[_function_name] = _cal[_function_name]
            
            for _funcname in _cal[_function_name]: 
                if is_function_wrapper(idc.get_name_ea_simple(_funcname)):
                    # second layer caller is wrapper sub_BBB{sub_AAA();} third layer caller，subCCC->subBBB
                    print(f"third xref")
                    _nested = check_call_site(idc.get_name_ea_simple(_funcname), _funcname, _byteod)
                    if "isuri" in _nested and _nested["isuri"] == 1:
                        tempjson = {}
                        tempjson["isUriDispatch"] = 1
                        tempjson["UriStrings"] = list(_nested["uristring"])
                        tempjson["urifunction"] = _nested["urifunction"]
                        final_result["URIDATA"].append(tempjson)
                        # return final_result
                   
                    if _funcname in _nested:
                        final_result[_funcname] = _nested[_funcname]
    
    return final_result

def main():
    ida_auto.auto_wait()
    function_name = idc.ARGV[1]
    output_path = idc.ARGV[2]
    
    if ida_ida.inf_is_be():
        byteorder = "big"
    else:
        byteorder = "little"

    list_data_segment_variables()
    if len(Data_addr_list) == 0:
        # ARM "no data segent" only "LOAD segment"
        list_data_segment_variables("LOAD")
    outjson = find_function_parent(function_name, byteorder)

    for func in outjson:
        if func not in ["URIDATA"]:
            outjson[func] = list(outjson[func])
    with open(output_path, 'w') as f:
        json.dump(outjson, f, indent=4,ensure_ascii=False)

    # Exit IDA Pro
    ida_pro.qexit(0)

if __name__ == "__main__":
    main()