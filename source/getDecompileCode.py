# get decompilded code
import idaapi
import idc
import ida_hexrays
import ida_name
import ida_auto
import ida_pro
import sys
import time

def log(msg):
    with open("aab.txt", "a") as f:
        f.write(msg + "\n")
        
def wait_for_analysis():
    # while idaapi.get_func_qty() == 0:
    print("Waiting for function analysis...")
    time.sleep(10)  

# get definition by name
def decompile_function(function_name, output_path):
    # get the function address by name
    func_addr = idc.get_name_ea_simple(function_name)
    print(f"Function address: {hex(func_addr)}")
    if func_addr == idc.BADADDR:
        print(f"Function name {function_name} not found")
        return 
    # get the function object
    func = idaapi.get_func(func_addr)
    print(f"Function object: {func} {hex(func_addr)}")
    if not func:
        print(f"Failed to get function at address {hex(func_addr)}.")
        return 
    print(f"Decompiling function at address, {hex(func_addr)}")
    # Decompile the function using Hex-rays decompiler
    try:
        cfunc = ida_hexrays.decompile(func)
        if cfunc:
            decompiled_code = str(cfunc)
            with open(output_path, "w") as f:
                f.write(decompiled_code)
        else:
            print(f"Failed to decompile function '{function_name}'.")
    except ida_hexrays.DecompilationFailure as e:
        print(f"Decompilation failure: {str(e)}")
    return 

def main():
    ida_auto.auto_wait()

    function_name = idc.ARGV[1]
    output_path = idc.ARGV[2]
    # function_name = "main"
    # output_path = "aaa.txt"
    # print(f"Decompiling function {function_name} {output_path}\n")
    decompile_function(function_name, output_path)
    # exit idapro
    ida_pro.qexit(0)

if __name__ == "__main__":
    main()