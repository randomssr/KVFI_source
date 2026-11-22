# ida python get start ea of function by name
import idaapi
import idc
import ida_hexrays
import ida_name
import ida_auto
import ida_pro

# get start ea of function
def get_function_addr(function_name, output_path):
    # get the function address by name
    func_addr = idc.get_name_ea_simple(function_name)
    print(f"Function address: {hex(func_addr)}")
    if func_addr == idc.BADADDR:
        func_addr = 0

    with open(output_path, "w") as f:
        f.write(hex(func_addr))
    return 
        
def main():
    ida_auto.auto_wait()
    function_name = idc.ARGV[1]
    output_path = idc.ARGV[2]
    # function_name = "sub_16700"
    # output_path = "aaa.txt"
    get_function_addr(function_name, output_path)
    ida_pro.qexit(0)

if __name__ == "__main__":
    main()