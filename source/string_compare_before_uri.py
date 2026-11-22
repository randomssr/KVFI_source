# match strings
import os
import json
import sys
from config import settings

def get_string_from_frontend(frontend_string_json):
    with open(frontend_string_json, "r") as f:
        content = json.load(f)
    # lower 
    frontend_strings = [x.lower() for x in content]
    return frontend_strings

def get_string_from_function(function_call_json, function_name, binary_path_list):
    called_strings = set()
    with open(function_call_json, "r") as f:
        content = json.load(f)

    for binary_path in binary_path_list:
        if binary_path in content and function_name in content[binary_path]["callsite_result"]:
            _strs = content[binary_path]["callsite_result"][function_name]["parameters"]
            called_strings = called_strings | set(_strs)
    return list(called_strings)
            
def compare_strings(frontend_string, function_string):
    # print(frontend_string)
    # print(function_string)
    intersection = set(frontend_string) & set(function_string)
    return intersection

def compare_string_frontend_function_uri(frontend_string, uri_string_list):
    combine_string = []
    for _str in uri_string_list:
        if "." in _str:
            combine_string.append(_str.split(".")[0])
        combine_string.append(_str)
    intersec = compare_strings(frontend_string, combine_string)
    # if intersec:
    #     print(f"intersection is {intersec}")
    #     return 1
    # return 0
    return intersec

def compare_string_frontend_function_key_value(frontend_string, function_name, binary_path, binary_list_json, function_call_json):
    with open(binary_list_json, "r") as f:
        content = json.load(f)
    
    if binary_path in content and function_name in content[binary_path]:
        if "export_binary" in content[binary_path][function_name]:
            binary_path_list = content[binary_path][function_name]["export_binary"]
        else:
            binary_path_list = [binary_path]
        function_string = get_string_from_function(function_call_json, function_name, binary_path_list)
        intersection = compare_strings(frontend_string, function_string)
        if intersection:
            print(f" There is intersection {intersection}")
            return 1
    return 0


def find_value(funcname, binary_list_path, call_values_path):
    with open(binary_list_path, "r") as f:
        content = json.load(f)
    involved_bins = []
    for binpath in content:
        if funcname in content[binpath]:
            if "export_binary" in content[binpath][funcname]:
                involved_bins.extend(content[binpath][funcname]["export_binary"])
            involved_bins.append(binpath)
            break
    with open(call_values_path, "r") as f:
        content1 = json.load(f)
    # print(call_values_path)
    res_values = set()
    for binpath in involved_bins:
        if funcname in content1[binpath]["callsite_result"]:
            res_values |= set(content1[binpath]["callsite_result"][funcname]["parameters"])

    return res_values

def main():
    devicename = sys.argv[1]
    frontend_string_json = os.path.join(settings.result_path, devicename, "keywords.json")
    cfg_string_json = os.path.join(settings.result_path, devicename, "cfgkeywords.json")
    function_call_json = os.path.join(settings.result_path, devicename, "final_call_output.json")
    binary_list_json = os.path.join(settings.result_path, devicename, "final_possible.json")
    llm_json = os.path.join(settings.result_path, devicename, "llm_possible.json")
    # ablation study no llm first layer
    llm_json = os.path.join(settings.result_path, devicename, "final_possible.json")
    
    string_check_result_path = os.path.join(settings.result_path, devicename, "string_check_result.json")
    frontend_string_lower = get_string_from_frontend(frontend_string_json)
    
    cfg_string_lower = get_string_from_frontend(cfg_string_json)
    check_string_results = {}
    with open(llm_json, "r") as f:
        llm_result = json.load(f) 
   
    for binary_path in llm_result:
        check_string_results[binary_path] = {}
        for func in llm_result[binary_path]:
            check_string_results[binary_path][func] = {}
            key_values = find_value(func, binary_list_json, function_call_json)
            key_values_lower = set()
            for var in key_values:
                # if var.startswith("New"):
                #     var = var[3:]
                if "xx." in var.lower() and var.lower().count("xx.") == 1:
                    # xx. is 1. 2. 3. 
                    for i in range(10):
                        key_values_lower.add(var.lower().replace('xx.',f"{str(i)}."))
                        
                key_values_lower.add(var.lower())
            intersection1 = compare_strings(frontend_string_lower, key_values_lower)
            intersection1_cfg = compare_strings(cfg_string_lower, key_values_lower)
            # if func == "uci_safe_get":
            #     print(f"{intersection1_cfg}")
            #     print(f"{intersection1}")

            if len(intersection1_cfg) >= len(intersection1):
                # check_string_results["cfg_string"][func] = list(intersection1_cfg)
                check_string_results[binary_path][func] = {"type":"cfg_string","need":0,"intersect":list(intersection1_cfg)}
            elif len(intersection1) > len(key_values)/3:
                # check_string_results["key_value"][func] = list(intersection1)
                check_string_results[binary_path][func] = {"type":"key_value","need":1,"intersect":list(intersection1)}
            elif len(intersection1) > 0:
                # check_string_results["candidate"][func] = list(intersection1)
                need = 1 if len(intersection1) > 2 else 0
                check_string_results[binary_path][func] = {"type":"candidate", "need":need,"intersect":list(intersection1)}
 
    with open(string_check_result_path, "w") as f:
        json.dump(check_string_results, f, indent=4, ensure_ascii=False) 

if __name__ == "__main__":
    main()
    