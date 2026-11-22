import os
import sys
import json
import subprocess
from openai import OpenAI, APIError
import hashlib
from pathlib import Path
import re
from config import settings
import time

vendor_content = {}
llm_time = 0
other_type = {}

def message_to_json(message):
    # convert the message to json
    # if "'" in message:
    #     message = message.replace("'", '"')
    if message.startswith("json"):
        message = message[4:] 
    index1 = message.find("{")
    index2 = message.rfind("}")
    message = message[index1:index2+1]
    message = re.sub(r'/\*.*?\*/', '', message, flags=re.DOTALL)
    message = re.sub(r'#.*?{', ' {', message, flags=re.DOTALL)
    # if "\n" in message:
    #     message = message.replace("\n","")
    
    return json.loads(message)

def calculate_file_sha1(file_path):
    # calculate the file content hash
    hash_sha1 = hashlib.sha1()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha1.update(chunk)
    return hash_sha1.hexdigest()

def llm_deepin_check(funcname, decompiled_code, called_code):
    prompt = """
    You are an expert program analysis assistant\n. Your task is to analyze the given code snippet and determine whether `function` is used to get values from key-value pairs.\n
    Instructions:\n
    1. Understand the functionality of each function and determine whether `function` is proposed to retrieve values from key-value pairs. The key string is input parameter. The value is acquired from pairs and directly returned. \n
    2. NOTE: The function should get values, not set, not update, not exec, or not just match or just search. It is not aimed for other file parsing or environment(calling getenv) or configuration(calling config_get) fetching. In addition, The special function `GetValue` is for handling configuration. If the function calls `GetValue`(specific name) then it is not compliant. \n
    3. Analyze the parameter position of `key`, `value` and `pair` based on the definition and callsite code.
    Output the results in JSON format:\n
    {"match":"", "reason":"", "value_pos":"", "key_pos":"", "pair_pos":"", "other_type":""}\n
        - match: Set to 1 if the `function` contains the required chracteristics, or 0 if it does not. \n 
        - reason: Reasoning based on code analysis. \n
        - value_pos: if it matches, give the return value position. If it is the parameter, give the parameter index(from 0). If it is the return, output -1.\n
        - key_pos: Give the parameter index (from 0) of the key to be queried.\n
        - pair_pos: Give the parameter index (from 0) of the key-value pair variable. If the pair is a global variable used in the function, set to -1.\n
        - other_type: Other types that the function parses, such as config or environment variables.
        
    NOTE:  Carefully heed the user's instructions. Only output the JSON without any additional text or explanations.\n
    """
    # openai 
    client = OpenAI(
        base_url = "https://api.deepseek.com/v1",
        api_key = ""
    )
    
    while True:
        try:
            response = client.chat.completions.create(
                model = "deepseek-reasoner",
                temperature = 0,
                stream=False,
                top_p = 1,
                presence_penalty = 0,
                frequency_penalty = 0,
                # response_format={
                #     'type': 'json_object'
                # },
                messages=[
                    {
                        "role": "system",
                        "content": prompt
                    },
                    {
                        "role": "user",
                        "content":f"Analyze {funcname}\n. Here is the definition code: {decompiled_code}. Here is the callsite code:{called_code}."
                    }
                ]
            )
            
            return response.choices[0].message.content
        except APIError as e:
            print(f"error API 500 response because of {e}")

def ida_plugin_ana(ida_path, bin_path, ida_script, function_name, output_path):
    try:
        if os.path.isfile(output_path):
            os.remove(output_path)
        # Command to run IDA Pro with the specified script
        command = [ida_path, '-A', f'-S{ida_script} {function_name} {output_path}', bin_path]
        print(command)
        result = subprocess.run(command, capture_output=True, text=True)

        # Print the output for debugging purposes
        print("IDA Pro output:")
        print(result.stdout)
        print(result.stderr)
        if result.returncode != 0:
            print(f"IDA Pro exited with error code {result.returncode}")
        else:
            print("IDA Python script executed successfully")
    except Exception as e:
        print(f"Error running IDA script: {e}")

def get_decompiled_code(binary_path, func, devicename):
    # get definition code
    # binary_path is func defined
    ida_path = settings.ida_path
    ida_script = os.path.join(settings.script_path, "function_and_called.py")
    output_path = os.path.join(settings.result_path, devicename, "temp.json")
    
    ida_plugin_ana(ida_path, binary_path, ida_script, func, output_path)
    decompiled_code = ""
    if os.path.isfile(output_path):
        with open(output_path, "r") as f:
            content = json.load(f)
            decompiled_code = content["code"]

    return decompiled_code   

def deepin_analyse(binary_path, funcname, defined_code, called_code):
    # reasoning analysis
    global vendor_content
    global llm_time
    global other_type
    file_sha1 = calculate_file_sha1(binary_path)
    if file_sha1 not in vendor_content:
        vendor_content[file_sha1] = {}
        vendor_content[file_sha1]["files"] = []
        vendor_content[file_sha1]["func_res"] = {}
    vendor_content[file_sha1]["files"].append(binary_path)
    
    if funcname in vendor_content[file_sha1]["func_res"]:
        resjson = vendor_content[file_sha1]["func_res"][funcname]
        print(f"fetching res json")
    else:
        st = time.time()
        res = llm_deepin_check(funcname, defined_code, called_code)
        print(res)
        llm_time += (time.time()-st)
        resjson = message_to_json(res)
        vendor_content[file_sha1]["func_res"][funcname] = resjson
    print(resjson)
    if "match" in resjson:
        try:
            if str(resjson["match"]) == "0":
                print(f"error in previous jusgment {funcname}")
                if resjson["other_type"] != "":
                    if binary_path not in other_type:
                        other_type[binary_path] = {}
                    other_type[binary_path][funcname] = {}
                    other_type[binary_path][funcname] = {"type": resjson["other_type"], "value_pos":resjson["value_pos"], "key_pos":resjson["key_pos"], "pair_pos":resjson["pair_pos"]}
                    
                return ()
            else:
                value_pos = int(resjson["value_pos"])
                key_pos = int(resjson["key_pos"])
                pair_pos = int(resjson["pair_pos"])
                return (value_pos, key_pos, pair_pos)
        except Exception as e:
            print(f"error happend!!!! {e}")
            return ()

def find_called_code(binary_path, func, devicename):
    # get call site
    # binary_path is func called
    ida_path = settings.ida_path
    ida_script = os.path.join(settings.script_path, "get_callsite_decompile_code.py")
    output_path = os.path.join(settings.result_path, devicename, "temp.json")
    
    ida_plugin_ana(ida_path, binary_path, ida_script, func, output_path)
    called_code = ""
    if os.path.isfile(output_path):
        with open(output_path, "r") as f:
            content = json.load(f)
        if func in content:
            lines = content[func]
            if len(content[func]) > 10:
                lines = content[func][:10]
            for line in lines:
                called_code += line+"\n"
            # called_code = content[func]
    print(called_code)
    return called_code   

def get_func_addr(binary_path, func, devicename):
    # get func start ea
    # binary_path is func defined
    ida_path = settings.ida_path
    ida_script = os.path.join(settings.script_path, "get_func_addr.py")
    output_path = os.path.join(settings.result_path, devicename, "tempaddr.txt")
    define_addr = ""
    ida_plugin_ana(ida_path, binary_path, ida_script, func, output_path)
    called_code = ""
    if os.path.isfile(output_path):
        with open(output_path, "r") as f:
            content = f.read()
        define_addr = content.strip()
        if define_addr == "0x0":
        
            print(f"{func} not defined in {binary_path}")
    return define_addr   

def main():
    devicename = sys.argv[1]
    possible_results = os.path.join(settings.result_path, devicename, "final_possible.json")
    llm_check_results = os.path.join(settings.result_path, devicename, "llm_possible.json")
    stringcheck_results = os.path.join(settings.result_path, devicename, "string_check_result.json")
    uri_check_result_path = os.path.join(settings.result_path, devicename, "uricheck_result.json")
    deepin_result_path = os.path.join(settings.result_path, devicename, "deepin_result_path.json")
    deepin_othertype_result_path = os.path.join(settings.result_path, devicename, "deepin_other_type.json")
    
    vendor_path = Path(settings.vendor_deepin_result)
    st = time.time()
    if not vendor_path.exists():
        data = {}
        with vendor_path.open('w') as f:
            json.dump(data, f, indent=4)
    global vendor_content
    global llm_time
    global other_type
    with open(vendor_path,"r") as f:
        vendor_content = json.load(f)
    
    with open(llm_check_results, "r") as f:
        llm_result_content = json.load(f)
    with open(stringcheck_results, "r") as f:
        string_result_content = json.load(f)
    with open(uri_check_result_path, "r") as f:
        uri_result_content = json.load(f)
    result = {}
    for binary_path in uri_result_content:
        for func in uri_result_content[binary_path]:
            # find start ea
            func_addr = get_func_addr(binary_path, func, devicename)
            # get callsite
            deepin_path = uri_result_content[binary_path][func]["uribinpath"]
            called_code = find_called_code(deepin_path, func, devicename)
            # get definition
            defined_code1 = llm_result_content[binary_path][func]["decompile"]
            defined_code = get_decompiled_code(binary_path, func, devicename)
            if "hsearch_r" in defined_code and "hsearch_r()" in defined_code:
                defined_code = defined_code1
            # print(defined_code)
            # reasong LLM analysis
            poses = deepin_analyse(binary_path,func, defined_code, called_code)
            if len(poses) == 3:
                value_pos = poses[0]
                key_pos = poses[1]
                pair_pos = poses[2]
                # collect info
                paramlen = llm_result_content[binary_path][func]["paramlen"]
                call_count = llm_result_content[binary_path][func]["call_count"]
                is_export = llm_result_content[binary_path][func]["is_export"]
                export_binary = []
                if "export_binary" in llm_result_content[binary_path][func]:
                    export_binary = llm_result_content[binary_path][func]["export_binary"]
                string_intersect = string_result_content[binary_path][func]["intersect"]
                uri_func = uri_result_content[binary_path][func]["urifunc"]
                if binary_path not in result:
                    result[binary_path] = {}
                result[binary_path][func] = {}
                result[binary_path][func]["paramlen"] = paramlen
                result[binary_path][func]["value_pos"] = value_pos
                result[binary_path][func]["key_pos"] = key_pos
                result[binary_path][func]["pair_pos"] = pair_pos
                result[binary_path][func]["call_count"] = call_count
                result[binary_path][func]["string_intersect"] = string_intersect
                result[binary_path][func]["uri_func"] = uri_func
                result[binary_path][func]["uribin_path"] = deepin_path
                result[binary_path][func]["is_export"] = is_export
                result[binary_path][func]["export_binary"] = export_binary
    
    
    with open(vendor_path, "w") as f:
        json.dump(vendor_content, f, indent=4, ensure_ascii=False) 
      
    with open(deepin_result_path, "w") as f:
         json.dump(result, f, indent=4, ensure_ascii=False) 
    with open(deepin_othertype_result_path, "w") as f:
         json.dump(other_type, f, indent=4, ensure_ascii=False)
    totaltime = time.time() - st
    print(f"total time cost {totaltime} llm analysis time cost {llm_time}")


if __name__ == "__main__":
    main()