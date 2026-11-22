# analyze functionality using LLM
import os
import sys
import requests
import json
import subprocess
import re
import asyncio
import ollama
from openai import OpenAI, APIError
from config import settings
import time
from pathlib import Path
import hashlib
import time 


LIBC_FUNCTION = ["malloc", "calloc", "zalloc", "realloc", "xmalloc", "xcalloc", "xzalloc", "xrealloc","xstrdup", "strdup", "read", "fread", "free", "gets", "getc", "fgets", "fgetc", "close", "fstat", "stat", "ioctl", "lseek", "seek", "open", "write", "printf", "sprintf", "fprintf", "vsnprintf", "vsprintf", "snprintf", "vfprintf","asprintf","vasprintf","sscanf", "vsscanf","fflush","fwrite","putchar","memcpy","memset","memchr","memcmp","strnlen","strerror_r","strdup","strerror","perror","fatal", "error","strtoul", "getenv", "setenv","strcpy","strncpy","strlcpy","strlcat","strstr","stristr","stricmp","strnicmp","getopt", "getopt_long","exit","opendir","readdir","closedir","mkdir","mkpath","fcntl","_exit","_Exit","fclose","fopen","strchr","strchrnul","strcspn","strncmp","strrchr","strspn","kill","strlen","strncmp","strcmp","hcreate","hsearch","hdestroy","hcreate_r","hdestroy_r","puts","fputs","signal","chdir","getcwd","chroot","mkdir","strcasecmp","strncasecmp","strcasestr","strsep","strtok","strpbrk","syslog","openlog","unlink","assert","strtok_r","strcat","cprintf","sleep","usleep","chmod","pthread_mutex_lock","pthread_mutex_init","popen","inet_addr","inet_aton","inet_ntoa","inet_pton","inet_ntop","qsort","atoi","remove","system","socket","bind","listen","connect","accept","send","access","symlink","readlink","sigaction","strncat","umount","mount","time","strftime", "fscanf","sendto","dlopen", "dlsym","dladdr","dlinfo","dlclose","warn","warnx","err","errx","pthread_create","pthread_sigmask","bcopy","__assert","hsearch_r"]
# final result
match_llm = {}
match_nvram = {}
check_time = 0
def calculate_file_sha1(file_path):
    # calculate file content hash
    hash_sha1 = hashlib.sha1()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha1.update(chunk)
    return hash_sha1.hexdigest()

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
    


def prompt_check(decompiled_code,function_name, has_nvram):
    # LLM check
    prompt_4omini = """
    You are an expert program analysis assistant\n. Your task is to analyze the given code snippet and determine whether `function` is used to get values from key-value pairs.\n
    Instructions:\n
    1. The `function` can call other functions. Understand the functionality of each called function and then use these information to acquire the semantic functionality of `function`.\n
    2. According to the semantics, determine whether `function` is proposed to retrieve values from key-value pairs. The key string is input parameter. The `function` can call other functions to complete searching, comparison, or retrieving. \n
    3. The function should get values, not set, not update or not just match. \n
    
    Output the results in JSON format:\n
    {"match":"", "reason":"", "value_pos":""}\n
        - match: Set to 1 if the `function` contains the required chracteristics, or 0 if it does not. \n 
        - reason: Reasoning based on code analysis. \n
        - value_pos: if it matches, give the return value position. If it is the parameter, give the parameter index(from 0). If it is the return, output -1.\n
    NOTE:  Carefully heed the user's instructions. Only output the JSON without any additional text or explanations.\n
    
    """
    nvramprompt_4omini= """
    You are an expert program analysis assistant\n. Your task is to analyze the given code snippet and determine whether `function` is used to get values from key-value pairs.\n
    Instructions:\n
    1. The `function` can call other functions. Understand the functionality of each called function and then use these information to acquire the semantic functionality of `function`.\n
    2. According to the semantics, determine whether `function` is proposed to retrieve values from key-value pairs. The key string is input parameter. The `function` can call other functions to complete searching, comparison, or retrieving. \n
    3. The function should get values, not set, not update or not just match. \n
    In addition, if `function` is aimed to retrieve values from NVRAM, such as nvram_get, or it is the encapsulation of nvram_get, please note it in the `is_nvram` column.
    Output the results in JSON format:\n
    {"match":"", "reason":"", "value_pos":"", "is_nvram":""}\n
        - match: Set to 1 if the `function` contains the required chracteristics, or 0 if it does not. \n 
        - reason: Reasoning based on code analysis. \n
        - value_pos: if it matches, give the return value position. If it is the parameter, give the parameter index(from 0). If it is the return, output -1.\n
        - is_nvram: Set to 1 if the `function` aims to get values from NVRAM, or 0 if it does not.\n
    NOTE:  Carefully heed the user's instructions. Only output the JSON without any additional text or explanations.\n

    """
    prompt = nvramprompt_4omini if has_nvram else prompt_4omini

    # openai 
    client = OpenAI(
        base_url="", 
        api_key="")
  
    while True:
        try:
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                n=1,
                temperature = 0.1,
                stream=False,
                top_p = 1,
                # presence_penalty = 0,
                # frequency_penalty = 0,
                response_format={
                    'type': 'json_object'
                },
                messages = [
                    {
                        "role": "system",
                        "content": prompt
                    },
                    {
                        "role": "user",
                        "content":f"Here is the given code, analyze {function_name}: {decompiled_code}"
                    }
                ]
            )
            
            return response.choices[0].message.content
        except APIError as e:
            print(f"error API 500 response because of {e}")
            
def func_decompile_run_ida_script(ida_path, binary_path, script_path, function_name, output_path):
    # get definitions
    """
    Run an IDA Python script on a given binary file using IDA Pro.

    :param ida_path: Path to the IDA Pro executable.
    :param binary_path: Path to the binary file to analyze.
    :param script_path: Path to the IDA Python script to run.
    :param function_name: Name of the function to decompile.
    :param output_path: Path to the output file to write the decompiled code.
    """
    
    try:
        # Command to run IDA Pro with the specified script and function name
        command = [
        ida_path,                               
        # "-B",                                   
        '-A',                                   
        f'-S{script_path} {function_name} {output_path}',
        binary_path                            
        ]
        if os.path.exists(output_path):
            os.remove(output_path)
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

        # Read the decompiled code from the output file
        
    except Exception as e:
        print(f"Error running IDA script: {e}")
        return None
    return None

def get_param_count(funcname, bin_path, funcinfo_path):
    with open(funcinfo_path, "r") as f:
        content = json.load(f)
    if bin_path in content and funcname in content[bin_path]:
        return content[bin_path][funcname]["paramlen"]

async def get_llm_result(all_funcs, ida_path, binary_path, script_path, output_path, decompile_script_path, decompile_output, finalcontent):
    global match_llm
    global match_nvram
    global check_time
    print(f"processing {binary_path}")
    # vendor的总结果
    vendor_path = Path(settings.vendor_func_result)
    if not vendor_path.exists():
        data = {}
        with vendor_path.open('w') as f:
            json.dump(data, f, indent=4)
        
    with open(vendor_path,"r") as f:
        vendor_content = json.load(f)
    file_sha1 = calculate_file_sha1(binary_path)
    if file_sha1 not in vendor_content:
        vendor_content[file_sha1] = {}
        vendor_content[file_sha1]["files"] = []
        vendor_content[file_sha1]["func_res"] = {}
    vendor_content[file_sha1]["files"].append(binary_path)
    # whether nvram
    hasnvram = 0
    cmds = f"readelf -s {binary_path} | grep -i nvram"
    try:
        result = subprocess.run(cmds, shell=True, capture_output=True, text=True)
        if result.stdout:
            hasnvram = 1
    except Exception:
        pass
    print(f"has nvram {binary_path} {hasnvram}")
    _funcs = finalcontent[binary_path]
    
    for _func in _funcs:
        # get the decompiled code of the func and its called functions
        func_decompile_run_ida_script(ida_path, binary_path, script_path, _func, output_path)
        decompiled_code = ""
        if os.path.exists(output_path):
            with open(output_path, 'r') as f:
                outjson = json.load(f)
            decompiled_code += outjson["code"] + "\n"
            ex_funcs = set(outjson["external_funcs"])
            print(f"exfun nc {ex_funcs}")
            if len(ex_funcs) != 0:
                with open(all_funcs, "r") as f:
                    totalfuncs = json.load(f)
                for _path in totalfuncs:
                    if _path not in ["totalfunc"]:
                        defines = set(totalfuncs[_path]["funcnames"])
                        _sect = defines & ex_funcs
                        # 去掉libc里面的库函数
                        if "libc-" in _path.lower() or "libc.so" in _path.lower() or "pthread" in _path.lower() or "stdc" in _path.lower() or "gcc" in _path.lower():
                            for _f in _sect:
                                ex_funcs.discard(_f)
                        _sect = set(LIBC_FUNCTION) & ex_funcs
                        for _f in _sect:
                            ex_funcs.discard(_f)
                            # _sect = set()
                for _path in totalfuncs:
                    if _path not in ["totalfunc"]:
                        defines = set(totalfuncs[_path]["funcnames"])
                        _sect = defines & ex_funcs                
                        for _f in _sect:
                            func_decompile_run_ida_script(ida_path, _path, decompile_script_path, _f, decompile_output)
                            if os.path.exists(decompile_output):
                                with open(decompile_output, 'r') as f:
                                    decompiled_code = f.read() + "\n" + decompiled_code
                                ex_funcs.discard(_f)
                        if len(ex_funcs) == 0:
                            break

        if decompiled_code:
            print(decompiled_code)
            if "nvram" in decompiled_code.lower():
                hasnvram = 1
            else:
                hasnvram = 0

            try:
                if _func in vendor_content[file_sha1]["func_res"]:
                    # getting the result of function
                    res_json = vendor_content[file_sha1]["func_res"][_func]
                    print(f"fetching from vendor results: {res_json}")
                else:
                    check_start = time.time()
                    # res = {}
                    res = prompt_check(decompiled_code, _func, hasnvram)
                   
                    check_time += (time.time()-check_start)
                    res_json = message_to_json(res)
                    vendor_content[file_sha1]["func_res"][_func] = res_json
                    # res = '{"match": 1, "pos": -1, "decompile":"aaaa"}'
                    # print(f"results: {res}")
                if str(res_json["match"]) == "1":
                    # find possible key-value retrieving function,，not with nvram
                    if ("is_nvram" in res_json and int(res_json["is_nvram"]) != 1) or "is_nvram" not in res_json:
                        if binary_path not in match_llm:
                            match_llm[binary_path] = {}
                        # match_llm[binary_path][_func] = finalcontent
                        match_llm[binary_path][_func] = finalcontent[binary_path][_func]
                        match_llm[binary_path][_func]["value_pos"] = int(res_json["value_pos"])
                        # match_llm[binary_path][_func]["key_pos"] = int(res_json["key_pos"])
                        # match_llm[binary_path][_func]["source_pos"] = int(res_json["source_pos"])
                        if "is_nvram" in res_json:
                            match_llm[binary_path][_func]["is_nvram"] = int(res_json["is_nvram"])
                        else:
                            match_llm[binary_path][_func]["is_nvram"] = -1
                        match_llm[binary_path][_func]["decompile"] = decompiled_code
                  
                if "is_nvram" in res_json and int(res_json["is_nvram"]) == 1:
                    if binary_path not in match_nvram:
                        match_nvram[binary_path] = {}
                    match_nvram[binary_path][_func] = finalcontent[binary_path][_func]
                    match_nvram[binary_path][_func]["value_pos"] = int(res_json["value_pos"])
                    # match_nvram[binary_path][_func]["key_pos"] = int(res_json["key_pos"])
                    # match_nvram[binary_path][_func]["source_pos"] = int(res_json["source_pos"])
                    match_nvram[binary_path][_func]["match"] = int(res_json["match"])
                    match_nvram[binary_path][_func]["decompile"] = decompiled_code
            except Exception as e:
                print(f"weeerrtrt")
                print(e)

    with open(vendor_path,"w") as f:
        json.dump(vendor_content, f, indent=4, ensure_ascii=False)
    # print(match_llm,match_nvram)

async def parse_function(final_possible_json, devicename):
    # check input-processing functionality
    ida_path = settings.ida_path
    # script_path = os.path.join(settings.script_path, "getDecompileCode.py")
    script_path = os.path.join(settings.script_path, "function_and_called.py")
    
    output_path = os.path.join(settings.result_path, devicename, "aaa.json")
    possible_code_path = os.path.join(settings.result_path, devicename, "possible_function_code.txt")
    
    funcinfo_path = os.path.join(settings.result_path, devicename, "final_possible.json")
    all_funcs = os.path.join(settings.result_path, devicename, "funcs.json")
    decompile_script_path = os.path.join(settings.script_path, "getDecompileCode.py")
    decompile_output = os.path.join(settings.script_path, "code.txt")
    # match_llm = {}
    with open(final_possible_json, "r") as f:
        content = json.load(f)
    # 一个binary_path一个task
    tasks = []
    for binary_path in content:

        args = (all_funcs, ida_path, binary_path, script_path, output_path, decompile_script_path, decompile_output, content)
        tasks.append(get_llm_result(all_funcs, ida_path, binary_path, script_path, output_path, decompile_script_path, decompile_output, content))
    await asyncio.gather(*tasks)   

def main():
    # vender like ASUS TPLINK
    devicename = sys.argv[1]
    final_possible_json = os.path.join(settings.result_path, devicename, "final_possible.json")
    llm_possible_path = os.path.join(settings.result_path, devicename, "llm_possible.json")
    nvram_possible_path = os.path.join(settings.result_path, devicename, "nvram_possible.json")
    starttime = time.time()
    loop = asyncio.get_event_loop()
    final_results = loop.run_until_complete(parse_function(final_possible_json, devicename))
    loop.close()
    global match_llm
    global match_nvram
    global check_time
    with open(llm_possible_path, "w") as f:
        json.dump(match_llm, f, indent=4, ensure_ascii=False)
    with open(nvram_possible_path, "w") as f:
        json.dump(match_nvram, f, indent=4, ensure_ascii=False)
    endtime = time.time()
    print(f"total check time  {check_time} cost time {endtime-starttime}")
    
    
if __name__ == "__main__":
    main()
    