# analyze candidate functions
# check request-dispatching in calling context

import json
import subprocess
import os
import sys
import time
import multiprocessing
import json
import requests
import re
import ollama
import hashlib
from pathlib import Path
import time
from openai import OpenAI, APIError
from config import settings
from dispatch_map import structural_uri_result   # §2.7: reuse engine A's dispatch discovery

urivendor_content={}
llm_check_time = 0
uri_result_json = {}
# §2.7 reuse accounting: how many URI-dispatch checks were answered by the shared
# structural dispatch map (engine A) vs. how many still needed an LLM call.
structural_hits = 0
llm_hits = 0

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
    # print("rererereree")
    # print(repr(message))
    
    return json.loads(message)

def prompt_uri_check(decompiled_code):
    prompt = """
        You are an expert program analysis assistant\n. Your task is to understand the functionality of the code snippet and check whether it is involved with network request dispatching\n. The request dispatching is to process the network request, and perform the appropriate actions according to different requests, not handling program options. Carefully heed the user's instructions.\n 
        Instructions:\n
        1. Identify request Dispatching: Determine if the function conforms to the below three forms. When the request uri meets the string, the corresponding is called.\n
        2. Extract Comparison Constants: Extract the constant request strings used in the comparisons. If the request dispatching is in a predefined structure, the comparison constants are also in the structure. \n
        There are three forms of request dispatching functions:\n
        1. String Comparison Method: The function compares the request string with and call the corresponding handling function.\n
        **Example**:\n
        if (!strcmp(s1, "scan.cgi")) sub_AAAA(a1, a2);\n
        if (!strcmp(s1, "phpcgi")) sub_BBBB(a1, a2, a3);\n
        These comparisons are consecutive and the code format is the same. 
        2. Callback Function Method: The function uses callback functions where the request string and the corresponding function are passed as parameters to a dispatcher function.\n
        **Example**:\n
            websFormDefine("scan.cgi", sub_AAAA);\n
            websFormDefine("phpcgi", sub_BBBB);\n
        3. These functions and their request strings are in a predefined data structure, such as array1=["scan.cgi",1,sub_AAAA,"phpcgi",2,sub_BBBB]. The program, upon finding the appropriate request string, calls a pre-registered handler function.
        sub_AAAA and sub_BBBB are handling functions. The `strings` result is ["scan.cgi", "phpcgi"].
        Output Format: Provide the results in JSON format with the following structure:\n
        {"match": "", "reason": "", "strings": [""]}\n
        - match: Set to 1 if the function is used to dispatch different requests, or 0 if it does not. If the number of strings is 0, or if the strings are all numbers, the `match` is 0.\n
        - reason: Provide reasoning based on the code analysis. \n
        - strings: List the extracted comparison request strings. \n
        NOTE: Only output the JSON without any additional text or explanations.\n

    """
    # openai 
    client = OpenAI(
        base_url="", 
        api_key="")
    while True:
        try:
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                temperature = 0.1,
                stream=False,
                top_p = 1,
                presence_penalty = 0,
                frequency_penalty = 0,
                response_format={
                    'type': 'json_object'
                },
                messages=[
                    {
                        "role": "system",
                        "content": prompt
                    },
                    {
                        "role": "user",
                        "content":f"Here is the given code: {decompiled_code}"
                    
                    }
                ]
            )
            return response.choices[0].message.content
        except APIError as e:
            print(f"error API 500 response because of {e}")


def check_parent_uri(need_inspect, devicename):
    global urivendor_content
    global llm_check_time
    global uri_result_json
    global structural_hits, llm_hits
    ida_path = settings.ida_path
    script_path = os.path.join(settings.script_path, "getDecompileCode.py")
    output_path = os.path.join(settings.result_path, devicename, "temp1.txt")
    
    for func in need_inspect:
        binpath = need_inspect[func]["binary_path"]
        if binpath in uri_result_json and func in uri_result_json[binpath]:
            continue

        # §2.7 structure-first: if ANY inspected parent function is a structurally-proven
        # dispatch point (engine A's shared dispatch map), confirm this getter from the map
        # with ZERO LLM calls. Only a getter no structural dispatch point covers falls
        # through to the LLM URI-check below. Structure only adds a positive; it never vetoes.
        resolved = False
        for inspect in need_inspect[func]["inspection"]:
            bpath = inspect["binary_path"]
            for _nf in inspect["need_funcs"]:
                struct = structural_uri_result(bpath, _nf)
                if struct is not None:
                    structural_hits += 1
                    uri_result_json.setdefault(binpath, {})[func] = {
                        "urifunc": _nf, "uribinpath": bpath,
                        "uristring": sorted(set(struct["strings"])), "origin": "structural"}
                    print(f"structural short-circuit (getter resolved, no LLM): {func} {_nf} "
                          f"[{len(struct['strings'])} uris]")
                    resolved = True
                    break
            if resolved:
                break
        if resolved:
            continue

        for inspect in need_inspect[func]["inspection"]:
            binary_path = inspect["binary_path"]
            need_funcs = inspect["need_funcs"]
            file_sha1 = calculate_file_sha1(binary_path)
            if file_sha1 not in urivendor_content:
                urivendor_content[file_sha1] = {}
                urivendor_content[file_sha1]["files"] = []
                urivendor_content[file_sha1]["func_res"] = {}
            urivendor_content[file_sha1]["files"].append(binary_path)
            for _need_f in need_funcs:
                # if _need_f != "formDefineUtilities":
                #     continue
                try:
                    ida_plugin_ana(ida_path, binary_path, script_path, _need_f, output_path)
                    if os.path.isfile(output_path):
                        with open(output_path, "r") as f:
                            decompiled_code = f.read()
                    # for i in range(3):
                    if f"{func}(" in decompiled_code or f"{func} (" in decompiled_code:
                        # if function calls candidate function, we think it is not
                        res_json = {"match":0}
                        continue
                    # (§2.7 structural short-circuit already handled in the per-getter
                    # pre-pass above; anything reaching here is a structure-miss -> LLM.)
                    if _need_f in urivendor_content[file_sha1]["func_res"]:
                        res_json = urivendor_content[file_sha1]["func_res"][_need_f]
                        print(f"fetching from vendor results: {func} {_need_f} {res_json}")
                    else:
                        llm_hits += 1
                        print(decompiled_code)
                        times = time.time()
                        # if _need_f in["sub_1D79C"]:
                        uri_result = prompt_uri_check(decompiled_code)

                        llm_check_time += time.time() - times
                        res_json = message_to_json(uri_result)
                        urivendor_content[file_sha1]["func_res"][_need_f] = res_json
                        print(f"res json {func} {_need_f} {res_json}")
                    if "match" in res_json and str(res_json["match"]) == "1":
                        # print(f"llm check {func} {res_json} {uri_result_json}")
                        # find a potential function
                        strs = res_json["strings"]
                        # print("strssssss",strs)
                        hasstr = 0
                        for sr in strs:
                            pattern = r'^\d+$'
                            if not bool(re.match(pattern, sr)):
                                hasstr = 1
                        if len(strs) == 0 or hasstr == 0:
                            urivendor_content[file_sha1]["func_res"][_need_f] = {"match": 0,"reason": "although llm matches, there is no custom uri strings", "strings":strs}
                            print("modify")
                            continue
                        if binpath not in uri_result_json:
                            uri_result_json[binpath] = {}
                        uri_result_json[binpath][func] = {}
                        # if "strings" in res_json:
                        uri_result_json[binpath][func]["urifunc"] = _need_f
                        uri_result_json[binpath][func]["uribinpath"] = binary_path
                        uri_result_json[binpath][func]["uristring"] = list(set(res_json["strings"]))
                        
                        # break
                except Exception as e:
                    print(e)

                if binpath in uri_result_json and func in uri_result_json[binpath]:
                    break
            if binpath in uri_result_json and func in uri_result_json[binpath]:
                break
    print(uri_result_json)
    # return uri_result_json

def check_parent_uri_with_dataarray(data_uris, devicename, need_inspect):
    global urivendor_content
    global llm_check_time
    global uri_result_json
    global structural_hits, llm_hits
    ida_path = settings.ida_path
    script_path = os.path.join(settings.script_path, "getDecompileCode.py")
    output_path = os.path.join(settings.result_path, devicename, "temp1.txt")

    for func in data_uris:
        binpath = need_inspect[func]["binary_path"]
        if binpath in uri_result_json and func in uri_result_json[binpath]:
            continue
        for _temp in data_uris[func]:
            
            inspectfunc = _temp["Urifunction"]
            binary_path = _temp["binary_path"]
            file_sha1 = calculate_file_sha1(binary_path)
            if file_sha1 not in urivendor_content:
                urivendor_content[file_sha1] = {}
                urivendor_content[file_sha1]["files"] = []
                urivendor_content[file_sha1]["func_res"] = {}
            urivendor_content[file_sha1]["files"].append(binary_path)
            token_array = ""
            for var in _temp["arraycontent"]:
                # to reduce token limit
                _lis = _temp["arraycontent"][var][:12]
                token_array += f"{var} = {_lis}"
            try:
                ida_plugin_ana(ida_path, binary_path, script_path, inspectfunc, output_path)
                if os.path.isfile(output_path):
                    with open(output_path, "r") as f:
                        decompiled_code = f.read()
                if f"{func}(" in decompiled_code or f"{func} (" in decompiled_code:
                    # if function calls candidate function
                    res_json = {"match":0}
                    continue
                # §2.7 unification: structural dispatch map first, LLM only on a miss.
                struct = (None if inspectfunc in urivendor_content[file_sha1]["func_res"]
                          else structural_uri_result(binary_path, inspectfunc))
                if inspectfunc in urivendor_content[file_sha1]["func_res"]:
                    res_json = urivendor_content[file_sha1]["func_res"][inspectfunc]
                    print(f"fetching from vendor results: {func} {inspectfunc} {res_json}")
                elif struct is not None:
                    structural_hits += 1
                    res_json = struct
                    urivendor_content[file_sha1]["func_res"][inspectfunc] = res_json
                    print(f"structural short-circuit: {func} {inspectfunc} {res_json}")
                else:
                    llm_hits += 1
                    print(f"{decompiled_code} \n {token_array}")
                    # for i in range(3):
                    times = time.time()
                    uri_result = prompt_uri_check(f"{token_array} \n {decompiled_code}")
                    llm_check_time += time.time() - times
                    with open(output_path, "w") as f:
                        f.write(f"{decompiled_code} \n {token_array}")
                    res_json = message_to_json(uri_result)
                    urivendor_content[file_sha1]["func_res"][inspectfunc] = res_json
                    print(f"res json  {func} {inspectfunc} {res_json}")
                if "match" in res_json and str(res_json["match"]) == "1":
                    # possible function
                    # llm false positive，delete [] strs
                    strs = res_json["strings"]
                    print("strssssss",strs)
                    hasstr = 0
                    for sr in strs:
                        pattern = r'^\d+$'
                        if not bool(re.match(pattern, sr)):
                            hasstr = 1
                    if len(strs) == 0 or hasstr == 0:
                        urivendor_content[file_sha1]["func_res"][inspectfunc] = {"match": 0,"reason": "although llm matches, there is no custom uri strings", "strings":strs}
                        # print("modify")
                        continue
                    if binpath not in uri_result_json:
                        uri_result_json[binpath] = {}
                    uri_result_json[binpath][func] = {}
                    uri_result_json[binpath][func]["urifunc"] = inspectfunc
                    uri_result_json[binpath][func]["uribinpath"] = binary_path
                    uri_result_json[binpath][func]["uristring"] = list(set(res_json["strings"]))
        
            except Exception as e:
                print(e)
            # if func in uri_result_json:
            #     break
            if binpath in uri_result_json and func in uri_result_json[binpath]:
                break
    # return uri_result_json   

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
        # with open(output_path, "r") as f:
        #     content = json.load(f)
            
        if result.returncode != 0:
            print(f"IDA Pro exited with error code {result.returncode}")
        else:
            print("IDA Python script executed successfully")
    except Exception as e:
        print(f"Error running IDA script: {e}")

def parse_result(stringcheck_results, possible_results):
    func_binary = {}
    with open(stringcheck_results, "r") as f:
        stringcheck_content = json.load(f)
    with open(possible_results, "r") as f:
        possible_content = json.load(f)
    for binary_path in stringcheck_content:
        for func in stringcheck_content[binary_path]:
            if stringcheck_content[binary_path][func] == {}:
                continue
            need_inspect = stringcheck_content[binary_path][func]["need"]
            
            if need_inspect  == 0:
                continue
            func_binary[func] = {}
            func_binary[func]["binary_path"] = binary_path
            func_binary[func]["call_count"] = possible_content[binary_path][func]["call_count"]
            
            is_export = possible_content[binary_path][func]["is_export"]
            if is_export == True:
                func_binary[func]["export_binary"] = possible_content[binary_path][func]["export_binary"]
    return func_binary

def get_caller_parent(func_binary, devicename):
    # find grandparent function
    data_uris = {}
    need_inspect = {}
    for func in func_binary:
        need_inspect[func] = {}
        need_inspect[func]["binary_path"] = func_binary[func]["binary_path"]
        binary_paths = []
        binary_paths.append(func_binary[func]["binary_path"])
        if "export_binary" in func_binary[func]:
            binary_paths.extend(func_binary[func]["export_binary"])
        need_inspect[func]["inspection"] = []
        for bin_path in binary_paths:
            # filter binary
            if ".so" in bin_path.lower() and  ("libc-" in bin_path.lower() or "libc.so" in bin_path.lower() or "pthread" in bin_path.lower() or "stdc" in bin_path.lower() or "gcc" in bin_path.lower() or "crypt" in bin_path.lower() or "sqlite" in bin_path.lower() or "ssl" in bin_path.lower() or "libcurl" in bin_path.lower() or "libxml" in bin_path.lower() or "smb" in bin_path.lower() or "libavcodec" in bin_path.lower() or "libavformat" in bin_path.lower() or "libz" in bin_path.lower() or "libevent" in bin_path.lower() or "libm" in bin_path.lower() or "libnsl" in bin_path.lower() or "ld-linux" in bin_path.lower() or "libstrongswan" in bin_path.lower() or "libxtables" in bin_path.lower() or "libexif" in bin_path.lower() or "libvorbis" in bin_path.lower() or "libpcre" in bin_path.lower() or "libupnp" in bin_path.lower() or "libexpat" in bin_path.lower() or "libid3tag" in bin_path.lower() or "libpam" in bin_path.lower() or "libdb" in bin_path.lower() or "liblzo2" in bin_path.lower() or "libjpeg" in bin_path.lower() or "libavahi" in bin_path.lower() or "libeap" in bin_path.lower() or "libneon" in bin_path.lower() or "libiconv" in bin_path.lower() or "flac" in bin_path.lower() or "libogg" in bin_path.lower() or "pctrl" in bin_path.lower() or "stlport" in bin_path.lower() or "libbcm_flashutil" in bin_path.lower() or "libnfnetlink" in bin_path.lower() or "libdl." in bin_path.lower() or "libqrencode" in bin_path.lower() or "libpng" in bin_path.lower() or "libjq." in bin_path.lower() or "libev." in bin_path.lower() or "libonig." in bin_path.lower() or "libebtc" in bin_path.lower() or "libws." in bin_path.lower() or "libdisk." in bin_path.lower() or "libresolv" in bin_path.lower() or "ncurses" in bin_path.lower() or "libical." in bin_path.lower() or "libext2fs" in bin_path.lower() or "libblobmsg_json" in bin_path.lower() or "libpanel" in bin_path.lower() or "libreadline" in bin_path.lower() or "libgobject" in bin_path.lower() or "libavutil" in bin_path.lower() or "libbcm" in bin_path.lower() or "libbluetooth" in bin_path.lower() or "libicalvcal" in bin_path.lower() or "libgio." in bin_path.lower() or "libglib." in bin_path.lower() or "libxt_" in bin_path.lower() or "libbcmmcast" in bin_path.lower() or "libfreeradius-" in bin_path.lower() or "ld-" in bin_path.lower() or "libthread_db" in bin_path.lower() or "libbfd-" in bin_path.lower() or "libgmp." in bin_path.lower() or "libldap" in bin_path.lower() or "liblber" in bin_path.lower() or "libusb" in bin_path.lower() or "libnetsnmpmibs" in bin_path.lower() or "libnetsnmpagent" in bin_path.lower() or "libnetsnmp" in bin_path.lower() or "libnetconf" in bin_path.lower() or "libnl" in bin_path.lower() or "libsafec" in bin_path.lower() or "libwebsockets" in bin_path.lower() or "libgio-" in bin_path.lower() or "libcli." in bin_path.lower() or "libopcodes" in bin_path.lower() or "libkrb5." in bin_path.lower() or "libpython" in bin_path.lower() or "libsmartcols." in bin_path.lower() or "libkadm5clnt_mit" in bin_path.lower() or "libkadm5srv_mit" in bin_path.lower() or "libevtlog" in bin_path.lower() or "libbz2" in bin_path.lower() or "libcmt" in bin_path.lower() or "libldns" in bin_path.lower() or "libsodium" in bin_path.lower() or "liblua" in bin_path.lower() or "libpcap" in bin_path.lower() or "libblkid" in bin_path.lower() or "libglib" in bin_path.lower() or "libperl" in bin_path.lower() or "libsudo_util" in bin_path.lower() or "sudoers" in bin_path.lower() or "libubox" in bin_path.lower() or "libiproute2" in bin_path.lower() or "libasound" in bin_path.lower() or "libfreetype" in bin_path.lower() or "libexosip2" in bin_path.lower() or "libpci" in bin_path.lower() or "libnss_nisplus" in bin_path.lower() or "libselinux" in bin_path.lower() or "libproc." in bin_path.lower() or "libsepol" in bin_path.lower() or "libip6t_frag" in bin_path.lower() or "libfuse" in bin_path.lower() or "libosip2" in bin_path.lower() or "libidn." in bin_path.lower() or "libacl." in bin_path.lower() or "libaudit" in bin_path.lower() or "libtinfo" in bin_path.lower() or "libdevmapper." in bin_path.lower() or "libauparse." in bin_path.lower() or "libacl." in bin_path.lower() or "libfl-" in bin_path.lower() or "libixml." in bin_path.lower() or "libthreadutil" in bin_path.lower() or "libintl-" in bin_path.lower() or "libgmp-" in bin_path.lower() or "libdcerpc-binding" in bin_path.lower() or "libtalloc." in bin_path.lower() or "libnetfilter_queue" in bin_path.lower() or "libcares." in bin_path.lower() or "libejdb." in bin_path.lower() or "libos." in bin_path.lower() or "libcms_core." in bin_path.lower() or "libcms_cli." in bin_path.lower() or "libcms_util." in bin_path.lower() or "libcms_boardctl." in bin_path.lower() or "libcms_dal." in bin_path.lower() or "libcms_core." in bin_path.lower() or "libcms_cli." in bin_path.lower() or "libbigballofmud." in bin_path.lower() or "libext2fs." in bin_path.lower() or "libusb-" in bin_path.lower() or "/lib/xtables/" in bin_path.lower()):
                continue
            if ".so" in bin_path.lower() and ("libwbclient" in bin_path.lower() or "libndr." in bin_path.lower() or "libldb." in bin_path.lower() or "libtdb." in bin_path.lower() or "libswscale" in bin_path.lower() or "libhiredis" in bin_path.lower() or "libuclibc" in bin_path.lower() or "libplist." in bin_path.lower() or "libunistring." in bin_path.lower() or "libyaml." in bin_path.lower() or "libantlr3c" in bin_path.lower() or "libelf-" in bin_path.lower() or "libedit." in bin_path.lower() or "libscapi." in bin_path.lower() or "libiperf." in bin_path.lower() or "libubus." in bin_path.lower() or "libnettle." in bin_path.lower() or "libhogweed." in bin_path.lower() or "libbpf." in bin_path.lower() or "libatalk." in bin_path.lower() or "/ld.so" in bin_path.lower() or "liblz4." in bin_path.lower() or "libgssapi_krb5." in bin_path.lower()):
                continue
            # filter bianry
            if "openssl" in bin_path.lower() or "racoon" in bin_path.lower() or "racoonctl" in bin_path.lower() or "ipsec" in bin_path.lower() or "setkey" in bin_path.lower() or "iptables" in bin_path.lower() or "busybox" in bin_path.lower() or "sqlite" in bin_path.lower() or "flash_erase" in bin_path.lower() or "wget" in bin_path.lower() or "openvpn" in bin_path.lower() or "smbd" in bin_path.lower() or "dnsmasq" in bin_path.lower() or "curl" in bin_path.lower() or "odhcp6c" in bin_path.lower()or "wpa_cli" in bin_path.lower()or "hostapd" in bin_path.lower() or "udhcpd" in bin_path.lower()or "inadyn" in bin_path.lower()or "dropbear" in bin_path.lower()or "zebra" in bin_path.lower() or "quagga" in bin_path.lower() or "ebtables" in bin_path.lower() or "iptables" in bin_path.lower() or "ppp" in bin_path.lower() or "nmbd" in bin_path.lower() or "netstat" in bin_path.lower() or "ripd" in bin_path.lower() or "acme" in bin_path.lower() or "booster" in bin_path.lower() or "comgt"in bin_path.lower() or "ntfs" in bin_path.lower() or "/rc" in bin_path.lower() or "mtd" in bin_path.lower() or "uqmi" in bin_path.lower() or "qmi" in bin_path.lower() or "l2tp" in bin_path.lower() or "daapd" in bin_path.lower() or "lldpd" in bin_path.lower() or "lldpcli" in bin_path.lower() or "lldpctl" in bin_path.lower()  or "/wl" in bin_path.lower() or "/tc" in bin_path.lower() or "acsd" in bin_path.lower() or "charon" in bin_path.lower() or "pluto" in bin_path.lower() or "swanctl" in bin_path.lower() or "conntrack" in bin_path.lower() or "udev" in bin_path.lower() or "dropbear" in bin_path.lower() or "tcpdump" in bin_path.lower() or "pptp" in bin_path.lower() or "dhcrelay" in bin_path.lower() or "pppd" in bin_path.lower() or "ip6tables" in bin_path.lower() or "tr069" in bin_path.lower() or "udpxy" in bin_path.lower() or "dhcp6" in bin_path.lower() or "ez-ipupdate" in bin_path.lower() or "wpa_supplicant" in bin_path.lower() or "lsof" in bin_path.lower() or "lpr" in bin_path.lower() or "/lpd" in bin_path.lower() or "afpd" in bin_path.lower() or "udpxy" in bin_path.lower() or "fsck" in bin_path.lower() or "vsftpd" in bin_path.lower() or "uniconv" in bin_path.lower() or "sdparm" in bin_path.lower() or "/sbd" in bin_path.lower() or "/dbd" in bin_path.lower() or "samba" in bin_path.lower() or "avahi-daemon" in bin_path.lower() or "igmpproxy" in bin_path.lower() or "dropbox" in bin_path.lower() or "minidlna" in bin_path.lower() or "test" in bin_path.lower() or "stubby" in bin_path.lower() or "ipset" in bin_path.lower() or "jitterentropy" in bin_path.lower() or bin_path.endswith("/ip") or "nanddump" in bin_path.lower() or "traceroute" in bin_path.lower() or "ookla" in bin_path.lower() or "iperf3" in bin_path.lower() or "flashcp" in bin_path.lower() or "ubinfo" in bin_path.lower() or "brctl" in bin_path.lower() or "ntpclient" in bin_path.lower() or "radvd" in bin_path.lower() or "dhcrelay" in bin_path.lower() or "hotplug" in bin_path.lower() or "ethtool" in bin_path.lower() or "rdisc6" in bin_path.lower()or "phddns" in bin_path.lower() or "chilli" in bin_path.lower() or "mke2fs" in bin_path.lower() or "/jq" in bin_path.lower() or "/mmc" in bin_path.lower() or "ubimkvol" in bin_path.lower() or "ubirmvol" in bin_path.lower() or "ubirename" in bin_path.lower() or "ubiattach" in bin_path.lower() or "ubidetach" in bin_path.lower() or "snooper" in bin_path.lower() or "dbus-daemon" in bin_path.lower() or "tdts_rule_agent" in bin_path.lower() or "eventd" in bin_path.lower() or "mkfatfs" in bin_path.lower() or "wsdd2" in bin_path.lower() or "socat" in bin_path.lower() or "mkfs.ubifs" in bin_path.lower() or "usb_modeswitch" in bin_path.lower() or "idevicedebugserverproxy" in bin_path.lower() or "hcidump" in bin_path.lower() or "idevice" in bin_path.lower() or "hcitool" in bin_path.lower() or "bluetoothd" in bin_path.lower() or "iproxy" in bin_path.lower() or "l2ping" in bin_path.lower() or "btmgmt" in bin_path.lower() or "plistutil" in bin_path.lower() or "usbmuxd" in bin_path.lower() or "bccmd" in bin_path.lower() or "sdptool" in bin_path.lower() or "bluetoothctl" in bin_path.lower() or "vlanctl" in bin_path.lower() or "nandwrite" in bin_path.lower() or "newfs_hfs" in bin_path.lower() or "rmmod" in bin_path.lower() or "modprobe" in bin_path.lower() or "syslogd" in bin_path.lower() or "snmpwalk" in bin_path.lower() or "snmptrap" in bin_path.lower() or "named" in bin_path.lower() or "depmod" in bin_path.lower() or "snmpd" in bin_path.lower() or "dhclient" in bin_path.lower() or "mdnsd" in bin_path.lower() or "dhcpd" in bin_path.lower() or "ldapsearch" in bin_path.lower() or "mkfs.jffs2" in bin_path.lower() or "webBoot" in bin_path.lower() or "stunnel" in bin_path.lower() or "confd" in bin_path.lower() or "mail" in bin_path.lower() or "nameif" in bin_path.lower() or "/arp" in bin_path.lower() or "rtmon" in bin_path.lower() or "msmtp" in bin_path.lower() or "/sar" in bin_path.lower() or "nginx" in bin_path.lower() or "syslog-ng" in bin_path.lower() or "/tftpd" in bin_path.lower() or "/cron" in bin_path.lower() or "/zic" in bin_path.lower() or "bonjour" in bin_path.lower() or "netifd" in bin_path.lower() or "procd" in bin_path.lower() or "ldconfig" in bin_path.lower() or "fdisk" in bin_path.lower() or "uwsgi" in bin_path.lower() or "unix_chkpwd" in bin_path.lower() or "kdb5_util" in bin_path.lower() or "smcroute" in bin_path.lower() or "mkswap" in bin_path.lower() or "ubirsvol" in bin_path.lower() or "ubiformat" in bin_path.lower() or "mcproxy" in bin_path.lower() or "pam_tally2" in bin_path.lower() or "ubiupdatevol" in bin_path.lower() or "plainrsa-gen" in bin_path.lower() or "pam_tally" in bin_path.lower() or "blkid" in bin_path.lower() or "hping3" in bin_path.lower() or "/slapd" in bin_path.lower() or "/visudo" in bin_path.lower() or "s/trace" in bin_path.lower() or "mcsender" in bin_path.lower() or "ld.bfd" in bin_path.lower() or "/casa" in bin_path.lower() or "/h/ostip" in bin_path.lower() or "/ktutil" in bin_path.lower() or "/mutt" in bin_path.lower() or "objcopy" in bin_path.lower() or "/iperf" in bin_path.lower() or "/nm" in bin_path.lower() or "/whereis" in bin_path.lower() or "/ar" in bin_path.lower() or "smidump" in bin_path.lower() or "/ranlib" in bin_path.lower() or "/addr2line" in bin_path.lower() or "/cmm" in bin_path.lower() or "/readelf" in bin_path.lower() or "/sadf" in bin_path.lower() or "/vtysh" in bin_path.lower() or "/strip" in bin_path.lower() or "mpstat" in bin_path.lower() or bin_path.endswith("/as") or "/objdump" in bin_path.lower() or "/lib/python2.7" in bin_path.lower() or "/sadc" in bin_path.lower() or "/opkg" in bin_path.lower() or "/strings" in bin_path.lower() or "pam_krb5" in bin_path.lower() or "utelnetd" in bin_path.lower() or "/mDNSResponderPosix" in bin_path.lower() :
                continue
            if  "iwconfig" in bin_path.lower() or "/logic" in bin_path.lower() or "/nbns" in bin_path.lower() or "strace" in bin_path.lower() or "mkfs.ext2" in bin_path.lower() or "tune2fs" in bin_path.lower() or "mkdosfs" in bin_path.lower() or "/ftpd" in bin_path.lower() or "telnetd" in bin_path.lower() or "/lib/lua/" in bin_path.lower() or "setpci" in bin_path.lower() or "/lspci" in bin_path.lower() or "iwlist" in bin_path.lower() or "/ping" in bin_path.lower() or "/msntp" in bin_path.lower() or "/wput" in bin_path.lower() or "gdbserver" in bin_path.lower() or bin_path.endswith("/dcp") or "shutdown" in bin_path.lower() or "agetty" in bin_path.lower() or "iscsid" in bin_path.lower() or "/init" in bin_path.lower() or "xinetd" in bin_path.lower() or "onvifserver" in bin_path.lower() or "iscsiadm" in bin_path.lower() or "lldptool" in bin_path.lower() or bin_path.endswith("/ftp") or bin_path.endswith("/lum") or "dircolors" in bin_path.lower() or "/lldpad" in bin_path.lower() or "/wavplay" in bin_path.lower() or "xtables-multi" in bin_path.lower() or "/rtspd" in bin_path.lower() or "/sysconf" in bin_path.lower() or bin_path.endswith("/fwd") or bin_path.endswith("/dnrd") or bin_path.endswith("/noip2") or bin_path.endswith("/ncc") or bin_path.endswith("/ds") or bin_path.endswith("/mlabel") or bin_path.endswith("/disktype") or bin_path.endswith("/routed") or "mDNSResponder" in bin_path.lower() or "mod_status" in bin_path.lower() or "/unzip" in bin_path.lower() or "/bftpd" in bin_path.lower() or bin_path.endswith("/zip") or "/zipsplit" in bin_path.lower() or bin_path.endswith("/pot") or "zipcloak" in bin_path.lower() or "zipnote" in bin_path.lower() or "/bzip2" in bin_path.lower() or "/vmstat" in bin_path.lower() :
                continue
            if "/hdparm" in bin_path.lower() or "/picocom" in bin_path.lower() or "mkfs.xfs" in bin_path.lower() or "/xfs_growfs" in bin_path.lower() or "/xfs_repair" in bin_path.lower() or "/xfs_db" in bin_path.lower() or "/aperture" in bin_path.lower() or "/parted" in bin_path.lower() or "/p0f" in bin_path.lower() or "/ssmtp" in bin_path.lower() or bin_path.endswith("/bc") or bin_path.endswith("/lbd") or bin_path.endswith("/ssdk_sh") or "proftpd" in bin_path.lower() or "/vol_id" in bin_path.lower() or bin_path.endswith("/atd") or "avahi-autoipd" in bin_path.lower() or "logrotate" in bin_path.lower() or "transmission-daemon" in bin_path.lower() or bin_path.endswith("/at") or "redis-cli" in bin_path.lower() or "transmission-remote" in bin_path.lower() or bin_path.endswith("/tar") or "amulecmd" in bin_path.lower() or "/amuled" in bin_path.lower() or "/redis-server" in bin_path.lower() or "/netdrive" in bin_path.lower() or bin_path.endswith("/iw") or "/netctrl" in bin_path.lower() or "/lzma" in bin_path.lower() or bin_path.endswith("/fw3") or bin_path.endswith("/bridge") or "/openlldp" in bin_path.lower() or "/halt" in bin_path.lower() or bin_path.endswith("/watchdog") or "/mosquitto" in bin_path.lower() or bin_path.endswith("/lsusb") or bin_path.endswith("/uci2dat") or "partprobe" in bin_path.lower() or "mkfs.fat" in bin_path.lower() or "/cwmpClient" in bin_path.lower() or bin_path.endswith("/rpcd") or bin_path.endswith("/ubusd") or bin_path.endswith("/iwinfo") or "/endpoint" in bin_path.lower() or bin_path.endswith("/mycli") or "/tftp-hpa" in bin_path.lower() or "/usr/luajit/" in bin_path.lower() or "/uptime" in bin_path.lower() or "/ushare" in bin_path.lower() or "smbcontrol" in bin_path.lower() or "smbpasswd" in bin_path.lower() or "/gctwimax" in bin_path.lower() or "/madwimax" in bin_path.lower():
                continue
            if "/sysstate" in bin_path.lower() or bin_path.endswith("/pki") or "/mkfs.ubifs" in bin_path.lower() or "/mcpd" in bin_path.lower() or "/hspotap" in bin_path.lower() or "/vlanctl" in bin_path.lower() or "/ceventc" in bin_path.lower() or "/ubirsvol" in bin_path.lower() or "/ubiformat" in bin_path.lower() or "/ubiupdatevol" in bin_path.lower() or "/ubiblock" in bin_path.lower() or "/ceventd" in bin_path.lower() or "/nandwrite" in bin_path.lower() or bin_path.endswith("/eapd") or bin_path.endswith("/bpmctl") or bin_path.endswith("/email") or bin_path.endswith("/socat") or bin_path.endswith("/bsd") or bin_path.endswith("/dhd") or bin_path.endswith("/dhdctl") or bin_path.endswith("/route") or bin_path.endswith("/linuxrc") or bin_path.endswith("/ecmh") or bin_path.endswith("/mwcli") or bin_path.endswith("/top") or "/mdnsresponder" in bin_path.lower() or "/wps_pbcd" in bin_path.lower():
                continue
            res = {}
            res["binary_path"] = bin_path
            res["need_funcs"] = set()
            # get upper funciton
            ida_path = settings.ida_path
            ida_script = os.path.join(settings.script_path, "get_caller.py")
            output_path = os.path.join(settings.result_path, devicename, "caller.json")
            
            print(f"processing {func} {bin_path} {output_path}")
            ida_plugin_ana(ida_path, bin_path, ida_script, func, output_path)
            if os.path.isfile(output_path):
                with open(output_path, "r") as f:
                    content = json.load(f)
                if "URIDATA" in content:
                    for _temp in content["URIDATA"]:
                        if "isUriDispatch" in _temp and len(_temp["UriStrings"]) > 0:
                    # res["isUriDispatch"] = 1
                    # res["UriStrings"] = content["UriStrings"]
                            if func not in data_uris:
                                data_uris[func] = []
                            tempjson = {}
                            tempjson["binary_path"] = bin_path
                            tempjson["UriStrings"] = _temp["UriStrings"]
                            tempjson["Urifunction"] = _temp["urifunction"]["funcname"]
                            tempjson["arraycontent"] = _temp["urifunction"]["arraycontent"]
                            data_uris[func].append(tempjson)
                    
                for _f in content:
                    if _f != "URIDATA":
                        res["need_funcs"] |= set(content[_f])
            res["need_funcs"] = list(res["need_funcs"])
            # print(f"res {res}")
            need_inspect[func]["inspection"].append(res)
            # print(f"nnedd inspecttion {need_inspect}")
    return data_uris, need_inspect
    
    
def main():
    devicename = sys.argv[1]
    possible_results = os.path.join(settings.result_path, devicename, "final_possible.json")
    stringcheck_results = os.path.join(settings.result_path, devicename, "string_check_result.json")
    need_inspect_path = os.path.join(settings.result_path, devicename, "uri_need_inspect.json")
    uri_check_result_path = os.path.join(settings.result_path, devicename, "uricheck_result.json")
    global uri_result_json 
    start_time = time.time()
    # func_binary = parse_result(llm_results)
    func_binary = parse_result(stringcheck_results,possible_results)
    # print(func_binary)
    need_inspect = {}
    data_uri_strings = {}
    global urivendor_content
    data_uri_strings, need_inspect = get_caller_parent(func_binary, devicename)
    # print(f" need inspect {need_inspect}")
    # print(f"data uri {data_uri_strings}")
    with open(need_inspect_path, "w") as f:
        json.dump(need_inspect, f, indent=4, ensure_ascii=False)
    # with open(need_inspect_path, "r") as f:
    #     need_inspect = json.load(f)'
    urivendor_path = settings.vendor_uri_func_result
    if not Path(urivendor_path).exists():
        data = {}
        with Path(urivendor_path).open('w') as f:
            json.dump(data, f, indent=4)
    
    with open(urivendor_path,"r") as f:
        urivendor_content = json.load(f)
    if data_uri_strings:
        # uri in data array
        check_parent_uri_with_dataarray(data_uri_strings, devicename, need_inspect)
    for binpath in uri_result_json:
        for func in uri_result_json[binpath]:
            if func in need_inspect:
                del need_inspect[func]
    # LLM functionality check
    check_parent_uri(need_inspect, devicename)
    with open(uri_check_result_path, "w") as f:
        json.dump(uri_result_json, f, indent=4, ensure_ascii=False)

    with open(urivendor_path, "w") as f:
        json.dump(urivendor_content, f, indent=4, ensure_ascii=False)
    total_cost_time = time.time()-start_time
    total_checks = structural_hits + llm_hits
    frac = (structural_hits / total_checks * 100) if total_checks else 0.0
    print(f"total cost {total_cost_time} llm check time {llm_check_time}")
    print(f"[§2.7 reuse] URI-dispatch checks: {total_checks}  "
          f"structural short-circuit: {structural_hits} ({frac:.0f}%)  LLM: {llm_hits}")
    
if __name__ == "__main__":
    main()
    
