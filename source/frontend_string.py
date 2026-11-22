# select keywords from frontend files and configurations
# refer to Mango
from pathlib import Path
from bs4 import BeautifulSoup
from typing import Set, Union
import esprima
import re
import string
import json
import os
import sys
import configparser
import copy
from config import settings


php_suffix = {".php", ".cgi"}
js_suffix = {".js"}
html_suffix = {".htm", ".html", ".asp"}
xml_suffix = {".xml"}
cfg_suffix = {".cfg",".config",".conf",".cnf"}

all_suffix = (php_suffix | js_suffix | html_suffix | xml_suffix | cfg_suffix)
AVOID_KEYWORDS = {"from","global","filter","UNIX","unix","default","SMTP","UTF-8","utf-8","action","getTime","show","port","method","access","other","html","length","unknow","no","yes","error","properties","path","unused","unknown","data","true", "false", "static", "radio", "none", "disabled", "fixed","custom","version","name","addr","download","asus","http","https","confirm","mjpeg","MJPEG","right","center","left","string","top" }
MIN_STRING_LENGTH = 3
cfg_strs = set()

def is_php(filename: Path) -> bool:
    try:
        with filename.open("r") as f:
            for line in f.readlines():
                line = line.strip()
                if not line:
                    continue
                # print(f"line {line} {filename}")
                if line.startswith("<?"):
                    return True
                else:
                    return False
    except Exception as f:
        
        return False
    return False

def get_strings_from_html(path: Path, parser=None):
    try:
        soup = BeautifulSoup(path.read_text(), parser or "html.parser")
    except (UnicodeDecodeError, FileNotFoundError) as e:
        print(f"{path} no results")
        return set()    
    value_strings = set()
    
    for input_tag in soup.find_all("input"):
       
        name = input_tag.get("name")
        if name:
            value_strings.add(name)
        _id = input_tag.get("id")
        if _id:
            value_strings.add(_id)
    for input_tag in soup.find_all("INPUT"):
    #    <INPUT type="password" size=18 maxlength=8 id="NewPassword" value="">
        name = input_tag.get("name")
        if name:
            value_strings.add(name)
        _id = input_tag.get("id")
        if _id:
            value_strings.add(_id)    
    for select_tag in soup.find_all("select"):
        name = select_tag.get("name")
        if name:
            value_strings.add(name)
        _id = select_tag.get("id")
        if _id:
            value_strings.add(_id)    
    # print(value_strings)   
    for script_tag in soup.find_all("script"):
        if script_tag.string:
            value_strings |= get_strings_from_javascript(script_tag.string)
            # if "twitter" in str(path):
            #     print(path, get_strings_from_javascript(script_tag.string))
    return value_strings

def strip_non_alpha(s) -> str:
    s = s.split("=")[0]
    # s = s.split(":")[0]
    # s = s.split(";")[0]
    stripped = re.sub(r"^[^a-zA-Z]+|[^a-zA-Z0-9]+$", "", s)
    if any(x in stripped for x in string.whitespace):
        return ""
    left = stripped.find("<")
    if left != -1:
        stripped = stripped[left + 1 :]

    right = stripped.rfind(">")
    if right != -1:
        stripped = stripped[:right]
    backslash = stripped.find("\\")
    if backslash != -1:
        stripped = stripped[:backslash]
    question = stripped.find("?")
    if question != -1 and question != len(stripped) - 1:
        stripped = stripped[question + 1 :]
    return stripped

def get_strings_from_javascript(file: Union[Path, str]):
    # print("ssddddd")
    valid_strings = set()
    pattern = re.compile(r'property:\s*{[^}]*name:\s*"([^"]*)"[^}]*}', re.DOTALL)
    '''
        file document.write(help_show_hide) tokens [{
            type: "Identifier",
            value: "document"
        }, {
            type: "Punctuator",
            value: "."
        }, {
            type: "Identifier",
            value: "write"
        }, {
            type: "Punctuator",
            value: "("
        }, {
            type: "Identifier",
            value: "help_show_hide"
        }, {
            type: "Punctuator",
            value: ")"
        }] script {
            type: "Program",
            sourceType: "script",
            body: [
                {
                    type: "ExpressionStatement",
                    expression: {
                        type: "CallExpression",
                        callee: {
                            type: "MemberExpression",
                            computed: False,
                            object: {
                                type: "Identifier",
                                name: "document"
                            },
                            property: {
                                type: "Identifier",
                                name: "write"
                            }
                        },
                        arguments: [
                            {
                                type: "Identifier",
                                name: "help_show_hide"
                            }
                        ]
                    }
                }
            ]
        }
    '''
    try:
        if isinstance(file, str):
            tokens = esprima.tokenize(file)
            script = esprima.parse(file)
        else:
            tokens = esprima.tokenize(file.read_text())
            script = esprima.parse(file.read_text())
        
        for match in re.finditer(pattern, str(script)):
            # print(f" {match.group(0)}, {match.group(1)}, {match.start()}")
            stripped = strip_non_alpha(match.group(1))
            # print(f"1 {stripped}")
            if len(stripped) > MIN_STRING_LENGTH:
                valid_strings.add(stripped)
        # for obj_string in pattern.findall(str(script)):
        #     stripped = strip_non_alpha(obj_string)
        #     print(f"1 {stripped}")
        #     if len(stripped) > MIN_STRING_LENGTH:
        #         valid_strings.add(stripped)
        for token in tokens:
            if token.type == "String":
                stripped = strip_non_alpha(token.value)
                # print(f"2 {stripped} {token}")
                if len(stripped) > MIN_STRING_LENGTH:
                    valid_strings.add(stripped)
    except (esprima.error_handler.Error, UnicodeDecodeError, FileNotFoundError) as e:
        pass
    try:
        if isinstance(file, str):
            content = file
        else:
            content = file.read_text()
        
        for obj_string in pattern.findall(content):
            stripped = strip_non_alpha(obj_string)
            # print(f"3before {stripped}")
            if len(stripped) > MIN_STRING_LENGTH:
                valid_strings.add(stripped)
        # pattern2 = re.compile(r'prop\s*:\s*"([^"]+)"', re.DOTALL)
        # # {attrs:{prop:"hostMacAddress",label:e.$sakura.locale.neighbor.card.table.mac_address}}),e._v(" "),a("el-table-column",
        # for _str in pattern2.findall(content):
        #     stripped = strip_non_alpha(_str)
        #     # print(f"4 before  {stripped}")
        #     if len(stripped) > MIN_STRING_LENGTH:
        #         valid_strings.add(stripped)
        pattern = r'prop\s*:\s*"([^"]+)"'
        for match in re.finditer(pattern, content):
            stripped = strip_non_alpha(match.group(1))
            # print(f"4 before  {stripped}")
            if len(stripped) > MIN_STRING_LENGTH:
                valid_strings.add(stripped)
        

        newvalid = copy.deepcopy(valid_strings)
        for str1 in newvalid:
            if f".{str1}(" in content or f":{str1}()" in content or f": '{str1}'" in content or f'="{str1}"' in content or f'= "{str1}"' in content:
                # print(f"delete {str1}")
                valid_strings.remove(str1)
        
            # re expression
            pattern = rf'cfg_[a-zA-Z0-9_]+\("{re.escape(str1)}"\)'
            pattern1 = rf'config_[a-zA-Z0-9_]+\("{re.escape(str1)}"\)'
            if f'cfg_get("{str1}")' in content or f'config_get("{str1}")' in content or re.findall(pattern, content) or re.findall(pattern1, content):
                cfg_strs.add(str1)
                valid_strings.remove(str1)
                # print(f"cfg jas  {str1}")
            # filter var USER_CFG = "USER_CFG" var LAN_WLAN = "LAN_WLAN"
            pattern = rf'\b{re.escape(str1)}\b'
            count_banana = len(re.findall(pattern, content))
            if f'var {str1} = "{str1}"' in content and count_banana == 2 and str1 in valid_strings:
                valid_strings.remove(str1)
                # print(f" remove {str1} ")
            # filter "header": "Add A New Device Help"
            if str1 in valid_strings and f'"{str1}": ' in content and content.count(f'"{str1}"') == 1:
                valid_strings.remove(str1)
            if str1 in valid_strings and f'document.{str1}' in content:
                valid_strings.remove(str1)
            if "reject" == str1.lower() and str1 in valid_strings:
                # print(str1)
                valid_strings.remove(str1)
            
            if str1 == "frames" and content.count(".frames[") == count_banana and str1 in valid_strings:
                # print( content.count(".frames["),  content.count("frames"))        
                valid_strings.remove(str1)
        pattern = r'(cfg_[a-zA-Z0-9_]+)\("([^"]+)"\)'
        matches = re.findall(pattern, content)
        for i in matches:
            cfg_strs.add(i[1])
        pattern = r'(config_[a-zA-Z0-9_]+)\("([^"]+)"\)'
        matches = re.findall(pattern, content)
        for i in matches:
            cfg_strs.add(i[1])  
        
    except (UnicodeDecodeError, FileNotFoundError) as e:
        print(e)
        
    return valid_strings

def get_strings_from_xml(file_path: Path):
    try:
        soup = BeautifulSoup(file_path.read_text(encoding="unicode_escape"), "lxml-xml")
        tag_names = {tag.name for tag in soup.find_all(True)}
        name_elements = {tag.text for tag in soup.find_all("name")}
        return name_elements
        # return tag_names
    except (UnicodeDecodeError, FileNotFoundError) as e:
        pass
    return set()

def get_strings_from_php(file_path: Path):
    valid_strings = get_strings_from_html(file_path, parser="lxml")
    try:
    # print(f"item {file_path} valid strings {valid_strings}")
    
        matches = re.findall(
            """\$_(?:GET|POST|SERVER)\[(?:"|')(.*)(?:"|')\]""", file_path.read_text()
        )
        valid_strings |= set(matches)
        if file_path.suffix == ".cgi":
            # BeaconInterval=%%BeaconInterval();%%
            # print(f"ddddddd {file_path}")
            pattern = r'(\w+)=%%\1\(\);%%'
            matchall = re.findall(pattern, file_path.read_text())
            valid_strings |= set(matchall)
    except UnicodeDecodeError:
        pass
    return valid_strings

def get_strings_from_cfg(file_path: Path):
    cfg_keys= set()
    try:
        with open(str(file_path), "r") as f:
            content = f.readlines()
        
        for line in content:
            # print(line)
            line = line.strip()
            if "=" in line and not line.startswith("#") and line.count("=") == 1:
                cfg_keys.add(line.split("=")[0].strip())
                # for _part in line.split(" "):
                #     if "=" in _part and _part.count("=") == 1:
                #         print(_part.split("=")[0].strip())
                #         cfg_keys.add(_part.split("=")[0].strip())
            elif '=' in line and not line.startswith("#") and line.count('=') > 1 and '&' in line:
                # ID="VID=4088&ENABLED=YES&DIR=1&CPU=1&MEMBER=256
                parts = line.split("&")
                for part in parts:
                    if '=' in part and part.count('=') == 1:
                        cfg_keys.add(part.split("=")[0].strip('\'"').strip())
                    elif '=' in part and part.count('=') > 1:
                        cfg_keys.add(part.split("=")[-2].strip('\'"').strip())
            elif '=' in line and not line.startswith("#") and line.count('=') > 1: 
                # Channel="0" BeaconPeriod="100" RTSThreshold="2347" FragThreshold="2346"
                parts = line.split()
                for part in parts:
                    if '=' in part and part.count('=') == 1:
                        cfg_keys.add(part.split("=")[0].strip('\'"').strip())
            # "logoff": "ok",
            # "Login": true
            elif ":" in line and line.count(":") == 1:
                cfg_keys.add(line.split(":")[0].strip('\'"').strip())
            
        # another mode
        # config interface 'wan1'
            # option ifname 'eth2'
            # option proto 'dhcp'
            # can be wan1.ifname or config.wan1.ifname
        with open(str(file_path), "r") as f:
            contentstr = f.read()
        if "config" in contentstr and "option" in contentstr and contentstr.count("option") > contentstr.count("config"):
            configstr = ""
            for line in content:
                line = line.strip()
                if line.startswith("config") and len(line.split()) == 3:
                    eles = line.split()
                    ele1 = eles[1].strip()
                    ele2 = eles[2].strip("'").strip('"').strip()
                    
                    configstr = f"{ele1}.{ele2}"
                if line.startswith("option"):
                    eles = line.split()
                    if len(eles) == 3:
                        ele1 = eles[1].strip()
                        cfg_keys.add(ele1)
                        filename = file_path.stem # aa.txt get aa
                        if configstr != "":
                            cfg_keys.add(f"{configstr}.{ele1}")
                            cfg_keys.add(f"{filename}.{ele2}.{ele1}")
                            
    except (UnicodeDecodeError) as e:
        print(e)
    return cfg_keys

def find_frontend_string(root_dir):
    # find frontend keywords
    string_dict = {}
    p = Path(root_dir)
    cfg_string_dict = {}
    
    for item in p.rglob('*'):
        # print(f"html file is {item.suffix}")
        # if "login.htm" not in str(item):
        #     continue
        if item.is_dir():
            continue
        
        valid_strings = set()
        if item.suffix in html_suffix:
            # print(f"html file is {item}")
            valid_strings |= get_strings_from_html(item)
        
        elif item.suffix in js_suffix:
            # print(f'js item {item}')
            valid_strings |= get_strings_from_javascript(item)
        
        elif item.suffix in php_suffix:
            # print(item)
            if is_php(item) or item.suffix == ".cgi":
                valid_strings |= get_strings_from_php(item) 
       
        elif item.suffix in xml_suffix:
            # print(f'xml item {item}')
            valid_strings != get_strings_from_xml(item)
        
        elif item.suffix in cfg_suffix:
            strs = get_strings_from_cfg(item)
            for s in strs:
                if s not in cfg_string_dict:
                    cfg_string_dict[s] = []
                cfg_string_dict[s].append(item.name)
        else:
            pass
        for s in cfg_strs:
            if s not in cfg_string_dict:
                cfg_string_dict[s] = []
            
        for s in valid_strings:
            if Path(s).suffix in all_suffix:
                continue
            if s.startswith("text/"):
                continue
            if "content-type" in s.lower():
                continue
            if "if-" in s.lower():
                continue
            if "application/" in s.lower():
                continue
            if s.lower() in AVOID_KEYWORDS:
                continue
            if s not in string_dict:
                string_dict[s] = []
            string_dict[s].append(item.name)
    return string_dict, cfg_string_dict
    
if __name__ == "__main__":
    # root_dir = "netgearR6200squashfs-root"
    root_dir = sys.argv[1]
    devicename = sys.argv[2]
    string_results, cfg_results = find_frontend_string(root_dir)
    keyword_dir = os.path.join(settings.result_path, devicename, "keywords.json")
    cfgkeyword_dir = os.path.join(settings.result_path, devicename, "cfgkeywords.json")
    
    with open(keyword_dir, "w") as f:
        json.dump(string_results, f, indent=4, ensure_ascii=False)
    with open(cfgkeyword_dir, "w") as f:
        json.dump(cfg_results, f, indent=4, ensure_ascii=False)
    