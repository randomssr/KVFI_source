import sys
import json
import os
import hashlib
from check_binary_file import *
from config import settings
# analyze the binaries in a directory, and record all string arguments of call sites.

def calculate_file_hash(file_path, hash_algorithm='sha256'):
    """
    calculate the hash of file content.
    """
    # create hash object
    hash_func = hashlib.new(hash_algorithm)
    
    # process file content
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hash_func.update(chunk)
    
    # return hex representation
    return hash_func.hexdigest()

def callsite_ida_plugin_ana(ida_path, bin_path, ida_script, output_path):
    try:
        # Command to run IDA Pro with the specified script
        command = [ida_path, '-A', f'-S{ida_script} {output_path}', bin_path]
       
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


def main():
    dir_path = sys.argv[1]
    devicename = sys.argv[2]
    # python_script = sys.argv[2]
    python_script = os.path.join(settings.script_path, "callsite_string.py")
    temp_output_path = os.path.join(settings.result_path, devicename, "output.json")
    final_output_path = os.path.join(settings.result_path, devicename, "final_call_output.json")
    binary_files = find_binary_files(dir_path)
    finalfunc = {}
    hash_set = set()
    for binary_file in binary_files:
        # start analyze each binary file
        _hash = calculate_file_hash(binary_file)
        if _hash not in hash_set:
            hash_set.add(_hash)
        else:
            continue
        if os.path.isfile(temp_output_path): 
            os.remove(temp_output_path)
        binary_file = str(binary_file)

        ida_path = settings.ida_path
        callsite_ida_plugin_ana(ida_path, binary_file, python_script, temp_output_path)
        # process the return value
        if os.path.isfile(temp_output_path): 
            with open(temp_output_path, "r") as f:
                content = json.load(f)
                finalfunc[binary_file] = content
        else:
            print(f"no output when handling {binary_file}")
        # os.remove(temp_output_path)
    # save total results
    with open(final_output_path, "w") as f:
        json.dump(finalfunc, f, indent=4, ensure_ascii=False)

if __name__ == "__main__":
    main()
    