import os
import sys
import json
from config import settings

def main():
    devicename = sys.argv[1]
    final_call_output = os.path.join(settings.result_path, devicename, "final_call_output.json")
    final_possible = os.path.join(settings.result_path, devicename, "final_possible.json")
    with open(final_call_output, "r") as f:
        call_content = json.load(f)
    with open(final_possible, "r") as f:
        possible_content = json.load(f)
    for binary_path in possible_content:
        decompile_error = call_content[binary_path]['decompile_error']
        insect = set(decompile_error) & set(possible_content[binary_path].keys())
        if insect :
            print(f"decompile error in {binary_path} , need manually construct i64!")


if __name__ == "__main__":
    main()