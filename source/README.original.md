# KVFI

## Detailed Steps

* set the path in "setting.toml"
`vendor_func_result` records the input-processing functionality checking results using the lightweight LLM. (we chose GPT-4o mini)
`vendor_uri_func_result` records the request-dispatching functionality checking results using the lightweight LLM. (we chose GPT-4o mini)
`vendor_deepin_result` records the final validation results using the reasoning LLM. (we chose Deepseek R1)
NOTE: Remember to configure your API and URL in llm_function.py, process_llm_uri_check.py, and final_llm_pos_analysis.py 
* count custom functions: `python3 auto_define_funcs_dir.py [firmware_path] [firmware]` -- generate `funcs.json`
e.g. python3 auto_define_funcs_dir.py /home/root/ciscorv32cpio-root ciscorv32
[firmware] is the subdirectory of results : results/ciscorv32/
* extract string arguments: `python3 analyze_dir_callsite.py [firmware_path] [firmware]` -- generate `final_call_output.json`
* screen cource-grained: `python3 parse_call_results.py [firmware]` -- generate `final_possible.json`
* check decompilation error: `python3 check_decompile_error.py [firmware]`
The decompilation code of some functions is not incomplete, try manually open it with IDA Pro.
* check input-processing functionality: `python3 llm_function.py [firmware]` -- generate `llm_possible.json` and `nvram_possible.json`
* extract keywords in frontend files and configurations: `python3 frontend_string.py [firmware_path] [firmware]` -- generate `cfgkeywords.json` and `keywords.json`
* match arguments with keywords: `string_compare_before_uri.py [firmware]` -- generate `string_check_result.json`
* check request-dispatching functionality with the calling context of candidate functions: `python3 process_llm_uri_check.py [firmware]` -- generate `uri_need_inspect.json` and `uricheck_result.json`
* validata with reasong LLM: python3 final_llm_pos_analysis.py [firmware] -- generate `deepin_other_type.json` and `deepin_result_path.json`
* Our final results are with `deepin_result_path.json`

## Example
* The results of an example of DlinkDAP1860 are listed in ./example