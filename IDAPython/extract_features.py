"""
For IDA Pro 7.7

Current code support X86/X64 only.

summary: automatic decompilation of functions

description:
  Attempts to load a decompiler plugin corresponding to the current
  architecture (and address size) right after auto-analysis is performed,
  and then tries to decompile the function at the first entrypoint.

  It is particularly suited for use with the '-S' flag, for example:
  idat -Ldecompile.log -Sdecompile_entry_points.py -c file
"""
import idaapi
import idautils
import ida_funcs
import idc
import json
import ida_ida
import ida_auto
import ida_loader
import ida_auto
import ida_hexrays
import ida_idp
import ida_entry
import ida_kernwin

import sys

# ============================Strings =======================================

def get_string_with_ref_funcs():
    sc = idautils.Strings()
    string_to_func_dic = {} # key: string address, value (string text, (reference function addrs))
    for s in sc:
        # print ("%x: len=%d type=%d -> '%s'" % (s.ea, s.length, 0, str(s)))
        ins_list = list(map( lambda x: x.frm, idautils.XrefsTo(s.ea, flags=0)))
        func_addrs =set(map(lambda x: idc.get_func_attr(x, idc.FUNCATTR_START), ins_list))
        string_to_func_dic[s.ea] = [str(s), list(func_addrs)]

    return string_to_func_dic



# ============================imported and exported function =======================================


def get_plt_functions() -> dict:
    # return plt/imported function dic: {addr:name}
    plt_functions = {}
    # 获取段数目，遍历查找名为'.plt'的段
    for segment in idautils.Segments():
        seg_name = idc.get_segm_name(segment)
        if seg_name == ".plt":
            # 遍历PLT段内的所有函数
            func_ea = segment
            while func_ea != idaapi.BADADDR and func_ea < idc.get_segm_end(segment):
                plt_functions[func_ea] = idc.get_func_name(func_ea)
                func_ea = idc.get_next_func(func_ea)
            break

    return plt_functions




def get_exports() -> dict:
    # return exported function dic: {addr:name}
    exports = {}
    
    for ordinal, ea, _ , name in idautils.Entries():
        exports[ea] = name
    
    return exports


# ============================ call graph =======================================


def get_all_callee_addrs(func_a_ea):

    # 获取函数A的所有指令地址
    func_items = list(idautils.FuncItems(func_a_ea))

    # 存储被调用函数的地址
    called_funcs = set()

    # 遍历函数A中的每条指令
    for item_ea in func_items:
        # 获取指令的助记符（例如 call, jmp 等）
        insn_mnem = idc.print_insn_mnem(item_ea)
        
        # 检查是否为调用指令
        if insn_mnem == 'call' or insn_mnem == "jmp":
            # 获取操作数类型（例如直接调用，间接调用等）
            called_funcs.update(idautils.CodeRefsFrom(item_ea, 0))

    # 打印被调用的函数地址
    return called_funcs - set(func_items[1:])




# Function to create and display the call graph
def generate_call_graph():
    # Initialize an empty graph
    graph = {}

    # Iterate over all functions in the binary
    for func_ea in idautils.Functions():
        if is_import_function(func_ea):
            continue
        # Get the function object
        # print(f"From func: {hex(func_ea)}")
        graph[func_ea] =list(get_all_callee_addrs(func_ea))

    return graph
# ============================ HEXRAY =======================================

# because the -S script runs very early, we need to load the decompiler
# manually if we want to use it
def init_hexrays():
    ALL_DECOMPILERS = {
        ida_idp.PLFM_386: "hexrays",
        ida_idp.PLFM_ARM: "hexarm",
        ida_idp.PLFM_PPC: "hexppc",
        ida_idp.PLFM_MIPS: "hexmips",
    }
    cpu = ida_idp.ph.id
    decompiler = ALL_DECOMPILERS.get(cpu, None)
    if not decompiler:
        print("No known decompilers for architecture with ID: %d" % ida_idp.ph.id)
        return False
    if ida_ida.inf_is_64bit():
        if cpu == ida_idp.PLFM_386:
            decompiler = "hexx64"
        else:
            decompiler += "64"
    if ida_loader.load_plugin(decompiler) and ida_hexrays.init_hexrays_plugin():
        return True
    else:
        print('Couldn\'t load or initialize decompiler: "%s"' % decompiler)
        return False

def decompile_func(ea):
    # ida_kernwin.msg("Decompiling at: %X..." % ea)
    try:
        cf = ida_hexrays.decompile(ea)
        if cf:
            # ida_kernwin.msg("OK\n")
            return str(cf)
        else:
            # ida_kernwin.msg("failed!\n")
            return ("decompilation failure at %X!\n" % ea)
    except:
        return ("decompilation failure at %X!\n" % ea)

def is_import_function(ea):
    """Check if the function is an import function."""
    seg_name = idc.get_segm_name(ea)
    if seg_name in ['.text']:
        return False
    return True

def main():
    print("Waiting for autoanalysis...")
    ida_auto.auto_wait()
    if init_hexrays():
        args = idc.ARGV
        if len(args) > 1:
            cpath = args[1]
        else:
            idbpath = idc.get_idb_path()
            cpath = idbpath[:-4] + ".json"
        features = {"call_graph":{}, "pseudocode":{}, "strings":None}

        features['imported_function'] = get_plt_functions()
        features['exported_function'] = get_exports()

        # extract pseudocode
        func_code = {}
        for func_ea in idautils.Functions():
            if is_import_function(func_ea):
                continue  # Skip import functions
            pseudocode = decompile_func(func_ea)
            func_name = idc.get_func_name(func_ea)
            func_code[func_ea] =(func_name, hex(func_ea), pseudocode)
        features["pseudocode"] = func_code

        # extract call graph
        features["call_graph"] = generate_call_graph()

        # extract strings with all reference functions.
        features['strings'] = get_string_with_ref_funcs()
            
        print(f"dumping to json file {cpath}")
        with open(cpath, "w") as outfile:
            json.dump(features, outfile, indent=4)
        
    if ida_auto.is_auto_enabled():
        print("All done, exiting.")
        os._exit(0) # ida_pro.qexit(0) would not close the IDA Pro window
        # ida_pro.qexit(0)

main()