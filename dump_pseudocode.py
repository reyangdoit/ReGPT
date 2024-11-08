"""
For IDA Pro 7.7

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
import idc
import json
import ida_ida
import ida_auto
import ida_loader
import ida_hexrays
import ida_idp
import ida_entry
import ida_kernwin

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
    ida_kernwin.msg("Decompiling at: %X..." % ea)
    try:
        cf = ida_hexrays.decompile(ea)
        if cf:
            ida_kernwin.msg("OK\n")
            return str(cf)
        else:
            ida_kernwin.msg("failed!\n")
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
        idbpath = idc.get_idb_path()
        cpath = idbpath[:-4] + ".json"
        ALL_func_code = {}
        for func_ea in idautils.Functions():
            if is_import_function(func_ea):
                continue  # Skip import functions
            pseudocode = decompile_func(func_ea)
            func_name = idc.get_func_name(func_ea)
            ALL_func_code[func_ea] =(func_name, hex(func_ea), pseudocode)
            
        print("dumping to json file")
        with open(cpath, "w") as outfile:
            json.dump(ALL_func_code, outfile, indent=4)
        
    if ida_kernwin.cvar.batch:
        print("All done, exiting.")
        ida_pro.qexit(0)

main()