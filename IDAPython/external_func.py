import idautils
import idaapi
import idc

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

exports = get_exports()
for ea, name in exports.items():
    print(f"0x{ea:X}: {name}")



print("....======================")

# 调用函数并打印PLT表中的函数
plt_functions = get_plt_functions()
for ea, name in plt_functions.items():
    print(f"0x{ea:X}: {name}")
