import idaapi
import idautils
import ida_funcs
import ida_gdl
import ida_graph
import json
import idc

def is_import_function(ea):
    """Check if the function is an import function."""
    seg_name = idc.get_segm_name(ea)
    if seg_name in ['.text']:
        return False
    return True

def get_all_callee_addrs(func_a_ea):
    # 假设我们已经知道了函数A的起始地址

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
        print(f"From func: {hex(func_ea)}")
        graph[func_ea] =list(get_all_callee_addrs(func_ea))

    return graph
    

# Run the function to generate the call graph
print(generate_call_graph())
