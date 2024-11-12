import idautils
import idc
import json

def get_string_with_ref_funcs():
    sc = idautils.Strings()
    string_to_func_dic = {} # key: string address, value (string text, (reference function addrs))
    for s in sc:
        print ("%x: len=%d type=%d -> '%s'" % (s.ea, s.length, 0, str(s)))
        ins_list = list(map( lambda x: x.frm, idautils.XrefsTo(s.ea, flags=0)))
        func_addrs =set(map(lambda x: idc.get_func_attr(x, idc.FUNCATTR_START), ins_list))
        string_to_func_dic[s.ea] = [str(s), list(func_addrs)]

    return string_to_func_dic


print(json.dumps(get_string_with_ref_funcs(), indent=4))
    