
# 导入EXE_IDA_PYTHON类
from IDAPython.wrap_class import EXE_IDA_PYTHON
# 导入RenameSoftwareFunctions类
from function import MODULARIZATION_PREDICTION
# 导入Modularization类
from function import Modularization
import json
import logging
logger = logging.getLogger("main")
logger.setLevel(logging.DEBUG)
import argparse

# 定义主函数
def main():
    AP = argparse.ArgumentParser()
    AP.add_argument("binary", help="path to target binary file", type=str)
    AP.add_argument("--no_name_cache", help="do not use function prediction cache", action="store_true")
    AP.add_argument("-o", "--output", help="path to analysis output file", type=str)

    args = AP.parse_args()

    if not args.binary:
        print("Please provide the path to the target binary file.")
        AP.print_usage()
        exit(1)

    # 定义目标二进制文件路径
    TARGET_BIN = args.binary

    if args.output:
        RESULT_FILE = args.output
    else:
        # 定义结果文件路径
        RESULT_FILE = TARGET_BIN + "_result.json"

    # 是否使用函数预测缓存
    USE_FUNC_PREDICTION_CACHE = not args.no_name_cache
    # 创建一个EXE_IDA_PYTHON对象
    eip = EXE_IDA_PYTHON()
    # 提取二进制文件
    feature_json = eip.extract_bin(TARGET_BIN)

    # 创建一个RenameSoftwareFunctions对象
    rsf = MODULARIZATION_PREDICTION(feature_json, use_prediction_cache=USE_FUNC_PREDICTION_CACHE)
    # 预测所有函数名
    func_names = rsf.predict_all()
    # 获取调用图
    call_graph = rsf.get_callgraph()
    # 创建一个Modularization对象
    modular = Modularization()
    # 预测模块化结果
    res = modular.predict(name_dic=func_names, call_graph=call_graph)
    # save 结果
    with open(RESULT_FILE, "w", encoding="utf-8") as Result_file:
        # 将结果保存为JSON文件
        Result_file.write(res.to_json().decode())
    
    print(f"Results saved in {RESULT_FILE}.")

# 如果是主程序，则运行主函数
if __name__ == "__main__":
    main()