
# 导入EXE_IDA_PYTHON类
from IDAPython.wrap_class import EXE_IDA_PYTHON
# 导入RenameSoftwareFunctions类
from function import RenameSoftwareFunctions
# 导入Modularization类
from function import Modularization
import json
import logging
logger = logging.getLogger("main")
logger.setLevel(logging.DEBUG)

# 定义主函数
def main():

    # 定义目标二进制文件路径
    TARGET_BIN = "D:\\re_se\\ReGPT\\dataset\\stripped\\software_2.idb"

    RESULT_FILE = TARGET_BIN + "_result.json"

    # 是否使用函数预测缓存
    USE_FUNC_PREDICTION_CACHE = True

    # 创建一个EXE_IDA_PYTHON对象
    eip = EXE_IDA_PYTHON()
    # 提取二进制文件
    feature_json = eip.extract_bin(TARGET_BIN)

    # 创建一个RenameSoftwareFunctions对象
    rsf = RenameSoftwareFunctions(feature_json, use_prediction_cache=USE_FUNC_PREDICTION_CACHE)
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
        res = json.dumps(res, indent=4)
        Result_file.write(res)
    
    print(f"Results saved in {RESULT_FILE}.")

# 如果是主程序，则运行主函数
if __name__ == "__main__":
    main()