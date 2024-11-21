
# 导入EXE_IDA_PYTHON类
from IDAPython.wrap_class import EXE_IDA_PYTHON
# 导入RenameSoftwareFunctions类
from function import RenameSoftwareFunctions
# 导入Modularization类
from function import Modularization

# 定义主函数
def main():
    # 创建一个EXE_IDA_PYTHON对象
    eip = EXE_IDA_PYTHON()
    # 提取二进制文件
    feature_json = eip.extract_bin("D:\\re_se\\ReGPT\\dataset\\stripped\\software_1.idb")

    # 创建一个RenameSoftwareFunctions对象
    rsf = RenameSoftwareFunctions(feature_json)
    # 预测所有函数名
    func_names = rsf.predict_all()
    # 获取调用图
    call_graph = rsf.get_callgraph()

    # 创建一个Modularization对象
    modular = Modularization()
    # 预测模块化结果
    res = modular.predict(name_dic=func_names, call_graph=call_graph)
    # 打印结果
    print(res)


# 如果是主程序，则运行主函数
if __name__ == "__main__":
    main() 