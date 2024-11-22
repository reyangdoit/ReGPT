import configparser
import os
import subprocess

PROJECT_ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class EXE_IDA_PYTHON:

    def __init__(self) -> None:
        
        cfp = configparser.ConfigParser()
        # 读取配置文件
        cfp.read(os.path.join(PROJECT_ROOT_DIR, "./config.ini"))
        
        # 获取IDA32可执行文件路径
        self._ida32 = cfp['IDA']["IDA32_EXE"]
        # 获取IDA64可执行文件路径
        self._ida64 = cfp['IDA']["IDA64_EXE"]

        # 获取IDA Python脚本路径
        self._ida_python_script = os.path.join(PROJECT_ROOT_DIR, "IDAPython", "extract_features.py")

        # 检查IDA Python脚本是否存在
        if not os.path.exists(self._ida_python_script):
            raise FileNotFoundError(f"ida python script not found in {self._ida_python_script}")
        
        # 检查IDA32可执行文件是否存在
        if not os.path.exists(self._ida32):
            raise FileNotFoundError(f"ida exe not found in {self._ida32}")
        
        # 检查IDA64可执行文件是否存在
        if not os.path.exists(self._ida64):
            raise FileNotFoundError(f"ida exe not found in {self._ida64}")

    
    def extract_bin(self, bin_path: str):

        if not os.path.exists(bin_path):
            raise FileExistsError(f"bin file not found in {bin_path}")
        
        save_path = bin_path + ".json"

        if os.path.exists(save_path):
            print(f"Using cached feature file: {save_path}")
            return save_path
        
        # combine the command to execute
        command = [self._ida32, '-A', f'-S"{self._ida_python_script} {save_path}"', bin_path]

        # execute the command
        print(f"Executing command: {" ".join(command)}")
                
        try:
            os.system(" ".join(command))
        except subprocess.CalledProcessError as e:
            print(f"Error during IDA execution:\n{e.stderr}")
            return None

        return save_path