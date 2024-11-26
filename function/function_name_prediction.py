#encoding:utf-8
'''
This script predict function names based on decompiled results by decompilers such as hexray, ghidra, etc.

The decompiled results should be placed in json file with format

{
    function1_addr: [function1_name, function1_addr_, function1_pseudocode_text],
    function2_addr: [function2_name, function2_addr_, function2_pseudocode_text],
}.

To get a better decompilation result, this code applies several strategies:

    1. Predicting Variable Names First, Then Function Names
    2. Prioritizing Functions in Deep Positions in the Call Graph ()
    3. Using the Context of Function Call Sites
    4. Prioritizing Functions with Meaningful Strings First
'''

import model.chatgpt
import logging
import os
from function.prompts import PROMPT_DEBUG, PROMPT_ONLY_FUNCTION_NAME, PROMPT_OLLAMA_NAME_ONLY
import requests
import json
import numpy as np
import re
from tqdm import tqdm
import config

# where ollama service is running

class NamePrediction_aidapal:
    
    def __init__(self) -> None:
        self._ollama_url = config.get_config("OLLAMA", "URL")
        self._prompt = PROMPT_OLLAMA_NAME_ONLY

    def predict(self, function_pseudocode: str, additional_info = None) -> str:

        # 如果函数伪代码中包含"decompilation failure at"，则返回None
        if "decompilation failure at" in function_pseudocode:
            return None

        # 定义url和请求头
        url = self._ollama_url
        headers = {"Content-Type": "application/json"}
        # 定义请求体
        payload = {"model": "aidapal", "prompt": function_pseudocode + "\n" + self._prompt, "stream": False, "format":"json"}
        # 发送post请求
        try:
            res = requests.post(url, headers=headers, json=payload, timeout=120)
        # 解析返回的json数据
            t = res.json()['response']
            t = json.loads(t)
        # 打印解析后的数据
            # print(t)
        # 返回函数名
            return t['function_name']
        # 如果请求超时，则打印错误信息并返回None
        except (requests.exceptions.ReadTimeout, json.decoder.JSONDecodeError, KeyError) as e:
            print(str(e) + f"timeout when predicting function name for: {function_pseudocode}")
            return None

class NamePrediction_openai:

    def __init__(self, name_only = True) -> None:
        self.LLM = model.chatgpt.OpenAI()
        self._prompt = PROMPT_ONLY_FUNCTION_NAME
        if not name_only:
            self._prompt = PROMPT_DEBUG


    def prediction(self, function_content: str, additional_info = None) -> str :
        '''
        function_content: the pseudocode of target function.
        additional_info: dict: for additional information to improve the prompt.
        '''

        res = self.LLM.query(self._prompt + function_content)
        return res


class MODULARIZATION_PREDICTION:

    def __init__(self, software_datas, use_prediction_cache=True) -> None:
        '''
        software_datas: the json file path.
        The decompiled results should be placed in json file with format

            {
            pseudocode:[
                function1_addr: [function1_name, function1_addr_, function1_pseudocode_text],
                function2_addr: [function2_name, function2_addr_, function2_pseudocode_text],]
            
            call_graph:[
                    function1_addr: [callee1_addr, callee2_addr]
                ]
            
            strings_to_func:[
                str1_addr : [string1, [func1, func2]]
            ]
            }.

            imported_function: {
                imported_addr1: name,
            }

            exported_function{
                exported_addr: name
            }
        '''
        self._uc = use_prediction_cache
        self._llm = NamePrediction_aidapal()

        self.software_dic = None
        with open(software_datas, 'r') as f:
            self.software_dic = json.load(f)

        self._pseudocode = self.software_dic['pseudocode']

        self._prediction_res_json_path = os.path.join(os.path.dirname(software_datas), os.path.basename(software_datas)+".func_names")

    def sort_function_by_confidence(self) -> np.array:
        '''
        using page rank to calculate weight in call graph
        The rule of calculating confidence score:
            1. If functions calls imported function, add 1.
            2. If function calls a unamed function (sub_xxx), minus 1.
            3. If function refers a string, add 0-1, value depends on string meaning confidence.

        return the list of function addrs, sorted by their confidence.
        '''
        IMPORTED_ADDON = 0.1 # 导入函数对目标函数的加分
        STRING_ADDON = 0.1 # 字符串对目标函数的加分
        call_graph = self.software_dic['call_graph']
        plt = self.software_dic['imported_function']
        
        nodes_and_scores = {}
        # using imported and strings to init weights of nodes.
        for x in call_graph.keys():
            nodes_and_scores[int(x)] = 0

        for n in call_graph:
            for callee in call_graph[n]:
                if str(callee) in plt:
                    nodes_and_scores[int(n)] += IMPORTED_ADDON
                    continue
                elif callee not in nodes_and_scores:
                    nodes_and_scores[callee] = 0
        
        for _, v in self.software_dic['strings'].items():
            string_score = np.log10(len(v[0])/2)/10
            for func_addr in v[1]:
                if func_addr in nodes_and_scores:
                    nodes_and_scores[func_addr] += string_score
                
        # init scores
        func_addrs = np.array(list(nodes_and_scores.keys()))
        scores = np.array(list(nodes_and_scores.values()))

        nodes_num = len(nodes_and_scores)

        pagerank_values = np.ones(nodes_num) / nodes_num  + scores

        link_matrix = np.zeros((nodes_num, nodes_num))

        # 出链矩阵
        for page, outgoing_links in call_graph.items():
            page = int(page)
            if outgoing_links:
                for dest_page in outgoing_links:
                    if dest_page in func_addrs:
                        dest_page_i = np.where(func_addrs == dest_page)[0][0]
                        page_i = np.where(func_addrs == page)[0][0]
                        link_matrix[dest_page_i, page_i] = 1/len(outgoing_links)

        # 迭代计算pagerank值，直到收敛
        delta = 1
        damping_factor = 0.85
        i = 0
        while delta > 1.0e-6:
            new_pagerank_values = (1 - damping_factor) / nodes_num + damping_factor * link_matrix.dot(pagerank_values)
            delta = np.linalg.norm(new_pagerank_values - pagerank_values)
            pagerank_values = new_pagerank_values
            i += 1
            # print(f"{i}th calculation.")
        
        sorted_indices = np.argsort(pagerank_values)[::-1]
        return func_addrs[sorted_indices]



    def _update_func_names_in_pseudocode(self, pseudocode_text, predict_res) -> str:
        '''

        return: updated pseudocode
        '''

        for addr, func_name in predict_res.items():
            addr_hex = "sub_" + str(hex(addr))[2:]
            # print(addr_hex)
            pseudocode_text = re.sub(addr_hex, func_name, pseudocode_text, flags=re.IGNORECASE)
        
        return pseudocode_text


    def predict_all(self):

        if self._uc and os.path.exists(self._prediction_res_json_path):
            print(f"Prediction result exists, loading from cache... {self._prediction_res_json_path}")
            with open(self._prediction_res_json_path, 'r') as f:
                return json.load(f)


        funcs = self.sort_function_by_confidence()
        predict_res = {} # {addr : predicted_name}
        
        for func in tqdm(funcs, desc="Predicting Function Names"):
            func_addr = str(func)
            if func_addr in self._pseudocode:
                func_pseudocode = self._pseudocode[func_addr][2]
                #print(func_pseudocode)
                func_pseudocode = self._update_func_names_in_pseudocode(func_pseudocode, predict_res=predict_res)
                # replace the predicted function names in pseudocode.
                predicted_name = self._llm.predict(func_pseudocode)
                if predicted_name:
                    predict_res[int(func)] = predicted_name
                else:
                    predict_res[int(func)] = func_addr
            # 
        
        # print(predict_res)

        # save cache
        with open(self._prediction_res_json_path, 'w') as f:
            json.dump(predict_res, f)

        return predict_res


    def get_callgraph(self):
        return self.software_dic['call_graph']