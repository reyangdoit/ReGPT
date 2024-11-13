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
from function.prompts import PROMPT_DEBUG, PROMPT_ONLY_FUNCTION_NAME
import requests
import json


# where ollama service is running
ollama_url = "http://127.0.0.1:11434/api/generate"
class NamePredictionWithAidapal:
    
    def __init__(self) -> None:
        pass

    def prediction(self, function_pseudocode: str, additional_info = None) -> str:
        url = ollama_url
        headers = {"Content-Type": "application/json"}
        payload = {"model": "aidapal", "prompt": function_pseudocode, "stream": False,"format":"json"}
        res = requests.post(url, headers=headers, json=payload)
        t = res.json()['response']
        t = json.loads(t)
        return t['function_name']

class SingleFunctionNamePrediction:

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


class RenameSoftwareFunctions:

    def __init__(self, software_datas) -> None:
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
                function1_addr : [string1, string2]
            ]
            }.

            imported_function: {
                imported_addr1: name,
            }

            exported_function{
                exported_addr: name
            }
        '''

        self.software_dic = None
        with open(software_datas, 'r') as f:
            self.software_dic = json.load(f)

    
    def init_weights_in_call_graph(self):
        '''
        visit functions in call graph from bottom up along with assigning the confidence score to them.
        The rule of calculating confidence score:
            1. If functions calls imported function, add 1.
            2. If function calls a unamed function (sub_xxx), minus 1.
            3. If function refers a string, add 0-1, value depends on string meaning confidence.
        '''
        pass
        
        call_graph = self.software_dic['call_graph']

        




    def sort_function_by_confidence(self):
        pass





    def predict_all(self):
        pass