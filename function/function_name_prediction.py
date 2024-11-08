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

class SingFunctionNamePrediction:

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

    def __init__(self, function_pseudocode_json) -> None:
        '''
        function_pseudocode_json: the json file path.
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
        '''
        pass



    