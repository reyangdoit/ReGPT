import model.chatgpt

from function.prompts import PROMPT_Modularization as PROMPT

import json
import logging
logger = logging.getLogger("modularization")

class Modularization:

    def __init__(self, LLM_name = "openai") -> None:
        
        self._llm = None
        if LLM_name == "openai":
            self._llm = model.chatgpt.OpenAI()
        else:
            raise ValueError("LLM name is not supported!")
        self._prompt = PROMPT


    def predict_with_name_and_cg(self, name_dic: dict, call_graph: dict):
        
        prompt = self._prompt + " { 函数名称字典：" + json.dumps(name_dic) + "\n 函数调用图：" + json.dumps(call_graph) + "}"
        logger.info(prompt)
        res = self._llm.query(prompt)
        try:
            return json.loads(res)
        except Exception:
            print("Json parsing error.")
            print(res)
            return None


    def predict(self, name_dic, call_graph):
        return self.predict_with_name_and_cg(name_dic=name_dic, call_graph=call_graph)