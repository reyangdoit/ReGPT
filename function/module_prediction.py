import model.chatgpt

from function.prompts import PROMPT_Modularization_SYSTEM as PROMPT

import json
import logging
logger = logging.getLogger("modularization")
from pydantic import BaseModel
class Module_DESCRIPTION(BaseModel):
    Module_name: str
    Module_functions: list[str]
    Module_description: str

    def __str__(self) -> str:
        return str({"模块名": self.Module_name, "包含函数": str(self.Module_functions), "功能描述": self.Module_description})

class MODULARIZATION_RESULT(BaseModel):
    modules: list[Module_DESCRIPTION]
    Functionality_summary: str
    # other fields as needed

    def __str__(self) -> str:
        return str({"模块划分": [str(x) for x in self.modules], "程序功能总结": self.Functionality_summary})

    def to_json(self):
        json_str = json.dumps(self.model_dump(), indent=4, ensure_ascii=False)
        return json_str.encode('utf-8')

class Modularization:

    def __init__(self, LLM_name = "openai") -> None:
        
        self._llm = None
        if LLM_name == "openai":
            self._llm = model.chatgpt.OpenAI()
        else:
            raise ValueError("LLM name is not supported!")
        self._prompt = PROMPT

    def predict_with_name_and_cg(self, name_dic: dict, call_graph: dict):
        
        user_prompt = " { 函数名称字典：" + json.dumps(name_dic) + "\n 函数调用图：" + json.dumps(call_graph) + "}"
        res = self._llm.query(user_prompt, system_prompt=self._prompt, response_format=MODULARIZATION_RESULT)
        if res:
            return res
        else:
            return None


    def predict(self, name_dic, call_graph):
        return self.predict_with_name_and_cg(name_dic=name_dic, call_graph=call_graph)