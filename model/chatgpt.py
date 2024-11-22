import openai
import model.config
import logging
logger = logging.getLogger("chatgpt")

class OpenAI:

    def __init__(self) -> None:
        

        self._model_name = model.config.get_config("OpenAI","MODEL")
        self._api_key = model.config.get_config("OpenAI", "API_KEY")
        self._base_url =  model.config.get_config("OpenAI", "BASE_URL")

        if not self._base_url:
            self._base_url = "https://api.openai.com/v1/chat/completions"

        if not self._api_key:
            raise ValueError("no api key in config.ini")    

        logger.debug(f"model {self._model_name}, base_url {self._base_url}")    

        self._client = openai.OpenAI(
            api_key=self._api_key,
            base_url= self._base_url
        )

    

    def query(self, query:str):
        
        conversation =[ {
            "role" : "user",
            "content": query
        } ]

        response = self._client.chat.completions.create(
            model=self._model_name,
            messages=conversation,
        )
        
        return response.choices[0].message.content



