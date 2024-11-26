# ReGPT
Aiming to accomplish a reverse software enginnering.


# Install & Preparation

## env setting up

1. ollama setting up. (this part is based on aidapal project.)
    - install ollama
    - Download the fine-tuned weights and Ollama modelfile:
        - Model: https://huggingface.co/AverageBusinessUser/aidapal/blob/main/aidapal-8k.Q4_K_M.gguf
        - Ollama Modelfile: https://huggingface.co/AverageBusinessUser/aidapal/blob/main/aidapal.modelfile
    - Run model: run command `ollama create aidapal -f aidapal.modelfile` within the modelfile directory.
2. python env setting up
    - install python 3.10
    - install python package: `pip install -r requirements.txt`
3. chatgpt setting up
    - get your openai api key
    - edit the `config.ini` file for your api key
4. ida setting up
    - edit the `config.ini` file for your ida path

# Usage

`python main.py binary_path`


## example
```
python .\main.py .\dataset\stripped\software_6
Using cached feature file: .\dataset\stripped\software_6.json
Prediction result exists, loading from cache... .\dataset\stripped\software_6.json.func_names
Results saved in .\dataset\stripped\software_6_result.json.
```

check the .\dataset\stripped\software_6_result.json for the results.