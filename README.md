
# ReGPT
**Reverse engineering software using LLM-based approaches.**

## Installation & Setup

### Environment Setup

#### 1. **Ollama Setup**  
This process leverages the *Aidapal* project:  
- **Install Ollama.**  
- **Download fine-tuned weights and the Ollama model file:**  
  - [Model](https://huggingface.co/AverageBusinessUser/aidapal/blob/main/aidapal-8k.Q4_K_M.gguf)  
  - [Ollama Modelfile](https://huggingface.co/AverageBusinessUser/aidapal/blob/main/aidapal.modelfile)  
- **Run the model:**  
  Execute the following command in the directory containing the model file:  
  ```bash
  ollama create aidapal -f aidapal.modelfile
  ```

#### 2. **Python Environment Setup**  
- Install Python 3.10.  
- Install dependencies:  
  ```bash
  pip install -r requirements.txt
  ```

#### 3. **ChatGPT Setup**  
- Copy the example config file:  
  ```bash
  cp config.example.ini config.ini
  ```  
- Obtain your OpenAI API key.  
- Add your API key to the `config.ini` file.

#### 4. **IDA Setup**  
- Specify the path to your IDA installation in the `config.ini` file.

---

## Usage

Run the tool with the following command:  
```bash
python main.py binary_path
```

### Example
```bash
python main.py ./dataset/stripped/software_6
```

- If cached results exist, they will be loaded:  
  ```
  Using cached feature file: ./dataset/stripped/software_6.json
  Prediction result exists, loading from cache... ./dataset/stripped/software_6.json.func_names
  Results saved in ./dataset/stripped/software_6_result.json.
  ```
- Check the results in the output file:  
  ```plaintext
  ./dataset/stripped/software_6_result.json
  ```

### Example output

see `./dataset/stripped/software_6_result.json`