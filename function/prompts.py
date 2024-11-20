

PROMPT_DEBUG = """You are a binary code analyst tasked with analyzing a pseudocode function that has a generic or meaningless name. Your objective is to suggest a more descriptive and meaningful function name based on the function's behavior.

# Steps:
1. Infer Variable Names: Start by examining *all* unnamed variables within the function. Use any identifiable function calls to make educated guesses about the variable roles. For example, in a line such as `sigaddset(v2, a1)`, where `sigaddset` is defined as `int sigaddset(sigset_t *set, int signum);`, you could rename `v2` to `set` and `a1` to `signum` to improve readability.
   
2. Analyze Code Behavior: Review each line of code to understand the function's purpose. Consider the operations performed, the nature of inputs, and the expected output. 

3. Rename the Function: Once you’ve comprehended the function's purpose, rename it with a term that accurately reflects its behavior.

# Example:
Given the pseudocode:

```c
int sub_0x40879(int a, int b) {
    return a + b;
}
```

Upon analysis, you observe that the function returns the sum of two arguments (`a + b`). Therefore, a more meaningful name for this function would be `sum`.

# Task:
Analyze the pseudocode below and suggest a more meaningful function name based on its behavior:

Pseudocode:"""

PROMPT_ONLY_FUNCTION_NAME = """You are a binary code analyst tasked with analyzing a pseudocode function that has a generic or meaningless name. Your objective is to suggest a more descriptive and meaningful function name based on the function's behavior.

# Steps:
1. Infer Variable Names: Start by examining *all* unnamed variables within the function. Use any identifiable function calls to make educated guesses about the variable roles. For example, in a line such as `sigaddset(v2, a1)`, where `sigaddset` is defined as `int sigaddset(sigset_t *set, int signum);`, you could rename `v2` to `set` and `a1` to `signum` to improve readability.
   
2. Analyze Code Behavior: Review each line of code to understand the function's purpose. Consider the operations performed, the nature of inputs, and the expected output. 

3. Rename the Function: Once you’ve comprehended the function's purpose, rename it with a term that accurately reflects its behavior.

# Example:
Given the pseudocode:

```c
int sub_0x40879(int a, int b) {
    return a + b;
}
```

Upon analysis, you observe that the function returns the sum of two arguments (`a + b`). Therefore, a more meaningful name for this function would be `sum`.

# Task:
Analyze the pseudocode below and suggest a more meaningful function name "only" (no explaination) based on its behavior:

Pseudocode:"""




# copy from paper "Binary Code Summarization: Benchmarking ChatGPT/GPT-4 and Other Large Language Models."

PROMT_BinSum = """Imagine you're an expert in binary reverse engineering. I'll provide you with a binary function, and your task is to conduct a thorough analysis of its functionality. Explain its underlying operations and logic in detail, and then suggest an appropriate, intuitive name for the function from a coder’s perspective."""




PROMPT_Modularization = """**任务描述**：  
你是一名二进制逆向工程和程序分析的专家。你需要协助分析一个程序的逻辑结构和功能模块。以下是我提供的数据：

1. **函数名称字典**：程序中的函数地址与对应的函数名映射，如 `{"func1_addr": "func1_name", "func2_addr": "func2_name", ..., "funcN_addr": "funcN_name"}`。  
2. **函数调用图**：函数之间的调用关系图，表示为字典形式：`{"func1_addr": ["func2_addr", "funcI_addr"], "func2_addr": [...], ...}`。

**目标**：  
根据提供的函数名称和调用图数据，完成以下任务：  
1. 分析程序中包含的主要模块或逻辑部分（如初始化模块、核心功能模块、清理模块等）。  
2. 推测各模块的功能，尽可能给出合理的描述。  
3. 总结整个程序的主要功能以及其实现方式。  

**具体要求**：  
- 使用函数名称和调用关系进行模块划分，可以通过函数的调用链、命名模式或其他合理的线索确定模块。  
- 如果可能，识别关键函数（如主入口函数、重要逻辑处理函数）。  
- 对调用图进行整理，形成一个清晰的模块功能分层结构。  
- 输出应以清晰的结构化形式呈现（例如分模块的描述），并包含适当的推断依据。  

示例数据结构：  
```json
{
  "names": {
    "0x401000": "main",
    "0x401100": "init",
    "0x401200": "process_data",
    "0x401300": "cleanup"
  },
  "call_graph": {
    "0x401000": ["0x401100", "0x401200"],
    "0x401100": [],
    "0x401200": ["0x401300"],
    "0x401300": []
  }
}
```
结果输出应该为json格式。
**输出示例**：
```
{

    "模块划分"：{
        "1. 初始化模块" : {
            "包含函数":["init (0x401100)", ... ],
            "功能": "完成程序的初始化工作，可能涉及资源分配或环境配置。"
        },
        "2. 数据处理模块" : {
            "包含函数":["process_data (0x401200)", ... ],
            "功能": "核心逻辑处理功能，负责程序的主要任务。调用了 `cleanup` 进行清理。"
        },
        "3. 清理模块" : {
            "包含函数":["cleanup (0x401300)", ... ],
            "功能": "释放资源、清理环境，保证程序安全退出。"
        }
    },
    "程序功能总结":"该程序是一个包含初始化、数据处理和清理模块的典型程序。入口为 `main (0x401000)`，按序调用各模块完成整个流程。它可能是一个用于数据处理或计算的工具程序。 "
}
```

请根据上述要求，分析提供的程序数据并输出完整的模块和功能描述，只输出json格式的结果。
"""