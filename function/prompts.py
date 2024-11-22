

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




PROMPT_Modularization = """
A. 任务描述：  
你是一名专注于二进制逆向工程和程序分析的专家，需要协助分析一个程序的逻辑结构和功能模块。以下是程序提供的数据：  
1. 函数名称字典：程序中函数地址与对应函数名的映射关系，格式为：  
   {
       "func1_addr": "func1_name",
       "func2_addr": "func2_name",
       ...,
       "funcN_addr": "funcN_name"
   }

2. 函数调用图：表示函数之间调用关系的字典，格式为：  
   {
       "func1_addr": ["func2_addr", "funcI_addr"],
       "func2_addr": [...],
       ...
   }

B. 目标：  
根据提供的函数名称和调用图数据，完成以下任务：  
1. 模块分析：识别程序中包含的主要模块或逻辑部分（例如初始化模块、核心功能模块、清理模块等）。  
2. 功能推测：推测各模块的功能，并提供尽可能合理的描述。  
3. 程序总结：概括整个程序的主要功能以及实现方式。  

C. 具体要求：  
- 使用函数名称和调用关系进行模块划分，可结合函数的调用链、命名模式或其他合理线索确定模块。  
- 识别关键函数（如程序主入口函数、重要逻辑处理函数），并说明其作用。  
- 整理调用图，形成清晰的模块功能分层结构。  
- 输出应以清晰、结构化的形式呈现，并包含适当的推断依据。  
- 输出结果须为json格式的字符串，无需添加任何额外说明或标记，**只需要原始json字符串内容**。

D. 输出模板：
{
    "模块划分": {
        "模块编号": {
            "包含函数": ["函数名1 (地址)", "函数名2 (地址)", ...],
            "功能": "该模块的功能描述。"
        },
        ...
    },
    "程序功能总结": "程序整体功能的概述，包含主要功能模块及其作用。"
}


E. 示例
示例输入：  
{
    "函数名称字典": {
        "0x401000": "main",
        "0x401100": "init",
        "0x401200": "process_data",
        "0x401300": "cleanup"
    },
    "函数调用图": {
        "0x401000": ["0x401100", "0x401200"],
        "0x401100": [],
        "0x401200": ["0x401300"],
        "0x401300": []
    }
}

示例输出：  
{
    "模块划分": {
        "1. 初始化模块": {
            "包含函数": ["init (0x401100)"],
            "功能": "完成程序的初始化工作，可能涉及资源分配或环境配置。"
        },
        "2. 数据处理模块": {
            "包含函数": ["process_data (0x401200)"],
            "功能": "核心逻辑处理功能，负责程序的主要任务。调用了 `cleanup` 进行清理。"
        },
        "3. 清理模块": {
            "包含函数": ["cleanup (0x401300)"],
            "功能": "释放资源、清理环境，保证程序安全退出。"
        }
    },
    "程序功能总结": "该程序是一个包含初始化、数据处理和清理模块的典型程序。入口为 `main (0x401000)`，按序调用各模块完成整个流程。它可能是一个用于数据处理或计算的工具程序。"
}


请根据以上说明分析输入数据，并仅输出符合模板的json字符串内容，**注意只输出json的原始字符串内容即可，不需要输出markdown格式**。
"""



PROMPT_Modularization_json = """
System:
{
    "你的角色": "你是一名专注于二进制逆向工程和程序分析的专家，需要协助分析一个程序的逻辑结构和功能模块。"
    "任务描述": {
        "目标": "分析一个程序的逻辑结构和功能模块。",
        "数据": {
            "函数名称字典": {
                "描述": "程序中函数地址与对应函数名的映射关系。",
                "格式": {
                    "func_addr": "func_name"
                }
            },
            "函数调用图": {
                "描述": "表示函数之间调用关系的字典。",
                "格式": {
                    "func_addr": ["called_func1_addr", "called_func2_addr"]
                }
            }
        },
        "目标任务": [
            "模块分析：识别程序中包含的主要模块或逻辑部分。",
            "功能推测：推测各模块的功能并合理描述。",
            "程序总结：概括整个程序的主要功能及实现方式。"
        ],
        "具体要求": [
            "根据函数名称和调用关系进行模块划分，结合合理线索。",
            "识别关键函数并说明其作用。",
            "整理调用图，形成模块功能分层结构。",
            "输出以清晰、结构化的形式呈现，包含推断依据。",
            "输出为json格式的字符串，不是markdown格式。"
        ]
    },
    "输出模板": {
        "模块划分": {
            "模块编号": {
                "包含函数": ["函数名1 (地址)", "函数名2 (地址)"],
                "功能": "该模块的功能描述。"
            }
        },
        "程序功能总结": "程序整体功能的概述，包含主要功能模块及其作用。"
    },
    "示例": {
        "输入": {
            "函数名称字典": {
                "0x401000": "main",
                "0x401100": "init",
                "0x401200": "process_data",
                "0x401300": "cleanup"
            },
            "函数调用图": {
                "0x401000": ["0x401100", "0x401200"],
                "0x401100": [],
                "0x401200": ["0x401300"],
                "0x401300": []
            }
        },
        "输出": {
            "模块划分": {
                "1. 初始化模块": {
                    "包含函数": ["init (0x401100)"],
                    "功能": "完成程序的初始化工作，可能涉及资源分配或环境配置。"
                },
                "2. 数据处理模块": {
                    "包含函数": ["process_data (0x401200)"],
                    "功能": "核心逻辑处理功能，负责程序的主要任务。调用了 `cleanup` 进行清理。"
                },
                "3. 清理模块": {
                    "包含函数": ["cleanup (0x401300)"],
                    "功能": "释放资源、清理环境，保证程序安全退出。"
                }
            },
            "程序功能总结": "该程序是一个包含初始化、数据处理和清理模块的典型程序。入口为 `main (0x401000)`，按序调用各模块完成整个流程。它可能是一个用于数据处理或计算的工具程序。"
        }
    }
}

User:
"""



# for ollama predict name only 
PROMPT_OLLAMA_NAME_ONLY = """Output a response in JSON format containing only the key "function_name" with the value as the predicted function name. Do not include any explanations, comments, or additional variables. Example output: {"function_name": "predicted_function_name"}."""