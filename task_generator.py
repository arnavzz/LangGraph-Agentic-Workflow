import os
from langchain_groq import ChatGroq
from langchain.schema import SystemMessage, HumanMessage
from dotenv import load_dotenv

load_dotenv()
GROQ_API_KEY = os.getenv("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")

# Initialize Groq LLM
llm = ChatGroq(model_name = "mixtral-8x7b-32768", api_key = GROQ_API_KEY)


SYSTEM_PROMPT = """
You are a cybersecurity AI agent. Given a high-level security instruction,
break it down into a step-by-step **task list**.

Tasks should include:
1. The tool to use (`nmap`, `gobuster`, `ffuf`, `sqlmap`).
2. The exact command to execute.
3. Any dependencies (like discovered subdomains).

Return the tasks as a **structured JSON** list.

"""
def generate_task_list(user_input: str):
    """Takes a security instruction and generates structured tasks."""
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=f"Instruction: {user_input}")
    ]
    response = llm.invoke(messages)
    
    return response.content  # Expecting JSON output from AI

if __name__ == "__main__":
    test_input = "Scan example.com for open ports and directories"
    task_list = generate_task_list(test_input)
    print(task_list) 