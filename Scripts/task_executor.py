import os
import subprocess
import json
import time
from langchain_groq import ChatGroq
from langchain.schema import SystemMessage, HumanMessage
from dotenv import load_dotenv
from langgraph.graph import StateGraph, END

# Load environment variables
load_dotenv()
GROQ_API_KEY = os.getenv("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")

# Initialize Groq LLM
llm = ChatGroq(model_name="mixtral-8x7b-32768", api_key=GROQ_API_KEY)

# Log storage
LOG_FILE = "scan_logs.txt"

# Function to execute a command and return output
def run_command(command):
    """Executes a system command and returns output."""
    try:
        print(f"Executing: {command}")
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            return {"status": "success", "output": result.stdout}
        else:
            return {"status": "error", "output": result.stderr}
    
    except Exception as e:
        return {"status": "failed", "output": str(e)}

# Function to handle retry logic
def handle_failure(task, attempt):
    """Retry a failed task with modifications if needed."""
    if attempt >= 2:  # Limit retries to 2 attempts
        return {"status": "failed", "output": "Max retries reached"}
    
    print(f"Retrying Task: {task['command']} (Attempt {attempt + 1})")
    
    # Modify parameters (e.g., change ports, use different wordlists)
    if "nmap" in task["command"]:
        task["command"] = task["command"].replace("-p-", "-p 80,443")
    
    elif "gobuster" in task["command"]:
        task["command"] = task["command"].replace("common.txt", "big.txt")

    return run_command(task["command"])

# Function to execute tasks sequentially
def execute_tasks(task_list):
    """Executes a list of security tasks with retries and logging."""
    logs = []
    
    for task in task_list:
        print(f"\n[ Task {task['step']} - {task['tool']} ]")
        attempt = 0
        result = run_command(task["command"])
        
        # Retry logic if failure occurs
        while result["status"] != "success" and attempt < 2:
            attempt += 1
            result = handle_failure(task, attempt)
        
        # Log result
        logs.append({"task": task, "result": result})
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps({"task": task, "result": result}) + "\n")
        
        time.sleep(2)  # Prevent aggressive scanning
    
    return logs

if __name__ == "__main__":
    # Example AI-generated task list
    task_list = [
    {"step": 1, "tool": "nmap", "command": "nmap -Pn -p- scanme.nmap.org"},
    {"step": 2, "tool": "gobuster", "command": "gobuster dir -u http://scanme.nmap.org -w common.txt"},
    {"step": 3, "tool": "sqlmap", "command": "sqlmap -u http://your-test-site.com/login.php --dbs"}
]
    
    logs = execute_tasks(task_list)
    print("\nExecution Completed! Logs stored in scan_logs.txt")
