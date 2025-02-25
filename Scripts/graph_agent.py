import os
import json
import time
import subprocess
import fnmatch
from langchain_groq import ChatGroq
from langchain.schema import SystemMessage, HumanMessage
from dotenv import load_dotenv
from langgraph.graph import StateGraph, END
from typing import TypedDict, List, Dict, Any

# Load environment variables
load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")  # Use a generic variable name

# Initialize Groq LLM
llm = ChatGroq(model_name="mixtral-8x7b-32768", api_key=GROQ_API_KEY)

# Logging setup
LOG_FILE = "scan_logs.txt"

ALLOWED_TARGETS = [
    "scanme.nmap.org",  # ✅ Explicitly allowing this domain
]

def validate_scope(target):
    """Check if the target is within the allowed scope (with debugging)."""
    print(f"[DEBUG] Checking scope for: '{target}'")  # Ensuring target is not empty
    print(f"[DEBUG] Allowed Targets: {ALLOWED_TARGETS}")
    
    for allowed in ALLOWED_TARGETS:
        print(f"[DEBUG] Checking against: {allowed}")
        if fnmatch.fnmatch(target, allowed):
            print(f"[DEBUG] ✅ Target {target} is ALLOWED.")
            return True
    
    print(f"[DEBUG] ❌ Target {target} is BLOCKED.")
    return False

class AgentState(TypedDict):
    task_list: List[Dict[str, Any]]

# Function to log messages
def run_command(command):
    """Executes a system command and returns output."""
    try:
        print(f"Executing: {command}")
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=120)
        
        if result.returncode == 0:
            return {"status": "success", "output": result.stdout}
        else:
            return {"status": "error", "output": result.stderr}
    
    except Exception as e:
        return {"status": "failed", "output": str(e)}

# Function to handle failed execution
def handle_failure(task, attempt):
    """Retry a failed task with modified parameters."""
    if attempt >= 2:  # Limit retries
        return {"status": "failed", "output": "Max retries reached"}

    print(f"Retrying Task: {task['command']} (Attempt {attempt + 1})")

    # Modify parameters for retry
    if "nmap" in task["command"]:
        task["command"] = task["command"].replace("-p-", "-p 80,443")
    
    elif "gobuster" in task["command"]:
        task["command"] = task["command"].replace("common.txt", "big.txt")

    return run_command(task["command"])

# Task execution function
def execute_task(state):
    """Executes the current task if it's within scope."""
    task = state["task_list"].pop(0)  # Get first task
    target = task.get("target", "")

    print(f"[DEBUG] Extracted Target: '{target}'")  # Debugging extracted target

    if not target:
        print("[ERROR] ❌ Target is missing from the task! Skipping execution.")
        return state  # Skip execution if target is missing

    if not validate_scope(target):
        print(f"[BLOCKED] Task '{task['command']}' was skipped (Out of scope).")
        return state  # Skip execution

    attempt = 0
    result = run_command(task["command"])
    
    while result["status"] != "success" and attempt < 2:  # Retry on failure
        attempt += 1
        result = handle_failure(task, attempt)

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps({"task": task, "result": result}) + "\n")

    # Dynamically modify task list based on results
    if "open port" in result["output"].lower():
        state["task_list"].append({
            "step": len(state["task_list"]) + 1,
            "tool": "nmap",
            "command": f"nmap -Pn -A {task['target']}", 
            "target": task["target"]
        })

    time.sleep(2)  # Time to wait between scanning to prevent aggressive scanning
    return state

# Function to determine next step
def should_continue(state):
    """Decides whether to continue or stop based on tasks remaining."""
    return "execute_task" if state["task_list"] else END

# Define LangGraph workflow
graph = StateGraph(AgentState)
graph.add_node("execute_task", execute_task)
graph.set_entry_point("execute_task")
graph.add_conditional_edges("execute_task", should_continue)

agent = graph.compile()

# Function to generate tasks using Groq AI
def generate_tasks(instruction, target):
    """Uses Groq API to generate a cybersecurity task list."""
    system_prompt = """
    You are an AI security expert. Given a user request, generate a structured list of security tasks 
    (port scanning, directory fuzzing, vulnerability scanning) in JSON format.
    """

    user_prompt = f"Instruction: {instruction}\nTarget: {target}\n\nGenerate structured task list."

    response = llm.invoke([SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)])

    try:
        task_list = json.loads(response.content)  # Parse AI response
    except:
        task_list = [{"step": 1, "tool": "nmap", "command": f"nmap -Pn -p- {target}", "target": target}]

    # ✅ Ensure every task includes a target
    for task in task_list:
        if "target" not in task:
            task["target"] = target  # Manually add target if missing

    print(f"[DEBUG] Generated Task List: {task_list}")  # Debug generated tasks
    return task_list

if __name__ == "__main__":
    instruction = "Scan example.com for open ports and directories"
    target = "scanme.nmap.org"
    
    # Generate initial task list
    task_list = generate_tasks(instruction, target)

    print(f"[DEBUG] Final Task List Before Execution: {task_list}")  # Debug before execution
    
    # Run LangGraph-based agent
    agent.invoke({"task_list": task_list})
    print("\nExecution Completed! Logs stored in scan_logs.txt")
