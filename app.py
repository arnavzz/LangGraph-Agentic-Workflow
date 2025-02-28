import os
import json
import time
import subprocess
import fnmatch
import re
import platform
import streamlit as st
from langchain_groq import ChatGroq
from langchain.schema import SystemMessage, HumanMessage
from dotenv import load_dotenv
from langgraph.graph import StateGraph, END
from typing import TypedDict, List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, TimeoutError as ThreadTimeoutError
from datetime import datetime

# Load environment variables
load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# Initialize Groq LLM
llm = ChatGroq(model_name="mixtral-8x7b-32768", api_key=GROQ_API_KEY)

# File to store logs
LOG_FILE = "scan_logs.txt"
ALLOWED_TARGETS = ["scanme.nmap.org"]

# Set wordlist directory based on user-provided path
WORDLIST_DIR = "C:\\Users\\share\\wordlists\\dirb\\"
DEFAULT_WORDLIST = "common.txt"

# Increased timeouts for security tools
COMMAND_TIMEOUT = 120  # Increased from 30 to 120 seconds
TASK_TIMEOUT = 300     # Increased from 60 to 300 seconds

st.set_page_config(page_title="Cybersecurity Scanner", layout="wide")

# ---- UI STYLING ----
st.markdown(
    """
    <style>
        .big-font { font-size:24px !important; font-weight: bold; }
        .success-text { color: #4CAF50; font-size: 18px; }
        .error-text { color: #FF5733; font-size: 18px; }
        .pending { color: #FFA500; }
        .running { color: #1E90FF; }
        .completed { color: #4CAF50; }
        .failed { color: #FF5733; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---- Task Validation ----
def validate_scope(target):
    """Check if the target is within the allowed scope, normalizing URLs."""
    if not target:
        return False
    normalized_target = re.sub(r'^https?://', '', target).split('/')[0].strip("'")
    for allowed in ALLOWED_TARGETS:
        if fnmatch.fnmatch(normalized_target, allowed):
            return True
    return False

# ---- Check Tool Availability ----
def check_tool_availability(tool):
    """Check if a tool is available on the system."""
    try:
        if platform.system() == "Windows":
            result = subprocess.run(f"where {tool}", shell=True, capture_output=True, text=True, timeout=5)
        else:
            result = subprocess.run(f"which {tool}", shell=True, capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False

# ---- Check Wordlist Existence ----
def check_wordlist(command):
    """Check if the wordlist exists, return adjusted command or error."""
    pattern = r"-w\s+([^\s]+)"
    match = re.search(pattern, command)
    if match:
        wordlist_path = match.group(1).strip('"\'')
        if not os.path.exists(wordlist_path):
            default_path = os.path.join(WORDLIST_DIR, DEFAULT_WORDLIST)
            if os.path.exists(default_path):
                command = re.sub(pattern, f"-w \"{default_path}\"", command)
                log_message(f"Wordlist replaced with default: {default_path}")
            else:
                return f"echo 'Wordlist {wordlist_path} not found and no default available'"
    return command

# ---- Task Execution ----
def run_command(command):
    """Executes a system command with enforced timeout."""
    try:
        # Don't execute actual commands if they're just echo error messages
        if command.startswith("echo"):
            return {"status": "error", "output": command[5:].strip("'")}
            
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            stdout, stderr = process.communicate(timeout=COMMAND_TIMEOUT)
            output = stdout if process.returncode == 0 else stderr
            output = ''.join(char if ord(char) < 128 else '?' for char in output)
            return {"status": "success" if process.returncode == 0 else "error", "output": output}
        except subprocess.TimeoutExpired:
            process.kill()
            return {"status": "failed", "output": f"Command timed out after {COMMAND_TIMEOUT} seconds"}
    except Exception as e:
        return {"status": "failed", "output": str(e)}

# ---- Handle Failure ----
def handle_failure(task, full_command):
    """Retry a failed task with modified parameters."""
    if "nmap" in full_command.lower():
        # Simplify nmap scan to avoid timeout
        simplified_command = re.sub(r"-p\s+\S+", "-p 22,80,443", full_command)
        simplified_command = simplified_command.replace("--script vuln", "")
        return run_command(simplified_command)
    elif "gobuster" in full_command.lower():
        # Reduce gobuster complexity
        simplified_command = re.sub(r"-x\s+\S+", "", full_command)
        return run_command(simplified_command)
    elif "ffuf" in full_command.lower():
        # Simplify ffuf scan
        if DEFAULT_WORDLIST != "common.txt":
            simplified_command = full_command.replace(os.path.join(WORDLIST_DIR, "common.txt"), 
                                                    os.path.join(WORDLIST_DIR, DEFAULT_WORDLIST))
        else:
            simplified_command = full_command
        return run_command(simplified_command)
    return run_command(full_command)

# ---- Replace Wordlist Path ----
def replace_wordlist_path(command):
    """Replace wordlist filename with full system-specific path."""
    pattern = r"-w\s+([^\s\"\']+|\"[^\"]+\"|\'[^\']+\')"
    match = re.search(pattern, command)
    if match:
        wordlist_file = match.group(1).strip('"\'')
        if not os.path.isabs(wordlist_file):
            # Create proper path based on OS
            if platform.system() == "Windows":
                full_path = os.path.join(WORDLIST_DIR, wordlist_file).replace("\\", "\\\\")
            else:
                full_path = os.path.join(WORDLIST_DIR, wordlist_file)
            
            # Replace the path with quotes to handle spaces
            command = re.sub(pattern, f'-w "{full_path}"', command)
            log_message(f"Wordlist path updated: {full_path}")
    return command

# ---- Construct Full Command ----
def construct_full_command(task):
    """Constructs the full command from tool and command fields."""
    if not task:
        return "echo 'Invalid task'"
        
    tool = task.get("tool", "").lower()
    command_args = task.get("command", "")
    target = task.get("target", "")

    tool_map = {
        "nmap": "nmap",
        "ffuf": "ffuf",
        "sqlmap": "sqlmap",
        "gobuster": "gobuster"
    }
    
    executable = tool_map.get(tool)
    if not executable:
        return f"echo 'Unknown tool: {tool}'"
    
    if not check_tool_availability(executable):
        return f"echo 'Tool {tool} not available on this system'"
    
    # Handle command construction based on tool
    if command_args.startswith(executable):
        full_command = command_args
    else:
        full_command = f"{executable} {command_args}".strip()

    # Special handling for nmap
    if tool == "nmap":
        # Ensure target is in command and replace -p- with limited port range
        if target and target not in full_command:
            full_command = full_command.replace("-p-", "-p 1-1000")
            full_command = f"{full_command} {target}".strip()

    # Special handling for directory scanning tools
    if tool in ["ffuf", "gobuster"]:
        full_command = replace_wordlist_path(full_command)
        full_command = check_wordlist(full_command)
    
    # Ensure FUZZ parameter is correctly set for ffuf
    if tool == "ffuf" and "FUZZ" not in full_command and "-u" in full_command:
        if not re.search(r"-u\s+\S*FUZZ", full_command):
            full_command = re.sub(r"-u\s+(\S+)", r"-u \1/FUZZ", full_command)
            log_message(f"Added FUZZ parameter to URL: {full_command}")

    return full_command

# ---- Enhanced Agent State ----
class AgentState(TypedDict):
    task_list: List[Dict[str, Any]]
    task_status: Dict[int, str]
    task_outputs: Dict[int, str]
    scope_violations: List[str]
    vulnerabilities: List[str]

# ---- Execute Single Task ----
def execute_single_task(task, state):
    """Executes a single task and updates state."""
    step = task.get("step", 0)
    target = task.get("target", "")
    full_command = construct_full_command(task)

    state["task_status"][step] = "Running"
    log_message(f"Starting task {step}: {full_command}")

    if not validate_scope(target) and not full_command.startswith("echo"):
        log_message(f"❌ [BLOCKED] {full_command} - OUT OF SCOPE")
        state["scope_violations"].append(f"Task {step}: {full_command} - Target {target} out of scope")
        state["task_status"][step] = "Failed"
        state["task_outputs"][step] = "Target out of scope"
        return

    result = run_command(full_command)
    # Retry once if failed with simplified parameters
    if result["status"] != "success":
        log_message(f"⚠️ [RETRY] {full_command} - Previous error: {result['output']}")
        result = handle_failure(task, full_command)

    # Truncate output to avoid excessive display
    truncated_output = result.get("output", "")[:1000]
    if len(result.get("output", "")) > 1000:
        truncated_output += "\n... (output truncated)"

    log_message(f"{'✅ [COMPLETED]' if result['status'] == 'success' else '❌ [FAILED]'} {full_command}")
    log_message(f"Output: {truncated_output}")

    state["task_status"][step] = "Completed" if result["status"] == "success" else "Failed"
    state["task_outputs"][step] = truncated_output

    # Analyze output for potential vulnerabilities
    if result["status"] == "success":
        if "open port" in truncated_output.lower() or "open tcp" in truncated_output.lower():
            state["vulnerabilities"].append(f"Task {step}: Open ports detected in {full_command}")
        if "directory found" in truncated_output.lower() or "status: 200" in truncated_output.lower():
            state["vulnerabilities"].append(f"Task {step}: Exposed directories in {full_command}")
        if "sql injection" in truncated_output.lower():
            state["vulnerabilities"].append(f"Task {step}: Potential SQL injection in {full_command}")

    # Adaptive task generation based on findings
    if result["status"] == "success" and ("open port" in truncated_output.lower() or "open tcp" in truncated_output.lower()):
        # Extract ports for targeted scanning
        port_matches = re.findall(r"(\d+)\/(?:tcp|udp)\s+open", truncated_output)
        if port_matches:
            ports = ",".join(port_matches[:5])  # Limit to first 5 ports to avoid timeout
            new_step = max(state["task_status"].keys(), default=0) + 1
            state["task_list"].append({
                "step": new_step,
                "tool": "nmap",
                "command": f"-Pn -A -p {ports} {target}",
                "target": target
            })
            state["task_status"][new_step] = "Pending"
            log_message(f"Created follow-up task for detected ports: {ports}")

# ---- Task Execution with Concurrency ----
def execute_task(state):
    """Executes tasks concurrently and updates state."""
    if not state.get("task_list") or len(state["task_list"]) == 0:
        log_message("No tasks to execute or all tasks completed")
        return state

    with ThreadPoolExecutor(max_workers=2) as executor:  # Reduced max_workers to avoid resource contention
        # Get pending tasks
        tasks_to_run = [task for task in state["task_list"] if state["task_status"].get(task["step"]) == "Pending"]
        
        # Remove tasks we're about to run from the list
        state["task_list"] = [task for task in state["task_list"] if task not in tasks_to_run]
        
        # Submit tasks to executor
        futures = {executor.submit(execute_single_task, task, state): task for task in tasks_to_run}
        
        try:
            for future in futures:
                future.result(timeout=TASK_TIMEOUT)
        except ThreadTimeoutError:
            for future in futures:
                if not future.done():
                    step = futures[future]["step"]
                    log_message(f"Task {step} timed out after {TASK_TIMEOUT} seconds")
                    state["task_status"][step] = "Failed"
                    state["task_outputs"][step] = "Task timed out"
        finally:
            executor.shutdown(wait=True)  # Changed to wait=True to ensure clean shutdown

    return state

# ---- Decision Logic ----
def should_continue(state):
    """Check if tasks are remaining."""
    pending = any(status == "Pending" for status in state["task_status"].values())
    running = any(status == "Running" for status in state["task_status"].values())
    if not pending and not running:
        log_message("All tasks completed or failed")
        return END
    return "execute_task"

# ---- Logging ----
def log_message(message):
    """Write logs to file efficiently."""
    try:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        safe_message = f"[{timestamp}] {''.join(char if ord(char) < 128 else '?' for char in message)}"
        with open(LOG_FILE, "a", encoding="utf-8", errors="replace") as f:
            f.write(safe_message + "\n")
    except Exception as e:
        st.error(f"Error writing to log file: {str(e)}")

# Generate task
def generate_tasks(instruction, target):
    """Uses Groq API to generate a task list."""
    
    system_prompt = (                                        # Prompt for clear instruction
        "You are a cybersecurity AI. Generate a structured task list in JSON format as a list of dictionaries. "
        "Each dictionary should contain 'step' (int), 'tool' (str), 'command' (str), and 'target' (str). "
        "The 'command' field should only include the arguments/options, not the tool name (e.g., '-p 1-1000 -sV' for nmap). "
        "For gobuster, 'command' should include the type and options (e.g., 'dir -u http://example.com -w common.txt'). "
        "For ffuf, ensure '-u' includes 'FUZZ' (e.g., '-u http://example.com/FUZZ') when appropriate. "
        "Consider the following constraints:\n"
        "1. Keep scans lightweight to avoid timeouts (scan fewer ports, use smaller wordlists)\n"
        "2. For nmap use -p 80,443,22,8080,8443 instead of -p-\n"
        "3. Use only 'common.txt' for wordlists\n"
        "4. Avoid CPU-intensive operations\n"
        "5. Use ONLY the following tools: nmap, ffuf, gobuster, sqlmap\n"
        "6. Limit to 2-3 tasks maximum"
    )
    user_prompt = f"Instruction: {instruction}\nTarget: {target}\nGenerate structured security tasks."

    if not GROQ_API_KEY:
        st.warning("GROQ_API_KEY not found. Using default task.")
        return [{"step": 1, "tool": "nmap", "command": f"-Pn -p 80,443 {target}", "target": target}]

    try:
        response = llm.invoke([SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)])
        log_message(f"Raw API response: {response.content}")
        
        # Extract JSON from response (in case there's additional text)
        json_match = re.search(r'\[.*\]', response.content, re.DOTALL)
        if json_match:
            json_content = json_match.group(0)
        else:
            json_content = response.content
            
        task_list = json.loads(json_content)
        
        if not isinstance(task_list, list) or len(task_list) == 0:
            raise ValueError("Invalid or empty task list")
        
        # Validate tasks
        for task in task_list:
            if not all(key in task for key in ["step", "tool", "command", "target"]):
                raise ValueError(f"Invalid task format: {task}")
            if task["tool"].lower() not in ["nmap", "ffuf", "sqlmap", "gobuster"]:
                raise ValueError(f"Unsupported tool: {task['tool']}")
            
           
            task["step"] = int(task["step"])
        
        # Sort tasks by step
        task_list.sort(key=lambda x: x["step"])
        
        
        for i, task in enumerate(task_list):
            task["step"] = i + 1
        
        return task_list
    except Exception as e:
        st.error(f"Task generation error: {str(e)}")
        log_message(f"Task generation error: {str(e)}")
        # Fallback to simple task
        return [{"step": 1, "tool": "nmap", "command": f"-Pn -p 80,443 {target}", "target": target}]

# UI for streamlit 
st.title("🔍 Cybersecurity Scanner Dashboard")
st.sidebar.header("⚙️ Scanner Settings")

# User Inputs
target = st.sidebar.text_input("Enter Target Domain", "scanme.nmap.org")
instruction = st.sidebar.text_area("Task Instruction", "Scan for open ports and directories")

# Add more configuration options
with st.sidebar.expander("Advanced Settings"):
    command_timeout = st.slider("Command Timeout (seconds)", 30, 300, COMMAND_TIMEOUT)
    task_timeout = st.slider("Task Timeout (seconds)", 60, 600, TASK_TIMEOUT)
    wordlist_path = st.text_input("Wordlist Directory", WORDLIST_DIR)
    
    if wordlist_path and os.path.exists(wordlist_path):
        WORDLIST_DIR = wordlist_path

start_scan = st.sidebar.button("🚀 Start Scan")

# 
if "agent_state" not in st.session_state:
    st.session_state.agent_state = {
        "task_list": [],
        "task_status": {},
        "task_outputs": {},
        "scope_violations": [],
        "vulnerabilities": []
    }

# Create LOG_FILE if it doesn't exist
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write("--- Scanner Log Started ---\n")

# Graph Setup
graph = StateGraph(AgentState)
graph.add_node("execute_task", execute_task)
graph.set_entry_point("execute_task")
graph.add_conditional_edges("execute_task", should_continue)
agent = graph.compile()

# RUN SCAN
if start_scan:
    if not validate_scope(target):
        st.error("🚫 Target is OUT OF SCOPE!")
        st.session_state.agent_state["scope_violations"].append(f"Target {target} out of scope")
    else:
        st.success(f"✅ Scan Started for {target}!")
        task_list = generate_tasks(instruction, target)
        
        if task_list and len(task_list) > 0:
            # Update global timeouts from UI that takes user input
            COMMAND_TIMEOUT = command_timeout
            TASK_TIMEOUT = task_timeout
            
            
            st.session_state.agent_state["task_list"] = task_list
            st.session_state.agent_state["task_status"] = {task["step"]: "Pending" for task in task_list}
            st.session_state.agent_state["task_outputs"] = {}
            st.session_state.agent_state["scope_violations"] = []
            st.session_state.agent_state["vulnerabilities"] = []
            
            with st.spinner("Executing security scan..."):
                start_time = time.time()
                try:
                    agent.invoke(st.session_state.agent_state)
                    duration = time.time() - start_time
                    st.success(f"Scan completed in {duration:.2f} seconds!")
                except Exception as e:
                    st.error(f"Error during scan execution: {str(e)}")
                    log_message(f"Scan execution error: {str(e)}")
        else:
            st.error("No valid tasks were generated.")

#  Real-Time Task List Visualization 
st.subheader("📋 Dynamic Task List")
if st.session_state.agent_state["task_status"]:
    task_data = []
    for step, status in sorted(st.session_state.agent_state["task_status"].items()):
        # Find task info in task_list
        task_info = next((t for t in st.session_state.agent_state["task_list"] if t.get("step") == step), None)
        
        if not task_info:
            
            command = "N/A"
            tool = "unknown"
        else:
            tool = task_info.get("tool", "unknown")
            command = construct_full_command(task_info)
            
        output = st.session_state.agent_state["task_outputs"].get(step, "N/A")
        output_preview = output[:100] + "..." if len(output) > 100 else output
        
        task_data.append({
            "Step": step, 
            "Tool": tool,
            "Command": command, 
            "Status": status, 
            "Output": output_preview
        })
    
    st.dataframe(task_data, use_container_width=True, column_config={
        "Status": st.column_config.TextColumn("Status", help="Task status: Pending, Running, Completed, Failed")
    })

#  Dashboard 
st.subheader("📊 Scan Progress")
logs = []
try:
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
            logs = f.readlines()
except Exception:
    logs = ["Error reading logs"]

completed_tasks = len([log for log in logs if "[COMPLETED]" in log])
blocked_tasks = len([log for log in logs if "[BLOCKED]" in log])
failed_tasks = len([log for log in logs if "[FAILED]" in log or "Task timed out" in log])

col1, col2, col3 = st.columns(3)
with col1:
    st.metric(label="✅ Completed Tasks", value=completed_tasks)
with col2:
    st.metric(label="⛔ Blocked Tasks", value=blocked_tasks)
with col3:
    st.metric(label="❌ Failed Tasks", value=failed_tasks)

# Task Logs 
st.subheader("📜 Task Logs")
st.text_area("Execution Logs", "\n".join(logs[-20:]) if logs else "No logs available", height=300)

#  Final Audit Report 
st.subheader("📑 Final Audit Report")
if st.session_state.agent_state["task_status"]:
    st.write(f"**Scan Target:** {target}")
    st.write(f"**Scan Instruction:** {instruction}")
    st.write(f"**Total Tasks:** {len(st.session_state.agent_state['task_status'])}")
    st.write(f"**Completed:** {sum(1 for s in st.session_state.agent_state['task_status'].values() if s == 'Completed')}")
    st.write(f"**Failed:** {sum(1 for s in st.session_state.agent_state['task_status'].values() if s == 'Failed')}")
    
    if st.session_state.agent_state["vulnerabilities"]:
        st.write("### Vulnerabilities Detected")
        for vuln in st.session_state.agent_state["vulnerabilities"]:
            st.markdown(f"- <span class='error-text'>{vuln}</span>", unsafe_allow_html=True)
    else:
        st.write("No vulnerabilities detected.")

    if st.session_state.agent_state["scope_violations"]:
        st.write("### Scope Violations")
        for violation in st.session_state.agent_state["scope_violations"]:
            st.markdown(f"- <span class='error-text'>{violation}</span>", unsafe_allow_html=True)
    else:
        st.write("No scope violations detected.")

# Clear logs button
col1, col2 = st.columns(2)
with col1:
    if st.button("Clear Logs"):
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            f.write("--- Logs Cleared ---\n")
        st.session_state.agent_state = {
            "task_list": [],
            "task_status": {},
            "task_outputs": {},
            "scope_violations": [],
            "vulnerabilities": []
        }
        st.success("Logs and state cleared successfully!")
        st.experimental_rerun()

with col2:
    if st.button("Download Logs"):
        log_content = ""
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
                log_content = f.read()
        
        st.download_button(
            label="Download Log File",
            data=log_content,
            file_name="security_scan_logs.txt",
            mime="text/plain"
        )

st.markdown("---")
st.markdown('<p class="big-font">Cybersecurity Scanner - Powered by AI</p>', unsafe_allow_html=True)