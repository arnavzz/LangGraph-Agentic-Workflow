# LangGraph-Agentic-Workflow

This repository contains an **agentic cybersecurity pipeline** leveraging **LangGraph** and **LangChain** for automating security tasks. The system integrates well-known security tools like `nmap`, `gobuster`, `ffuf`, and `sqlmap`, enabling intelligent decision-making, scope enforcement, and failure handling.

## 🚀 System Architecture

The architecture follows an **agentic workflow** where multiple autonomous agents collaborate to perform cybersecurity scans, enforce scope limits, and handle task failures efficiently.

### 🔹 **Key Components:**
1. **Task Execution Agent** – Executes security commands (`nmap`, `gobuster`, etc.).
2. **Scope Enforcement Agent** – Ensures tasks are executed only within the defined security scope.
3. **Failure Handling Agent** – Detects execution failures and retries commands with adjusted parameters.
4. **Logging & Visualization** – Stores structured outputs and logs, visualized using **Streamlit**.

---

## 🛡️ **Agent Roles and Responsibilities**

| Agent Name                  | Role & Responsibility |
|-----------------------------|----------------------|
| **Task Execution Agent**     | Runs security tools and processes results. |
| **Scope Enforcement Agent**  | Prevents out-of-scope commands and enforces safety limits. |
| **Failure Handling Agent**   | Detects failures and retries tasks with adaptive strategies. |
| **Logging & Monitoring**     | Stores results and visualizes execution details. |

---

## 🔐 **Scope Enforcement Strategy**

To ensure ethical and controlled execution of security scans, **scope enforcement** is applied using:

✅ **Allowlist-based Targeting** – Only predefined domains/IPs can be scanned.  
✅ **Rate Limiting** – Restricts execution frequency to prevent abuse.  
✅ **Automatic Blocking** – Stops unauthorized actions from being executed.  
✅ **Logging & Alerts** – Any scope violations are logged and flagged for review.  

---

## ⚙️ **Setup & Execution Guide**

### **1️⃣ Prerequisites**
Ensure you have the following installed:

- **Python 3.9+**
- **FastAPI**
- **LangGraph & LangChain**
- **Pytest (for testing)**
- **Streamlit (for visualization)**
- **Security tools:** `nmap`, `gobuster`, `ffuf`, `sqlmap`

### **2️⃣ Installation**
Clone the repository and set up the environment:

```bash
git clone https://github.com/your-repo/LangGraph-Agentic-Workflow.git
cd LangGraph-Agentic-Workflow
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### **3️⃣ Running the Agentic Workflow**
Execute the main script:

```bash
python graph_agent.py 
```

### 4️⃣ Running Tests
Unit tests are implemented using pytest. Run:
```bash
pytest tests
```

### 5️⃣ Monitoring via Streamlit
To visualize execution logs :
```bash
streamlit run monitor.py
```


## 👥 **Contributions**
Contributions are welcome! Feel free to open an issue or submit a pull request.

---

📧 **Contact:** Arnav Khamparia | arnav.worko@gmail.com
📌 **License:** MIT  

