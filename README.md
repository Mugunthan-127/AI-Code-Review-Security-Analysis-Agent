# AI Code Review & Security Analysis Agent

![Agent Preview](https://via.placeholder.com/1200x600.png?text=AI+Code+Review+Agent)

## 🚀 Overview
The **AI Code Review & Security Analysis Agent** is a sophisticated, multi-agent platform designed to act as an automated DevSecOps pipeline. It analyzes Java and Python code in real-time, detecting security vulnerabilities, code quality issues, and architectural flaws. 

By leveraging parallel AI agents (via **LangGraph**) and a built-in Knowledge Base (via **ChromaDB**), it grounds its security findings in official OWASP and CERT standards, ensuring the AI's recommendations are accurate, actionable, and free of hallucinations.

---

## 🛠️ Complete Tech Stack

### Frontend
- **Framework:** React.js powered by Vite for lightning-fast hot reloading.
- **Code Editor:** `@monaco-editor/react` (the engine behind VS Code) for syntax highlighting, line numbers, and a native IDE feel.
- **Styling:** Custom Vanilla CSS utilizing CSS Grid/Flexbox for a responsive, dark-mode, glassmorphic UI.

### Backend & Orchestration
- **API Framework:** FastAPI (Python) for high-performance, async API endpoints.
- **Orchestration:** LangGraph (State graph orchestration) to manage the parallel execution of multiple specialized AI agents.
- **LLM Integration:** LangChain (`langchain-groq`) to interface with LLMs (Llama-3) for ultra-fast inference and complex reasoning.
- **Static Analysis (Fallback):** Semgrep / SpotBugs integrations wrapped in LLM fallbacks for analyzing uncompiled or incomplete code snippets.

### Database & RAG (Retrieval-Augmented Generation)
- **Relational DB:** SQLite (managed via SQLAlchemy ORM) for storing scan history, findings, and metadata.
- **Vector DB:** ChromaDB for storing embedded security guidelines, OWASP documents, and secure coding practices.
- **Embeddings & Re-ranking:** HuggingFace `sentence-transformers`. Specifically uses a **Cross-Encoder** (`ms-marco-MiniLM-L-6-v2`) to mathematically re-rank vector search results, ensuring the AI only receives highly relevant context.

---

## ✨ Core Capabilities

1. **Instant Code Triage:** Paste raw, uncompiled code snippets and get an immediate breakdown of security and quality flaws without needing a full build environment.
2. **Multi-Agent Cross-Checking:** The system uses different agents for different tasks. The Code Quality agent focuses on logical bugs, while the Security agent focuses on vulnerabilities. They execute entirely in parallel.
3. **Accurate Risk Scoring:** Dynamically grades the severity of the code based on the types of vulnerabilities found (Critical, High, Medium, Low).
4. **Interactive Knowledge Base (KB Tester):** The built-in KB Tester allows developers to manually query the system's internal vector database to learn about vulnerabilities and see exactly what documentation the AI relies on.
5. **Historical Tracking:** Every scan is saved to the SQLite database. The "History" tab allows developers to view past analyses, making it easy to track improvements over time.
6. **Code Snippet Fixes:** Instead of just saying "You have SQL Injection", the app provides the exact rewritten code (e.g., how to use a `PreparedStatement` or parameterized query) to immediately resolve the issue.

---

## 🔄 The Architecture & Workflow

1. **Ingestion & Auto-Detection:** The user pastes code or uploads a file (.py or .java) in the React frontend. The FastAPI backend auto-detects the language.
2. **Parallel Agent Execution:** The code is passed into the LangGraph state machine, which forks into multiple parallel agents (Security, Quality, Complexity).
3. **RAG Context Enrichment:** If the Security Agent flags a potential vulnerability, it queries **ChromaDB** to find relevant security documents (e.g., OWASP A03 Injection guidelines). A **Cross-Encoder** re-ranks the chunks, and the highly-relevant security knowledge is injected into a final LLM prompt.
4. **Aggregation & PR Summary:** A final Orchestrator merges the findings, calculates a Risk Score, and generates a structured Pull Request (PR) style summary.
5. **Frontend Rendering:** The React UI renders a dynamic summary banner and individual Finding Cards pinpointing the exact lines of code with suggested fixes.

---

## 📦 Setup & Installation

### Prerequisites
- Python 3.10+
- Node.js 18+
- A Groq API Key (for LLM inference)

### Backend Setup
1. Navigate to the backend directory:
   ```bash
   cd backend
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Set your environment variables (create a `.env` file):
   ```env
   GROQ_API_KEY=your_groq_api_key_here
   ```
4. Start the FastAPI server:
   ```bash
   uvicorn main:app --reload --host 127.0.0.1 --port 8000
   ```

### Frontend Setup
1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Start the Vite development server:
   ```bash
   npm run dev
   ```

The application will be available at `http://localhost:5173`.
