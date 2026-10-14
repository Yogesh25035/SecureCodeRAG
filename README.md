# SecureCodeRAG — Secure Code Review & Defect Analysis Assistant

SecureCodeRAG is an end-to-end automotive and C/C++ secure-code review platform. It combines a React reviewer interface, FastAPI services, deterministic static analysis, project-aware retrieval-augmented generation (RAG), local Ollama inference, reviewer decisions, audit logging, and compliance report export.

---

## 1. Project Overview & Current Architecture

### Key Capabilities
- **Hybrid Analysis Pipeline**: Fast deterministic static detection (AST analysis, regular expression rules, Cppcheck integration) coupled with LLM reasoning.
- **Evidence-Grounded AI Explanations**: The configured LLM (`qwen2.5-coder:3b` in the current local setup) explains findings, identifies root causes, and recommends fixes without overriding deterministic findings or altering severity.
- **Project-Aware RAG**: Separate FAISS namespaces store the curated knowledge base and (when a project is uploaded) that project's accepted C/C++ source files using `nomic-embed-text` embeddings.
- **Reviewer Workflow**: Interactive Accept / Edit / Reject controls for security engineers with complete SQLite persistence.
- **Audit Trails & Export**: Tamper-evident audit logging with downloadable HTML and JSON compliance reports.

### Architecture Diagram
```
┌─────────────────────────────────────────────────────────────┐
│                      React 19 Frontend                      │
│        (Vite + TypeScript + Tailwind-free Vanilla CSS)      │
│                     http://localhost:5173                   │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTP / JSON
┌──────────────────────────────▼──────────────────────────────┐
│                     FastAPI Backend                         │
│                     http://localhost:8000                   │
│                                                             │
│  ┌────────────────────┐   ┌───────────────────────────────┐ │
│  │ Deterministic Scan │   │  RAG Retriever (FAISS)        │ │
│  │ (Cppcheck + AST)   │   │  - Knowledge base guidelines  │ │
│  └─────────┬──────────┘   │  - Uploaded repository code   │ │
│            │              └───────────────┬───────────────┘ │
│            └──────────────┬───────────────┘                 │
│                           ▼                                 │
│             ┌───────────────────────────┐                   │
│             │ Generator & Guardrails    │                   │
│             └─────────────┬─────────────┘                   │
└───────────────────────────┼─────────────────────────────────┘
                            │ http://host.docker.internal:11434
┌───────────────────────────▼─────────────────────────────────┐
│              Local Ollama Service (Windows Host)             │
│  - qwen2.5-coder:3b (Reasoning & Explanations)              │
│  - nomic-embed-text (Vector Embeddings)                     │
└─────────────────────────────────────────────────────────────┘
```

### Analysis and RAG Flow

1. A C/C++ request is checked by the deterministic scanner and Cppcheck. Compiler/build-log warnings can also be parsed through the build-log endpoint.
2. Cppcheck XML diagnostics are normalized into findings containing the rule, mapped category, severity, file, line, source line, and diagnostic message.
3. For each finding, the analysis endpoint builds a RAG query from:
   `category + flagged source line + diagnostic description`.
4. The retriever expands that query with secure-coding guidance wording, embeds it with `nomic-embed-text`, and searches the global knowledge FAISS index plus the project namespace when `project_id` is available.
5. The flagged line and its surrounding function/code context are collected separately. The LLM receives that code context, the authoritative finding fields, and the retrieved supporting documents.
6. The generator is explanatory only: deterministic category, severity, file, and line data remain authoritative. If the LLM is unavailable or its output fails validation, a deterministic fallback explanation is returned.

### Repository Ingestion and FAISS Documents

Repository uploads are handled by the repository API and receive a UUID-backed project namespace:

- The uploaded ZIP archive must be no larger than **50 MB**.
- Only `.c`, `.cpp`, `.h`, and `.hpp` files are ingested.
- Individual source/header files larger than **5 MB** are skipped.
- `.git`, `node_modules`, `build`, `dist`, `venv`, `__pycache__`, `binaries`, and directories containing `generated` in their name are skipped.
- Duplicate file contents are removed using a content hash. Files containing null bytes or invalid UTF-8 are skipped.
- Each accepted file is stored in the project FAISS index as one **whole-file document**. Each detected function is also stored as an additional function-level document.
- Project source files are not split into fixed-size character/token chunks today. Very large accepted files therefore remain single large embedding inputs.
- The FAISS index stores documents; retrieval does not send the entire project to the LLM. It returns only the most similar documents for the current finding.

The curated knowledge namespace indexes supported `.txt`, `.md`, `.csv`, and `.json` files under `backend/app/data/`. Project and knowledge indexes are persisted beneath the configured `VECTORSTORE_PATH`.

### Main Components

| Layer | Current implementation | Responsibility |
|---|---|---|
| Web UI | React 19, Vite, TypeScript, CSS | Authentication, code/repository submission, findings display, review actions, and report access |
| API | FastAPI | Authentication, analysis, repository ingestion, build-log upload, review, reporting, and health endpoints |
| Deterministic analysis | Static scanner, parser, Cppcheck, compiler-log parser | Produces the authoritative finding type/category, severity, file, line, and diagnostic evidence |
| Repository processing | Repository manager and C/C++ parser | Filters, validates, deduplicates, and extracts includes, functions, calls, and structural metadata |
| Retrieval | LangChain FAISS plus Ollama embeddings | Searches curated guidance and optional project-specific code context |
| Generation | Configured Ollama/Gemini/dummy provider | Produces constrained explanations; it does not replace deterministic analysis |
| Persistence | SQLite, FAISS local files, repository storage | Stores findings, users, audit events, vectors, and uploaded repository content |
| Output | JSON and HTML report generators | Combines findings, review state, audit history, and RAG source metadata into exportable reports |

### Backend API Surface

- `POST /api/auth/token` and `GET /api/auth/me`: login and current-user information.
- `POST /api/analyze`: analyze submitted C/C++ code, optionally scoped to a project.
- `POST /api/repositories/upload`: upload, extract, ingest, and index a repository ZIP.
- `POST /api/repositories/ingest`: ingest a repository path available to the backend.
- `POST /api/build-log/upload`: parse compiler/build logs and optionally associate them with a project.
- `/api/review/*`: retrieve findings and accept, reject, or edit review decisions.
- `GET /api/reports/{project_id}`: generate JSON or HTML project reports.
- `GET /health`: backend health check.

### Finding and Review Lifecycle

1. A user authenticates and submits code, a repository, or a build log.
2. The backend runs deterministic analyzers and normalizes all diagnostics into findings.
3. Findings are deduplicated, associated with functions where possible, and enriched with local code context.
4. RAG retrieves supporting guidance and project context. The configured LLM generates a bounded explanation with an evidence status.
5. The finding and analysis audit event are persisted in SQLite.
6. A reviewer can accept, reject, or edit the finding. Review changes are recorded in the audit trail.
7. Reports combine project information, findings, review state, explanations, confidence, and available RAG references.

The LLM is an assistant layer, not the security authority: deterministic analyzer output remains authoritative, and unavailable or invalid AI output falls back to a static explanation.

---

## 2. Prerequisites for Windows

Before starting, ensure the following software is installed on Windows:

1. **Docker Desktop for Windows**:
   - Download: [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/)
   - Ensure WSL 2 backend is enabled in Docker Desktop Settings.
2. **Ollama for Windows**:
   - Download: [ollama.com/download](https://ollama.com/download)
   - Ensure Ollama is running (check the llama icon in the Windows taskbar).
3. *(Optional - for running directly on host without Docker)*:
   - Python 3.11+
   - Node.js 18+ (LTS)
   - Cppcheck (`winget install Cppcheck.Cppcheck` or from source)

---

## 3. Required Ollama Models & Download

Open PowerShell or Windows Terminal and pull the required models:

```powershell
# 1. Pull the reasoning model used by the current local setup
ollama pull qwen2.5-coder:3b

# 2. Pull the embedding model (Nomic Embed Text)
ollama pull nomic-embed-text
```

Verify that both models are installed:
```powershell
ollama list
```
You should see `qwen2.5-coder:3b` and `nomic-embed-text` listed.

---

## 4. Environment Configuration

The application reads settings from `backend/.env`.

A prepared `.env` file is included in `backend/.env`. If missing, copy it from `.env.example`:
```powershell
# In PowerShell (from project root):
Copy-Item .env.example backend\.env
```

### Key Settings Explained
| Variable | Default Value | Description |
|---|---|---|
| `LLM_PROVIDER` | `ollama` | Inference engine (`ollama`, `gemini`, or `dummy`) |
| `LLM_MODEL` | `qwen2.5-coder:3b` | Configured LLM model name for the current Ollama setup |
| `OLLAMA_BASE_URL` | `http://host.docker.internal:11434` | Ollama endpoint accessible from Docker |
| `OLLAMA_EMBED_MODEL`| `nomic-embed-text` | Embedding model for FAISS vector search |
| `VECTORSTORE_PATH` | `vectorstore` | Relative path to vector storage directory |
| `TOP_K` | `4` | Default retriever limit; the code-analysis endpoint currently requests 2 documents from each FAISS namespace |

> **Note for Docker users:** Inside Docker containers on Windows, `http://host.docker.internal:11434` resolves to the Ollama service running on your Windows host. If running the backend directly on Windows (outside Docker), set `OLLAMA_BASE_URL=http://localhost:11434`.

---

## 5. Starting & Stopping the Project

### Option A: Using Docker Compose (Recommended)

1. **Build and start all services:**
   ```powershell
   docker compose up --build
   ```
   Add `-d` to run in detached (background) mode:
   ```powershell
   docker compose up -d
   ```

2. **Check container logs:**
   ```powershell
   docker compose logs -f
   ```

3. **Stop the services:**
   ```powershell
   docker compose down
   ```

### Option B: Running Locally on Windows (Without Docker)

1. **Start Backend:**
   ```powershell
   cd backend
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
   ```

2. **Start Frontend:**
   ```powershell
   cd frontend
   npm install
   npm run dev
   ```

---

## 6. Accessing the Application & Default Accounts

Once the containers are up:

| Interface | URL | Description |
|---|---|---|
| **Frontend Web UI** | [http://localhost:5173](http://localhost:5173) | Interactive reviewer dashboard & scan upload |
| **Backend API Docs** | [http://localhost:8000/docs](http://localhost:8000/docs) | Interactive OpenAPI / Swagger interface |
| **Health Check** | [http://localhost:8000/api/health](http://localhost:8000/api/health) | System health & status check |

### Default Development Accounts
The system initializes with preconfigured demo accounts for local role testing:

| Username | Password | Role | Permissions |
|---|---|---|---|
| `admin` | `admin123` | `ADMIN` | Full administrative access across all projects |
| `reviewer`| `review123` | `REVIEWER` | Reviewer workflow (Accept, Edit, Reject findings) |
| `dev` | `dev123` | `DEVELOPER` | Scan submission and finding inspection |

---

## 7. How to Test Code Analysis

1. Log into the frontend at [http://localhost:5173](http://localhost:5173) using `admin` / `admin123`.
2. Upload a C/C++ repository ZIP archive (the archive must be 50 MB or smaller).
3. The dashboard executes:
   - Repository ingestion with C/C++ file filtering, duplicate detection, and project FAISS indexing
   - Deterministic rule scanning and repository-aware Cppcheck analysis
   - RAG retrieval using the finding category, flagged source line, and diagnostic message
   - Context-grounded LLM inference via the configured model
4. Review detected findings, examine AI explanations and MISRA references, and use the **Accept**, **Edit**, or **Reject** actions to record review decisions.
5. Generate compliance reports in JSON or formatted HTML format.

---

## 8. Troubleshooting

### 1. Backend cannot connect to Ollama (`Connection Refused`)
- Ensure Ollama is running in Windows: open PowerShell and test `curl http://localhost:11434`.
- If Docker fails to resolve `host.docker.internal`, check that Docker Desktop has `extra_hosts: ["host.docker.internal:host-gateway"]` in `docker-compose.yml` (already configured).
- If Windows Firewall blocks Docker traffic to port 11434, set the environment variable `OLLAMA_HOST=0.0.0.0:11434` in Windows and restart Ollama.

### 2. Slow Inference / Model Out of Memory
- `qwen2.5-coder:3b` is a lightweight local model suitable for development and modest hardware. If you configure a different model through `LLM_MODEL`, adjust GPU/RAM allocation accordingly.
- To inspect Ollama resource usage: run `ollama ps` in PowerShell.
- Ensure Docker Desktop is allocated sufficient memory (WSL 2 memory limit in `.wslconfig`).

### 3. Port Conflicts (`Port 5173` or `Port 8000` already in use)
- Identify the process occupying the port:
  ```powershell
  Get-Process -Id (Get-NetTCPConnection -LocalPort 5173).OwningProcess
  ```
- Either stop the conflicting process or change the host port mappings in `docker-compose.yml`.

### 4. Database Reset
- If you wish to reset review history and start clean: delete `backend/data/review.db`. A clean database with all required tables will be regenerated automatically on the next startup.