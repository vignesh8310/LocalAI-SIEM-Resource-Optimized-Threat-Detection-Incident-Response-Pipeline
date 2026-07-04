# LocalAI-SIEM-Resource-Optimized-Threat-Detection-Incident-Response-Pipeline
A local AI-powered SIEM pipeline built in Python. Uses a high-speed regex filter to drop network noise before routing anomalies to a quantized local LLM (llama3.2:3b) via Ollama for threat verification. Features persistent SQLite storage and a RAG forensic engine accessible via an interactive Discord SOC bot.

---

## 🏗️ Software Architecture & Design

### 1. Ingestion & Pre-Filtering
* **Dynamic File Tail-ing:** Monitors target operating system log streams via low-overhead file pointer shifts (`file.seek`).
* **Deterministic Filtering:** Screens strings with a pre-compiled `re.compile` regular expression engine to drop normal traffic, shielding local GPU VRAM from processing fatigue.

### 2. Cognitive Analysis (Edge AI Engine)
* **Local Inference Core:** Leverages a locally hosted `llama3.2:3b` instance to evaluate anomalies without paid SaaS APIs or cloud network dependencies.
* **Structured Outputs:** Enforces strict system prompting rules to guarantee pure, structural JSON token returns, enabling automated downstream pipeline processing.

### 3. Forensic Persistence & RAG (Retrieval-Augmented Generation)
* **Data Tier:** Saves verified security alerts into an optimized local SQLite schema (`siem_history.db`).
* **Contextual Injection:** Dynamically filters, aggregates, and injects historical database telemetry rows directly into active LLM prompt memory buffers to allow context-aware operational review.

---

## 📦 Project Structure

* `siem_shipper.py` — **Autonomous Alerting Agent:** Connects the dynamic file tail engine directly to the AI core and pushes formatted rich embed notification cards via an outbound Discord Webhook payload.
* `soc_bot.py` — **Interactive Security Assistant:** Runs a concurrent multi-threaded environment. Spawns a background worker thread for log ingestion while keeping the main thread open to listen for interactive chat commands via the Asynchronous Discord Bot API.

---

## 🤖 Interactive SOC Commands (`soc_bot.py`)
Type these commands directly inside your connected Discord server text channel to query the agent:

* `!summary` - Extracts historical database logs, loading them into an edge-AI context block to generate an executive system overview brief.
* `!investigate <IP/User>` - Executes a targeted SQL `LIKE` wildcard search to pull threat footprints and compile an automated deep forensic timeline report.
* `!fix <Threat>` - Consults the local intelligence core to generate an immediate, bulleted technical Incident Response playbook.
* `!lookup <IP>` - Integrates outbound threat intelligence web hooks to run open-source geolocation infrastructure audits.
* `!metrics` - Performs real-time mathematical counting directly inside the SQLite database to return recent threat numbers.

---

## 💡 Key Architectural Highlights
* **100% Data Privacy & Zero Cost:** Operates strictly on internal localhost environments.
* **Failure Prevention Safety Net:** Implements packet slicing loops to break long AI outputs into clean 1900-character string arrays, fully bypassing Discord's native 2000-character transmission threshold.
* **Low Hardware Footprint:** Tailored resource boundaries optimized to run smoothly on consumer-grade 4GB VRAM hardware (Laptop RTX 2050 target configuration).



### Live System Alerts

<img width="1469" height="1017" alt="Screenshot (309)" src="https://github.com/user-attachments/assets/d3169a55-2244-436b-ad8d-7ff176cd3048" />

---


### Interactive Query Interface

<img width="1454" height="1021" alt="Screenshot (312)" src="https://github.com/user-attachments/assets/832d08e8-fc12-47f1-894b-a31c92e2d741" />
<img width="1432" height="587" alt="Screenshot 2026-07-04 111908" src="https://github.com/user-attachments/assets/cc84c9fd-422c-445a-b345-7cad22ef383a" />
<img width="1462" height="1014" alt="Screenshot (310)" src="https://github.com/user-attachments/assets/b86a6447-2b2f-48d7-b0a3-cfe3e59d79f2" />
<img width="1473" height="1014" alt="Screenshot (311)" src="https://github.com/user-attachments/assets/f6042e4a-b632-4183-a942-3a7acf6a8913" />


---

### Runtime Execution Logs (Local Host Terminal)

<img width="1915" height="957" alt="Screenshot 2026-07-04 114037" src="https://github.com/user-attachments/assets/5f03c435-8455-45a6-95ed-7c8c9839f4d0" />
<img width="1897" height="572" alt="Screenshot 2026-07-04 113942" src="https://github.com/user-attachments/assets/946428f4-e55d-4684-a6d6-f40656925cb7" />

