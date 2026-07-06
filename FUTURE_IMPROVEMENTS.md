# Future Improvements - SentinelFlow (SOAR Playbook Engine)

This document outlines high-value enhancements to expand the SentinelFlow SOAR platform. These features are designed to increase the complexity, realism, and portfolio value of the project.

---

## 🛠️ 1. Interactive Playbook Builder (Visual UI)
Allow analysts to design, edit, and configure playbooks directly through the web browser instead of writing YAML by hand.
*   **Frontend:** Add a drag-and-drop or pipeline step builder interface using CSS Grid/Flexbox (or a node library like React Flow / simple JS equivalent).
*   **Backend:** Add an endpoint `POST /api/playbook/save` that validates the configuration using the safe AST parser and writes it back to `playbook.yaml`.

## 🔌 2. Live API Integrations & Settings Panel
Expand playbooks beyond mocks to query real threat intelligence APIs and open real escalation channels.
*   **Credentials Manager:** Build a settings overlay on the dashboard to input API Keys (saved in a local `.env` or configuration file).
*   **VirusTotal Driver:** Add support for hash reputation scanning when alert contains `indicator_type: file_hash`.
*   **Ticketing & Notifications:** Connect the ticketing system to GitHub Issues / Jira API and send Slack/Discord webhook alerts with interactive response cards.

## 🖥️ 3. Simulated EDR Agent (Workstation Isolation)
Create a simulated endpoint workstation client that communicates with the SOAR dashboard to showcase active, real-time host containment.
*   **Agent Script (`agent.py`):** A lightweight background script running on a target host that polls the SOAR server `/api/agents/heartbeat`.
*   **Active Isolation:** When a critical alert is triggered, the engine sends a containment command to the agent. The agent executes a local containment rule (e.g. blocking connections via Windows Defender Firewall or `iptables`) and reports its state back.
*   **Agent Monitor:** Add a pane to the dashboard showing a list of registered agents, their connection heartbeat, and their containment status (Isolated / Active).

## 📄 4. Automated Incident Evidence & PDF Report Generator
Automate SANS-compliant incident documentation to generate evidence reports directly from the UI.
*   **Report Template:** Compile alert metadata, AbuseIPDB enrichment results, EDR execution actions, and analyst resolution comments.
*   **Export Actions:** Add an "Export Report" button on resolved tickets that generates a Markdown or PDF incident response report.
