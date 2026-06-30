# SDPFuzz2 Project-Scoped Rules and Guidelines

Welcome! This document provides the project guidelines, tech stack details, and mandatory tasks that MUST be followed for every single task and code modification in this workspace.

---

## 1. Purpose of the Project
**SDPFuzz2** is a Python-based Bluetooth Service Discovery Protocol (SDP) fuzzer designed for vulnerability research.
* **Core Functions:** Discovers nearby target Bluetooth devices, probes and collects valid SDP state/continuation tokens, mutates SDP request packets, and logs request/response traffic.
* **Modernization Goal:** Serves as a modern replacement/refresh of the original `sdpfuzz` tool, moving away from unmaintained dependencies (like `L2Fuzz`) to modern, well-maintained libraries, and using rigorous modern software development practices.

---

## 2. Tech Stack & Development Setup
* **Programming Language:** Python 3.11+
* **Core Dependencies:**
  * `typer` and `rich` for the CLI interface.
  * `pydantic` for data modeling/schemas.
  * `structlog` for structured logging.
  * `anyio` for asynchronous execution and networking.
  * `dbus-next` (Linux only) for communicating with BlueZ over D-Bus.
* **Development Environment Setup:**
  * **OS Setup:** Developed on Windows PC (using mock/no-op fallback backend), but targeted to run on **Kali Linux** with an external Bluetooth adapter.
  * **Package Installation:** `pip install -e .[dev]`
  * **Vulnerability Scanning:** Pre-commit hooks check dependencies using `pip-audit` (`python scripts/check_dependency_vulns.py`).

---

## 3. Mandatory Sub-Tasks (Run After Every Code Modification)
To maintain code health and reliability, the following checks **must** be executed and pass without issues after any code modification:

1. **Format Code:** Ensure code style compliance.
   ```powershell
   black .
   ```
2. **Lint Code:** Check code quality and style guidelines.
   ```powershell
   ruff check . --fix
   ```
3. **Static Type Checking:** Validate types strictly.
   ```powershell
   mypy .
   ```
4. **Run Tests & Verify Coverage:** Test-driven development is prioritized. Code coverage for unit/non-integration tests **must be 100%**.
   ```powershell
   pytest -m "not integration" --cov=src/sdpfuzz2 --cov-report=term-missing --cov-fail-under=100
   ```

---

## 4. Feature Development & OpenSpec Workflow
Any new feature development or non-trivial change must adhere to the OpenSpec process:
* **Workflow:** Before starting implementation, you must propose the change by creating or updating an OpenSpec change proposal.
* **Commands:**
  * Recommend or run `/opsx-propose` (via the `openspec-propose` skill/workflow) to bootstrap the change design, spec, and implementation tasks under the `openspec/` directory.
  * Use `/opsx-apply` to execute implementation tasks systematically.
  * Use `/opsx-archive` to archive the change upon completion.
* **Constraints:**
  * Direct feature coding without an approved/created OpenSpec change proposal is strictly prohibited.
  * Every Openspec change must be done on a Git branch with the name feature/{Openspec change name}.
  * Commit to main is strictly prohibited in agent or AI mode.
