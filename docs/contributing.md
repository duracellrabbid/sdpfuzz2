# Contributing Guide

Welcome to the SDPFuzz2 project! This guide will help you set up your development environment, understand our quality standards, and outline the workflow for making code changes.

## 1. Setup Dev Environment

1. **Clone the repository**:
   ```bash
   git clone https://github.com/duracellrabbid/sdpfuzz2.git
   cd sdpfuzz2
   ```
2. **Create a virtual environment** (Python 3.11+ is required):
   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # Linux/Kali:
   source .venv/bin/activate
   ```
3. **Install the package in editable mode with dev dependencies**:
   ```bash
   pip install -e .[dev]
   ```

## 2. Code Quality & Formatting

We enforce strict formatting, linting, and type checking rules. Code contributions must pass all checks.

- **Import Sorting & Linting (Ruff)**:
  We use `ruff` to lint the codebase and check imports.
  ```bash
  ruff check .
  # To apply automatic fixes:
  ruff check . --fix
  ```
- **Code Formatting (Black)**:
  We use `black` for consistent code formatting.
  ```bash
  black .
  ```
- **Type Checking (Mypy)**:
  Mypy checks strict types across the whole source code.
  ```bash
  mypy .
  ```

### Git Pre-Commit Hooks
We use `pre-commit` to check files automatically before you commit.
```bash
# Install hooks
pre-commit install --hook-type pre-commit --hook-type pre-push
```

## 3. Test-Driven Development (TDD)

We follow a strict Test-Driven Development (TDD) flow. Any new features or bug fixes must include corresponding tests.

- **Running the entire test suite**:
  ```bash
  pytest
  ```
- **Target Test Coverage**:
  We target near-100% code coverage. If your pull request reduces test coverage below the required gate (currently 90%+), the CI pipeline will fail.
  - Check coverage report:
    ```bash
    pytest --cov=src/sdpfuzz2 --cov-report=term-missing
    ```
- **Platform Independence**:
  Ensure unit tests are fully runnable on both Windows and Linux by mocking all Bluetooth socket connections. Integration tests are marked with `@pytest.mark.integration` and are restricted to Linux/Kali environments.
