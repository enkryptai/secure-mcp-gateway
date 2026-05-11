# Contributing to Secure MCP Gateway

Thank you for your interest in contributing to **Secure MCP Gateway**. This document explains how to get started, what we expect, and how to submit changes.

## Code of conduct

We expect all contributors to be respectful and constructive. By participating, you agree to uphold a welcoming and inclusive environment.

## Before you contribute

1. **Read the CLA.** By submitting a pull request or other contribution, you agree to our [Contributor License Agreement (CLA)](./CLA.md). Please read it before you submit.
2. **Check existing work.** Look at open issues and pull requests to avoid duplicating effort.
3. **Check the roadmap.** See the `TODO` file for current work in progress and planned features.

## Development setup

### Prerequisites

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- [pre-commit](https://pre-commit.com/)

### Quick start

```bash
# Clone the repository
git clone https://github.com/enkryptai/secure-mcp-gateway.git
cd secure-mcp-gateway

# Create a virtual environment and install in editable mode with dev extras
python -m venv .venv
source .venv/bin/activate          # Linux/macOS
# .venv\Scripts\activate           # Windows

pip install -e ".[dev]"

# Install pre-commit hooks (runs linting/formatting on every commit)
pre-commit install

# Verify everything works
ruff check src/
pytest -x -q
```

### Pre-commit hooks

We use [pre-commit](https://pre-commit.com/) to enforce code quality automatically. The configuration is in `.pre-commit-config.yaml` and includes:

- YAML, JSON, TOML validation
- Merge conflict detection
- Large file checks (max 500 KB)
- Python AST validation
- Debug statement detection
- Test file naming conventions
- Branch protection (no direct commits to `main`)
- Trailing whitespace and line ending normalization
- **Ruff** linting and formatting

Run hooks manually on all files:

```bash
pre-commit run --all-files
```

### Running tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Skip integration tests (require external services)
pytest -m "not integration"
```

## How to contribute

### Reporting bugs

- Open an issue with a clear title and description.
- Include steps to reproduce, your environment (OS, Python version, gateway version), and relevant logs or config (with secrets removed).

### Suggesting features or changes

- Open an issue describing the use case or improvement.
- Discussion in the issue is welcome before you write code.

### Submitting code or documentation

1. **Fork and clone** the repository.
2. **Set up your environment** following the [Development setup](#development-setup) section above.
3. **Create a branch** for your change (e.g. `fix/cache-timeout`, `feat/new-guardrail`).
4. **Make your changes** — keep them focused (one logical change per PR when possible).
5. **Run the checks** — `ruff check src/` and `pytest -x -q` must pass.
6. **Commit** with clear messages (e.g. "Fix cache key hashing for empty server name").
7. **Open a pull request** against the default branch. In the PR description:
   - Summarize what changed and why.
   - Reference any related issues.
   - Confirm you have read and agree to the [CLA](CLA.md).

We'll review your PR and may ask for updates. Once approved and merged, your contribution will be included under the project's license and our [CLA](CLA.md).

## Project structure

```
src/secure_mcp_gateway/
├── gateway.py             # Main MCP server (FastMCP, streamable HTTP)
├── client.py              # MCP client — forwards requests to real servers
├── cli.py                 # CLI interface (config, project, user management)
├── api_server.py          # FastAPI REST API server
├── api_routes.py          # Additional API routes
├── plugins/               # Auth, guardrails, and telemetry providers
├── services/              # Cache, discovery, execution, OAuth, timeout
└── bad_mcps/              # Test MCP servers for security scenarios
```

- **Config:** Example config is in `src/secure_mcp_gateway/example_enkrypt_mcp_config.json`; default values and paths are in `consts.py`.
- **Observability:** `observability/` folder contains Docker Compose and configs for OTel Collector, Jaeger, Loki, Prometheus, Promtail, and Grafana.

## Style guide

- Format and lint with **Ruff** (configuration is in `pyproject.toml`).
- Keep imports sorted (`ruff check --select I --fix`).
- Type hints are encouraged for new code.
- Docstrings should follow Google style.

## Questions

If you have questions about contributing or the project, open a discussion or an issue and we'll do our best to help.

Thank you for contributing to Secure MCP Gateway.
