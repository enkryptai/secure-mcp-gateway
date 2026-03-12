# Contributing to Secure MCP Gateway

Thank you for your interest in contributing to **Secure MCP Gateway**. This document explains how to get started, what we expect, and how to submit changes.

## Code of conduct

We expect all contributors to be respectful and constructive. By participating, you agree to uphold a welcoming and inclusive environment.

## Before you contribute

1. **Read the CLA.** By submitting a pull request or other contribution, you agree to our [Contributor License Agreement (CLA)](./CLA.md). Please read it before you submit.
2. **Check existing work.** Look at open issues and pull requests to avoid duplicating effort.
3. **Check the roadmap.** See the `TODO` file for current work in progress and planned features.

## How to contribute

### Reporting bugs

- Open an issue with a clear title and description.
- Include steps to reproduce, your environment (OS, Python version, gateway version), and relevant logs or config (with secrets removed).

### Suggesting features or changes

- Open an issue describing the use case or improvement.
- Discussion in the issue is welcome before you write code.

### Submitting code or documentation

1. **Fork and clone** the repository.
2. **Set up your environment** so you can run and test locally:
   - Follow [Local installation with Git clone](README.md#42-local-installation-with-git-clone), or
   - Build with `python -m build`, activate a virtual environment, and install with `pip install .`
3. **Create a branch** for your change (e.g. `fix/cache-timeout`, `docs/api-usage`).
4. **Make your changes** and keep them focused (one logical change per PR when possible).
5. **Test** your changes. See [Testing](README.md#19-testing) for how to run the test suite.
6. **Commit** with clear messages (e.g. "Fix cache key hashing for empty server name").
7. **Open a pull request** against the default branch. In the PR description:
   - Summarize what changed and why.
   - Reference any related issues.
   - Confirm you have read and agree to the [CLA](CLA.md).

We’ll review your PR and may ask for updates. Once approved and merged, your contribution will be included under the project’s license and our [CLA](CLA.md).

## Project structure and conventions

- **Source code:** `src/secure_mcp_gateway/` — gateway, client, services, plugins, etc.
- **Docs:** `docs/`, plus `README.md`, `CLI-Commands-Reference.md`, `API-Reference.md`.
- **Tests:** See [Testing](README.md#19-testing) for how and where tests are run.
- **Config:** Example config is in `src/secure_mcp_gateway/example_enkrypt_mcp_config.json`; default values and paths are in `consts.py` and documented in `CLAUDE.md`.

Keeping style consistent with the existing codebase (formatting, naming, docstrings) is appreciated.

## Questions

If you have questions about contributing or the project, open a discussion or an issue and we’ll do our best to help.

Thank you for contributing to Secure MCP Gateway.
