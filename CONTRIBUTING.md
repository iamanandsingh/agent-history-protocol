# Contributing to AHP

Thank you for your interest in contributing to the Agent History Protocol.

## Development Setup

```bash
git clone https://github.com/iamanandsingh/agent-history-protocol.git
cd agent-history-protocol
pip install -e ".[all,dev]"
```

## Running Tests

```bash
# Python tests
pytest tests/

# TypeScript SDK
cd packages/sdk-typescript
npm install && npm run build && npm test
```

## Code Quality

Before submitting a PR, ensure all checks pass:

```bash
ruff check ahp/             # Lint
ruff format --check ahp/    # Format
mypy ahp/ --ignore-missing-imports  # Type check
pytest tests/                # Tests
```

## Submitting Changes

1. Fork the repository and create a feature branch.
2. Write tests for new functionality.
3. Ensure all lint, type check, and test suites pass.
4. Submit a pull request with a clear description of the change.

## Code Style

- Follow the ruff configuration (line length 120, Python 3.9+ target).
- Type hints are required for public APIs.
- Tests are required for new features and bug fixes.
- Keep changes focused — one concern per PR.

## Reporting Issues

Open an issue on GitHub with a clear description, steps to reproduce, and expected vs. actual behavior.
