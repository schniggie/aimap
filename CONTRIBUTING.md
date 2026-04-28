# Contributing to AIMap

Thanks for your interest in contributing to AIMap! This project is maintained by [Bishop Fox](https://bishopfox.com) and we welcome contributions from the community.

## Getting Started

Follow the setup instructions in the [README](README.md) to get the backend (Python/FastAPI) and frontend (React/TypeScript) running locally. You will need Python 3.12+, Node 20+, MongoDB, and Redis.

## Development Workflow

1. Fork the repository and create a feature branch from `main`.
2. Make your changes, keeping commits focused and well-described.
3. Add or update tests for any new or changed functionality.
4. Verify everything passes locally:
   ```bash
   # Backend
   cd backend && pytest -v

   # Frontend
   cd frontend && npm run lint && npm run build
   ```
5. Open a pull request against `main` with a clear description of the change.

## Code Style

**Python (backend)**
- Use type hints on all function signatures.
- Write async functions for I/O-bound operations (database, HTTP, Redis).
- Follow existing patterns in `backend/app/` for route and service structure.

**TypeScript (frontend)**
- TypeScript strict mode is enabled -- do not use `any` without justification.
- Follow the existing component and hook patterns in `frontend/src/`.

## Pull Request Guidelines

- All PRs require passing CI (lint, build, tests).
- Include tests for new features and bug fixes where applicable.
- Keep PRs reasonably scoped -- prefer smaller, focused changes over large sweeping ones.
- A maintainer will review your PR and may request changes before merging.

## Security Vulnerabilities

If you discover a security issue, **do not open a public issue**. Please follow the responsible disclosure process in [SECURITY.md](SECURITY.md).

## License

By contributing to AIMap, you agree that your contributions will be licensed under the [MIT License](LICENSE) that covers this project.
