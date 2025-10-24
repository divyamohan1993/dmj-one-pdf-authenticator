# Contributing to dmj-one PDF Authenticator

Thank you for your interest in contributing! We welcome issues, feature requests, and pull requests.

## Getting Started

1. Fork the repository and clone it locally.
2. Install dependencies (requires Node.js and Wrangler) and set up a Cloudflare account.
3. Follow the deployment instructions in the [README.md](../README.md) or [QUICKSTART.md](../QUICKSTART.md) to run the Worker and signer service locally.
4. For the Java signer service, ensure you have Java 21 and Maven installed.

### Quick Setup for Development

For automated deployment on a VM:
```bash
# Follow the one-click deployment guide
# See one-click-deployment/readme.md
```

For local development:
```bash
# See DEVELOPMENT.md for detailed local setup instructions
```

## Submitting an Issue

- Use the **Bug report** or **Feature request** issue templates provided.
- Provide as much detail as possible, including steps to reproduce, expected behavior, and relevant logs or screenshots.

## Pull Requests

- Make sure there is an issue that describes the problem or feature you're addressing.
- Create a new branch from `main` for your work.
- Write clear, concise commit messages that explain the reason for the change.
- Run all tests and linters before submitting your PR.
- Update documentation and examples as needed.
- Reference the issue number in the PR description (e.g., "Closes #12").

## Coding Style

- TypeScript code should follow the existing lint rules (we use ESLint and Prettier). Use consistent formatting and type annotations.
- Java code should follow standard formatting (the Google Java Style is a good starting point).
- Bash scripts should be POSIX compliant and include a shebang (`#!/usr/bin/env bash`).

## Testing

- Test Worker changes locally with `wrangler dev`
- Test Java signer changes with `mvn test`
- Run shell script tests with `shellcheck` if available
- Verify deployment scripts in a clean VM environment when possible

## Documentation

When making changes, please update:
- Inline code comments for complex logic
- README.md for user-facing changes
- ARCHITECTURE.md for architectural changes
- QUICKSTART.md for deployment process changes
- API documentation in relevant files

## Code of Conduct

This project adopts the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to abide by its terms.

## Security

If you discover a security vulnerability, please follow the process described in [`SECURITY.md`](SECURITY.md) and report it privately.

## Attribution

This project uses the Attribution Assurance License (AAL). All contributions must acknowledge and maintain proper attribution to the original author. By contributing, you agree that your contributions will be licensed under the same terms.

## Questions?

- Check [SUPPORT.md](SUPPORT.md) for help resources
- Ask in [GitHub Discussions](https://github.com/divyamohan1993/dmj-one-pdf-authenticator/discussions)
- Review existing issues and PRs for similar topics

Thank you for contributing to dmj-one PDF Authenticator! 🚀
