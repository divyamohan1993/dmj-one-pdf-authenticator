# Development Guide

This guide helps you set up a local development environment for dmj-one PDF Authenticator.

## Prerequisites

### Required Software
- **Node.js** 20.x or higher
- **Java** 21 (OpenJDK or Oracle JDK)
- **Maven** 3.9.x or higher
- **Git** 2.x or higher
- **Cloudflare Account** (for Worker deployment)
- **Wrangler CLI** (Cloudflare's CLI tool)

### Optional Tools
- **VS Code** or **IntelliJ IDEA** (recommended IDEs)
- **Docker** (for containerized development)
- **ShellCheck** (for shell script linting)
- **yamllint** (for YAML validation)

## Repository Setup

### 1. Clone the Repository

```bash
git clone https://github.com/divyamohan1993/dmj-one-pdf-authenticator.git
cd dmj-one-pdf-authenticator
```

### 2. Install Dependencies

#### Worker Dependencies
```bash
cd worker
npm install
```

#### Java Signer Dependencies
```bash
cd ../signer-vm
mvn clean install
```

## Development Workflow

### Worker Development

#### Local Development
```bash
cd worker
npm run dev
# Opens local development server with hot reload
```

#### Type Checking
```bash
npm run typecheck
# Runs TypeScript compiler without emitting files
```

#### Dry Run Deployment
```bash
npx wrangler deploy --dry-run
# Tests deployment configuration without actually deploying
```

### Java Signer Development

#### Build
```bash
cd signer-vm
mvn clean package
# Creates JAR file in target/ directory
```

#### Run Locally
```bash
java -jar target/pdf-signer-1.0.0.jar
# Starts local server on dynamic port
```

#### Debug Mode
```bash
java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005 \
     -jar target/pdf-signer-1.0.0.jar
# Starts with remote debugging on port 5005
```

## Environment Configuration

### Worker Environment Variables

Create `.dev.vars` in `worker/` directory (DO NOT commit this file):

```bash
# Admin credentials
ADMIN_PASSWORD_HASH=your_pbkdf2_hash_here

# HMAC key for signer authentication
HMAC_KEY=your_64_char_hex_key_here

# TOTP master key for revocation
TOTP_MASTER_KEY=your_32_char_base32_key_here

# Signer service URL
SIGNER_URL=http://localhost:8080
```

### Generating Secrets

#### PBKDF2 Hash
```bash
# Using Node.js
node -e "const crypto = require('crypto'); \
  const password = 'your_password'; \
  const salt = crypto.randomBytes(16).toString('hex'); \
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha256').toString('hex'); \
  console.log('ADMIN_PASSWORD_HASH=' + salt + ':' + hash);"
```

#### HMAC Key
```bash
openssl rand -hex 32
```

#### TOTP Master Key
```bash
node -e "console.log(require('crypto').randomBytes(20).toString('base32'))"
```

## Testing

### Running Tests

#### Worker Tests
```bash
cd worker
npm test
# Note: Test infrastructure may need to be set up
```

#### Java Tests
```bash
cd signer-vm
mvn test
```

### Manual Testing

#### Test Signing Workflow
1. Start Java signer service
2. Start Worker dev server
3. Navigate to admin portal
4. Upload a test PDF
5. Verify signature is created

#### Test Verification Workflow
1. Navigate to verification portal
2. Upload signed PDF
3. Verify status is "GENUINE"

## Code Style

### TypeScript/JavaScript
- Follow ESLint configuration
- Use Prettier for formatting
- 2 spaces for indentation
- Use async/await instead of promises

### Java
- Follow Google Java Style Guide
- 4 spaces for indentation
- Use descriptive variable names
- Add JavaDoc for public methods

### Shell Scripts
- Use `#!/usr/bin/env bash`
- Follow ShellCheck recommendations
- Add comments for complex logic

## Debugging

### Worker Debugging
- Use `console.log()` statements
- Check `wrangler tail` for live logs
- Use browser DevTools Network tab
- Check Cloudflare dashboard for errors

### Java Debugging
- Use remote debugging (port 5005)
- Check application logs
- Use Java debugger in IDE
- Add breakpoints in critical sections

## Common Issues

### Problem: Worker fails to deploy
**Solution:** Check wrangler.toml configuration and ensure D1 database is created

### Problem: Java service won't start
**Solution:** Ensure port is available and Java 21 is installed

### Problem: Signature verification fails
**Solution:** Check HMAC key matches between Worker and Java service

### Problem: Cannot connect to Java service
**Solution:** Check firewall rules and ensure service is running

## Development Tips

### Quick Commands

```bash
# Build everything
cd worker && npm install && cd ../signer-vm && mvn clean package

# Start Java service in background
cd signer-vm && java -jar target/*.jar &

# Start Worker dev server
cd worker && npm run dev

# Run all linters
cd worker && npx tsc --noEmit
cd ../signer-vm && mvn checkstyle:check
```

### Git Workflow

1. Create feature branch: `git checkout -b feature/your-feature`
2. Make changes and commit: `git commit -s -m "feat: your message"`
3. Push to GitHub: `git push origin feature/your-feature`
4. Create pull request
5. Wait for CI to pass
6. Request review
7. Address feedback
8. Merge when approved

### Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test changes
- `chore`: Build/tooling changes

**Examples:**
```
feat(worker): add batch signing endpoint
fix(signer): resolve memory leak in PDF processing
docs: update deployment guide
```

## IDE Configuration

### VS Code

Recommended extensions:
- ESLint
- Prettier
- TypeScript and JavaScript Language Features
- Cloudflare Workers

Recommended settings (`.vscode/settings.json`):
```json
{
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.fixAll.eslint": true
  },
  "typescript.tsdk": "node_modules/typescript/lib"
}
```

### IntelliJ IDEA

1. Import as Maven project
2. Enable annotation processing
3. Install Checkstyle plugin
4. Configure code style to Google Java Style

## Database Migrations

### Creating a Migration

```bash
cd worker/migrations
# Create new migration file
touch 0003_your_migration_name.sql
```

### Applying Migrations

```bash
cd worker
wrangler d1 migrations apply YOUR_DATABASE_NAME
```

### Rolling Back

Migrations cannot be automatically rolled back. Create a new migration to undo changes.

## Performance Profiling

### Worker Performance
- Use Cloudflare Analytics
- Monitor response times
- Check CPU time usage
- Track memory consumption

### Java Performance
- Use JVM profiler (VisualVM, JProfiler)
- Monitor heap usage
- Track GC performance
- Profile method execution times

## Security Testing

### Local Security Checks

```bash
# Scan for secrets
git secrets --scan

# Check dependencies for vulnerabilities
cd worker && npm audit
cd signer-vm && mvn dependency-check:check

# Run security linter
npm run security-check
```

## Continuous Integration

CI runs automatically on:
- Every push to main/develop
- Every pull request
- Scheduled daily scans

Local CI simulation:
```bash
# Run all CI checks locally
./scripts/ci-local.sh
```

## Getting Help

- 📖 [README](../README.md)
- 🏗️ [Architecture](../ARCHITECTURE.md)
- 🤝 [Contributing](../.github/CONTRIBUTING.md)
- 💬 [Discussions](https://github.com/divyamohan1993/dmj-one-pdf-authenticator/discussions)

## Next Steps

1. Complete the setup steps above
2. Read the [Architecture documentation](../ARCHITECTURE.md)
3. Check the [Contributing guidelines](../.github/CONTRIBUTING.md)
4. Pick an issue labeled `good first issue`
5. Make your first contribution!

---

**Happy coding!** 🚀
