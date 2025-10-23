# GitHub Configuration Files

This directory contains all GitHub-specific configuration files for the dmj-one PDF Authenticator repository. These files enhance collaboration, automate workflows, and maintain code quality.

## 📁 Directory Structure

```
.github/
├── workflows/              # GitHub Actions workflows
│   ├── ci.yml             # CI/CD pipeline
│   ├── codeql-analysis.yml # Security scanning
│   ├── dependency-review.yml # Dependency checks
│   ├── release.yml        # Automated releases
│   └── stale.yml          # Stale issue management
├── ISSUE_TEMPLATE/        # Issue templates
│   ├── bug_report.md      # Bug report template
│   ├── feature_request.md # Feature request template
│   ├── general.md         # General issue template
│   └── config.yml         # Issue template config
├── DISCUSSION_TEMPLATE/   # Discussion templates
│   ├── ideas.yml          # Ideas/suggestions
│   ├── question.yml       # Q&A template
│   └── show-and-tell.yml  # Showcase template
├── codeql/                # CodeQL configuration
│   └── codeql-config.yml  # CodeQL analysis config
├── BRANCH_PROTECTION.md   # Branch protection guidelines
├── CODE_OF_CONDUCT.md     # Community guidelines
├── CODEOWNERS             # Code ownership
├── CONTRIBUTING.md        # Contribution guidelines
├── FUNDING.yml            # Sponsorship info
├── labels.yml             # Label configuration
├── PULL_REQUEST_TEMPLATE.md # PR template
├── README.md              # This file
├── REPOSITORY_SETTINGS.md # Repo settings guide
├── SECURITY.md            # Security policy
└── SUPPORT.md             # Support resources
```

## 🔄 Workflows

### CI/CD Pipeline (`ci.yml`)
**Triggers:** Push to main/develop, Pull Requests
**Jobs:**
- Test Cloudflare Worker (TypeScript)
- Build Java Signer Service (Maven)
- Lint shell scripts (ShellCheck)
- Validate configuration files
- Security scanning (Trivy)

### CodeQL Analysis (`codeql-analysis.yml`)
**Triggers:** Push, PR, Weekly schedule
**Purpose:** Automated security vulnerability scanning
**Languages:** JavaScript/TypeScript, Java

### Dependency Review (`dependency-review.yml`)
**Triggers:** Pull Requests
**Purpose:** Review dependency changes for security issues
**Features:** 
- Blocks high-severity vulnerabilities
- Denies incompatible licenses (GPL variants)

### Stale Management (`stale.yml`)
**Triggers:** Daily schedule
**Purpose:** Close inactive issues and PRs
**Settings:**
- Issues: 60 days stale → 14 days to close
- PRs: 30 days stale → 14 days to close

### Release Automation (`release.yml`)
**Triggers:** Version tags (v*.*.*)
**Purpose:** Automated release creation
**Actions:**
- Build Java JAR
- Generate release notes
- Upload artifacts
- Create GitHub release

## 📋 Templates

### Issue Templates
1. **Bug Report** - For reporting issues
2. **Feature Request** - For suggesting improvements
3. **General Issue** - For questions and discussions
4. **Config** - Links to discussions and security advisories

### Pull Request Template
Comprehensive checklist including:
- Type of change
- Testing requirements
- Security considerations
- Performance impact
- Breaking changes
- Attribution acknowledgment

### Discussion Templates
1. **Q&A** - Ask questions
2. **Ideas** - Share suggestions
3. **Show and Tell** - Showcase projects

## 🔒 Security

### CodeQL Configuration
- Scans TypeScript and Java code
- Runs security-extended and quality queries
- Ignores build artifacts and dependencies

### Security Policy (`SECURITY.md`)
- Supported versions
- Vulnerability reporting process
- Responsible disclosure guidelines

## 👥 Community

### Code of Conduct
Adopts the Contributor Covenant 2.1

### Contributing Guidelines
- Getting started guide
- Code style requirements
- PR submission process
- Testing expectations

### Code Owners
- Defines who reviews changes
- Automatic review requests
- Component-based ownership

## 🤖 Automation

### Dependabot (`dependabot.yml`)
Monitors and updates:
- NPM packages (Worker)
- Maven dependencies (Signer)
- GitHub Actions versions

**Schedule:** Weekly on Mondays

### Labels (`labels.yml`)
Comprehensive label system:
- Priority levels (critical, high, medium, low)
- Types (bug, feature, security, etc.)
- Status indicators
- Component tags
- Dependency categories

## 📊 Monitoring

### Branch Protection
See [BRANCH_PROTECTION.md](BRANCH_PROTECTION.md) for:
- Required reviews
- Status check requirements
- Commit signing
- Push restrictions

### Repository Settings
See [REPOSITORY_SETTINGS.md](REPOSITORY_SETTINGS.md) for:
- Complete settings guide
- Feature configuration
- Security setup
- Access management

## 🎯 Best Practices

### For Contributors
1. Use issue templates when reporting problems
2. Fill out PR template completely
3. Ensure all CI checks pass
4. Request review from code owners
5. Sign your commits

### For Maintainers
1. Review security alerts promptly
2. Keep dependencies updated
3. Monitor workflow success rates
4. Update documentation as needed
5. Enforce branch protection rules

## 🔧 Customization

### Adding New Workflows
1. Create YAML file in `workflows/`
2. Define trigger events
3. Add required jobs and steps
4. Test on feature branch first
5. Document in this README

### Modifying Templates
1. Update template files
2. Test with dummy issue/PR
3. Document changes
4. Announce to contributors

### Updating Labels
1. Edit `labels.yml`
2. Apply via GitHub CLI or API
3. Update related documentation
4. Communicate to team

## 📚 Documentation

All GitHub configuration is documented:
- **This README** - Overview and structure
- **REPOSITORY_SETTINGS.md** - Detailed settings guide
- **BRANCH_PROTECTION.md** - Protection rules
- **Workflow files** - Inline comments

## 🤝 Getting Help

Questions about GitHub configuration?
- Open a [Discussion](../../discussions)
- Check [SUPPORT.md](SUPPORT.md)
- Contact maintainers

## 📝 License Notice

All configuration files in this directory follow the repository's Attribution Assurance License. See [LICENSE](../LICENSE) for details.

## 🔗 Useful Links

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [GitHub Community Standards](https://docs.github.com/en/communities)
- [Branch Protection Rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/defining-the-mergeability-of-pull-requests/about-protected-branches)
- [CodeQL Documentation](https://codeql.github.com/docs/)
- [Dependabot Documentation](https://docs.github.com/en/code-security/dependabot)

---

**Maintained by:** @divyamohan1993  
**Last Updated:** 2025-01-01

*This directory is essential for maintaining repository quality, security, and community engagement.*
