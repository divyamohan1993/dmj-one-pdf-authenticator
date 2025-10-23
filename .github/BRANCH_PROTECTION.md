# Recommended Branch Protection Rules

This document outlines the recommended branch protection settings for this repository to maintain code quality and security.

## Main Branch Protection

Apply these settings to the `main` branch:

### Required Reviews
- ✅ Require pull request reviews before merging
- Number of required approvals: **2**
- ✅ Dismiss stale pull request approvals when new commits are pushed
- ✅ Require review from Code Owners
- ✅ Require approval of the most recent reviewable push

### Status Checks
- ✅ Require status checks to pass before merging
- ✅ Require branches to be up to date before merging

**Required status checks:**
- `Test Cloudflare Worker`
- `Build Java Signer Service`
- `Lint Shell Scripts`
- `Validate Configuration Files`
- `Security Scan`
- `Analyze TypeScript Code` (CodeQL)
- `Analyze Java Code` (CodeQL)
- `Review Dependencies` (for PRs)

### Commit Signing
- ✅ Require signed commits
- All commits must be signed with GPG or SSH keys

### Branch Restrictions
- ✅ Restrict who can push to matching branches
- **Allowed to push:** Repository administrators only
- ✅ Require linear history (no merge commits)

### Force Push & Deletion
- ✅ Do not allow force pushes
- ✅ Do not allow deletions

### Additional Rules
- ✅ Require conversation resolution before merging
- ✅ Lock branch (optional for stable releases)
- ✅ Do not allow bypassing the above settings

## Develop Branch Protection

Apply these settings to the `develop` branch (if using git-flow):

### Required Reviews
- ✅ Require pull request reviews before merging
- Number of required approvals: **1**
- ✅ Dismiss stale pull request approvals when new commits are pushed

### Status Checks
- ✅ Require status checks to pass before merging
- Same required checks as main branch

### Commit Signing
- ✅ Require signed commits

### Branch Restrictions
- More lenient than main
- Allow maintainers to push directly for hotfixes

### Force Push & Deletion
- ✅ Do not allow force pushes
- ✅ Do not allow deletions

## Tag Protection

Protect release tags from unauthorized modifications:

### Tag Protection Rules
- Pattern: `v*` (protects all version tags like v1.0.0)
- ✅ Only repository administrators can create matching tags
- ✅ Only repository administrators can delete matching tags

## Rulesets (GitHub Rulesets)

For enhanced protection using GitHub Rulesets:

### Ruleset: Production Protection
**Target branches:** `main`

**Rules:**
1. Restrict creations
2. Restrict updates
3. Restrict deletions
4. Require pull request before merging
5. Require status checks to pass
6. Require conversation resolution
7. Require signed commits
8. Block force pushes

**Bypass list:** None (applies to everyone including admins)

### Ruleset: Development Standards
**Target branches:** `develop`, `feature/*`, `bugfix/*`, `hotfix/*`

**Rules:**
1. Require pull request before merging to develop
2. Require status checks to pass
3. Require signed commits
4. Block force pushes to develop

**Bypass list:** Repository administrators (for emergency fixes)

## Environment Protection

For Cloudflare Worker deployment:

### Production Environment
- ✅ Required reviewers: 2
- ✅ Wait timer: 5 minutes before deployment
- ✅ Deployment branches: `main` only
- ✅ Prevent self-review

### Staging Environment
- ✅ Required reviewers: 1
- ✅ Deployment branches: `develop`, `main`

## CODEOWNERS Configuration

The `.github/CODEOWNERS` file should specify:

```
# Default owners for everything
* @divyamohan1993

# GitHub configuration files require additional review
/.github/ @divyamohan1993

# Security-sensitive files
/LICENSE @divyamohan1993
/SECURITY.md @divyamohan1993
/.github/workflows/ @divyamohan1993

# Java signing service - requires security review
/signer-vm/ @divyamohan1993

# Cloudflare Worker - requires architecture review
/worker/ @divyamohan1993

# PKI and cryptographic materials
/signer-vm/pki/ @divyamohan1993

# Infrastructure and operations
/signer-vm/ops/ @divyamohan1993
```

## Implementation Steps

1. **Navigate to Repository Settings**
   - Go to `Settings` → `Branches`

2. **Add Branch Protection Rule for `main`**
   - Click "Add rule"
   - Enter branch name pattern: `main`
   - Enable all recommended settings above
   - Click "Create" or "Save changes"

3. **Add Branch Protection Rule for `develop`** (if using)
   - Repeat with settings for develop branch

4. **Configure Tag Protection**
   - Go to `Settings` → `Tags`
   - Add protection rule for `v*` pattern

5. **Set up Environments**
   - Go to `Settings` → `Environments`
   - Create `production` and `staging` environments
   - Configure protection rules

6. **Enable Security Features**
   - Go to `Settings` → `Security & analysis`
   - Enable:
     - Dependency graph
     - Dependabot alerts
     - Dependabot security updates
     - Secret scanning
     - Push protection

## Monitoring & Auditing

- **Enable audit log:** Track all protection rule changes
- **Monitor bypass events:** Alert when admins bypass rules
- **Review branch protection weekly:** Ensure rules are still effective
- **Update CODEOWNERS:** Keep ownership assignments current

## Exceptions

In emergency situations (security patches, critical bugs):
1. Document the exception in a GitHub issue
2. Get approval from repository owner
3. Temporarily bypass rules if necessary
4. Restore protection immediately after merge
5. Conduct post-mortem review

---

**Note:** These recommendations should be adapted based on team size, release cadence, and organizational policies. Review and update regularly.
