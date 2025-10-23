# Project Governance

This document outlines the governance structure and decision-making process for the dmj-one PDF Authenticator project.

## Project Mission

To provide a secure, scalable, and easy-to-deploy serverless document signing and verification system that respects user privacy through zero-knowledge architecture.

## Values

- 🔒 **Security First** - Security is our highest priority
- 🌐 **Open Source** - Transparent development and collaboration
- 📚 **Documentation** - Well-documented code and processes
- 🤝 **Community** - Welcoming and inclusive community
- ⚡ **Performance** - Fast and efficient operations
- 🎯 **Simplicity** - Easy to understand and deploy

## Roles & Responsibilities

### Project Owner

**Current:** Divya Mohan (@divyamohan1993)

**Responsibilities:**
- Final decision-making authority
- Strategic direction and roadmap
- Release management
- Security oversight
- License compliance
- Trademark protection

**Authority:**
- Approve/reject major changes
- Grant/revoke commit access
- Create releases
- Modify governance structure

### Maintainers

**Current Maintainers:**
- Divya Mohan (@divyamohan1993)

**Becoming a Maintainer:**
Requirements:
- Consistent, high-quality contributions over 6+ months
- Deep understanding of codebase
- Community engagement (reviews, discussions)
- Alignment with project values
- Recommendation by existing maintainer
- Approval by project owner

**Responsibilities:**
- Code review and approval
- Issue triage and management
- Community support
- Documentation maintenance
- Security issue response
- Release testing

### Contributors

**Anyone can be a contributor!**

**How to Contribute:**
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request
5. Respond to review feedback

**Recognition:**
- Name in CONTRIBUTORS.md
- Acknowledgment in release notes
- Community reputation

### Community Members

**Everyone using or following the project**

**Ways to Participate:**
- Report bugs
- Suggest features
- Answer questions
- Write documentation
- Share the project
- Provide feedback

## Decision-Making Process

### Minor Changes
- **Examples:** Bug fixes, documentation updates, small improvements
- **Process:** PR → Review → Merge
- **Approval:** 1 maintainer approval required

### Moderate Changes
- **Examples:** New features, refactoring, dependency updates
- **Process:** Issue discussion → PR → Review → Merge
- **Approval:** 2 maintainer approvals required
- **Timeline:** Minimum 48-hour review period

### Major Changes
- **Examples:** Architecture changes, breaking changes, new components
- **Process:** RFC → Community discussion → PR → Review → Merge
- **Approval:** Project owner approval required
- **Timeline:** Minimum 1-week discussion period

### Security Issues
- **Process:** Private disclosure → Fix development → Release → Public disclosure
- **Authority:** Project owner decides timeline and response
- **Priority:** Highest - interrupts normal workflow

## Contribution Process

### 1. Discuss
- Create an issue for bugs/features
- Use discussions for questions/ideas
- Get feedback before starting work

### 2. Develop
- Fork and create feature branch
- Follow coding standards
- Write tests
- Update documentation

### 3. Submit
- Create pull request
- Fill out PR template completely
- Link related issues
- Ensure CI passes

### 4. Review
- Respond to feedback promptly
- Make requested changes
- Be patient and respectful
- Iterate until approved

### 5. Merge
- Maintainer merges approved PR
- Branch is automatically deleted
- Issue is closed
- Contributor is recognized

## Conflict Resolution

### Code Disagreements
1. Discuss in PR comments
2. If unresolved, escalate to maintainer meeting
3. If still unresolved, project owner makes final decision

### Community Disagreements
1. Follow Code of Conduct
2. Contact maintainers via email
3. Formal mediation if needed
4. Enforcement action if necessary

### Appeals
- Any decision can be appealed to project owner
- Submit appeal via email with detailed explanation
- Owner will review and respond within 7 days

## Release Process

### Versioning
Follows [Semantic Versioning](https://semver.org/):
- **MAJOR.MINOR.PATCH** (e.g., 1.2.3)
- MAJOR: Breaking changes
- MINOR: New features (backward compatible)
- PATCH: Bug fixes (backward compatible)

### Release Schedule
- **Patch releases:** As needed for critical bugs
- **Minor releases:** Every 2-3 months
- **Major releases:** As needed for breaking changes

### Release Procedure
1. Update CHANGELOG.md
2. Create release branch
3. Run full test suite
4. Update version numbers
5. Create git tag
6. GitHub Actions creates release
7. Announce on discussions

## Project Communication

### Channels
- **GitHub Issues** - Bug reports, feature requests
- **GitHub Discussions** - Questions, ideas, community
- **GitHub PRs** - Code reviews, contributions
- **Email** - Private security issues, governance questions

### Response Times
- Security issues: 24-48 hours
- Critical bugs: 2-3 days
- Regular issues: 1 week
- Questions: 1 week
- Feature requests: 2 weeks

## Code of Conduct

All participants must follow our [Code of Conduct](CODE_OF_CONDUCT.md).

**Enforcement:**
- First violation: Warning
- Second violation: Temporary ban
- Third violation: Permanent ban

**Reporting:**
- Email: contact@dmj.one
- Confidential and taken seriously
- Response within 24 hours

## Intellectual Property

### Copyright
- All contributions remain copyright of contributors
- Contributors grant license per Attribution Assurance License
- Attribution must be maintained

### License
- **Attribution Assurance License (AAL)**
- Mandatory attribution required
- See LICENSE file for full terms

### Trademarks
- "dmj-one PDF Authenticator" is a trademark of Divya Mohan
- Usage requires approval for commercial purposes
- Attribution must include trademark notice

## Sustainability

### Funding
- GitHub Sponsors
- Corporate sponsorships
- Grant applications
- Service agreements

### Priorities
1. Security maintenance
2. Bug fixes
3. Documentation
4. New features
5. Community support

## Amendments

This governance document may be amended by:
1. Proposal via GitHub Discussion
2. Community feedback period (2 weeks minimum)
3. Approval by project owner
4. Documentation of changes in CHANGELOG

## Questions?

For questions about governance:
- Open a [Discussion](https://github.com/divyamohan1993/dmj-one-pdf-authenticator/discussions)
- Email: contact@dmj.one

---

**Version:** 1.0  
**Last Updated:** 2025-01-01  
**Next Review:** 2025-07-01
