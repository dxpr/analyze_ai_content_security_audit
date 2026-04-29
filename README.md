> Part of [DXPR CMS](https://dxpr.com/c/marketing-cms): The AI-Powered Drupal CMS
>
> [Documentation](https://dxpr.com/docs) | [Try Free](https://dxpr.com/try) | [dxpr.com](https://dxpr.com)

# AI Content Security Audit: AI-Powered PII and Credential Leak Detection for Drupal

AI-powered content security risk analysis identifying potential PII disclosure,
credential exposure, and sensitive information leaks before publication.

## Features

- **Configurable Security Vectors**: Flexible risk management through admin UI
- **Risk Scoring**: Customizable scoring from 0 (no risk) to 100 (high risk)
- **Pre-configured Detection**: Built-in vectors for PII and credential
  disclosure
- **Custom Security Vectors**: Add organization-specific security policies
- **Batch Processing**: Comprehensive analysis of existing content volumes
- **Visual Risk Assessment**: Intuitive indicators and reporting dashboards

## Requirements

- [Analyze](https://www.drupal.org/project/analyze) framework
- [AI](https://www.drupal.org/project/ai) module with configured provider

## Installation

```bash
composer require drupal/analyze_ai_content_security_audit
drush en analyze_ai_content_security_audit
```

## Configuration

### Basic Setup
1. Configure AI provider at `/admin/config/ai/providers`
2. Manage security vectors at `/admin/config/analyze/content-security-audit`
3. Enable per content type at `/admin/config/content/analyze-settings`
4. Configure permissions at
   `/admin/people/permissions#module-analyze_ai_content_security_audit`

### Security Vector Management
- **Add vectors**: Click "Add vector" with risk scoring and detection criteria
- **Edit vectors**: Modify existing security policies
- **Delete vectors**: Remove vectors and associated analysis results

## Default Security Vectors

### PII Disclosure
Identifies potential exposure of personally identifiable information
including:
- Names, addresses, phone numbers
- Social security numbers, ID numbers
- Email addresses in sensitive contexts

### Credentials Disclosure  
Detects API keys, passwords, and authentication data exposure:
- API keys and tokens
- Database credentials
- Authentication secrets
- Configuration passwords

## Risk Assessment

Security risks scored from 0-100:
- **0-25**: Low risk - Minor policy violations
- **26-50**: Medium risk - Moderate security concerns
- **51-75**: High risk - Significant exposure potential
- **76-100**: Critical risk - Immediate attention required

## AI Coding Assistant Integration

The Content Security Audit module includes a built-in
[Agent Skills](https://agentskills.io) file (via the base
Analyze module) that teaches AI coding assistants how to run
security audit analysis through natural language. Run
`drush analyze:setup-ai` to enable, then ask naturally:

```
"Scan all content for security risks"
"Check if any pages expose PII or credentials"
"Run a security audit on all published articles"
"Analyze security vectors across the entire site"
```

Batch processing is available via the centralized Analyze
batch system:

```bash
# Check analysis coverage
drush analyze:batch --status

# Run this analyzer on all enabled content types
drush analyze:batch \
  --analyzers=analyze_ai_content_security_audit_analyzer

# Run on specific content types with limit
drush analyze:batch \
  --analyzers=analyze_ai_content_security_audit_analyzer \
  --types=node:article --limit=50

# Force re-analysis of already analyzed content
drush analyze:batch \
  --analyzers=analyze_ai_content_security_audit_analyzer --force
```

Compatible with Claude Code, Codex CLI, Gemini CLI, GitHub
Copilot, Cursor, and other tools supporting the
[Agent Skills standard](https://agentskills.io/specification).

## Compliance Use Cases

- **Privacy Regulations**: GDPR, CCPA, HIPAA compliance
- **Data Breach Prevention**: Proactive sensitive information detection
- **Publication Workflows**: Security risk assessment before content goes
  live
- **Audit Trails**: Historical tracking of security risk remediation

## Related DXPR Modules

- [Analyze](https://www.drupal.org/project/analyze)
- [Analyze Broken Links](https://www.drupal.org/project/analyze_broken_links)
- [AI Sentiments Analysis](https://www.drupal.org/project/analyze_ai_sentiments)
