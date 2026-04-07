# AI Content Security Audit

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

## CLI & AI Agent Support

### Batch Processing

Batch analysis is available through the centralized Analyze
batch system:

- **Admin UI**: Administration > Configuration > Content >
  Batch Analysis (`/admin/config/content/analyze-batch`)
- **Drush CLI**:
  `drush analyze:batch --analyzers=analyze_ai_content_security_audit_analyzer`

See the [Analyze module](https://www.drupal.org/project/analyze)
for full batch command options.

### AI Agent Integration

AI agents can access security audit analysis through the centralized
Analyze skill files. Install with `drush analyze:setup-ai`.

## Compliance Use Cases

- **Privacy Regulations**: GDPR, CCPA, HIPAA compliance
- **Data Breach Prevention**: Proactive sensitive information detection
- **Publication Workflows**: Security risk assessment before content goes
  live
- **Audit Trails**: Historical tracking of security risk remediation
