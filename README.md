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

### Batch Processing
1. Go to `/admin/config/analyze/content-security-audit/batch`
2. Select content types and processing limits
3. Choose per-vector processing for focused audits
4. Monitor security analysis progress

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

## Batch Processing

This module integrates with the centralized batch processing system provided
by the Analyze base module. Use the Analyze batch UI or Drush commands to
process content across all enabled analyzers, including security audits.

- Select specific content types for targeted analysis
- Use per-vector processing for focused security audits
- Force re-analysis when security policies change
- Run batch processing via Drush: `drush analyze:batch`

## Compliance Use Cases

- **Privacy Regulations**: GDPR, CCPA, HIPAA compliance
- **Data Breach Prevention**: Proactive sensitive information detection
- **Publication Workflows**: Security risk assessment before content goes
  live
- **Audit Trails**: Historical tracking of security risk remediation
