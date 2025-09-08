# AuditMind - Adversarial Risk Auditor Chatbot

AuditMind is an adversarial-but-constructive risk auditor that analyzes documents (code, design docs, policies, etc.) and produces structured surface-level risk reports in JSON format.

## Features

- **Adversarial Analysis**: Always assumes risks exist and tries to surface them
- **Multi-Category Risk Detection**: Security, Privacy, Compliance, Ethical/Fairness, Operational
- **Structured JSON Output**: Machine-readable results for system integration
- **Sensitive Data Masking**: Automatically masks credentials and secrets
- **Interactive Chat Interface**: Easy-to-use command-line interface

## Risk Categories

1. **Security**: Hardcoded credentials, code injection, insecure protocols, SQL injection
2. **Privacy**: PII handling, tracking mechanisms, logging issues
3. **Compliance**: Regulatory references, data retention policies
4. **Ethical/Fairness**: Algorithmic bias, fairness concerns, AI/ML issues
5. **Operational**: Technical debt, performance issues, timeouts

## Usage

### Interactive Mode
```bash
python audit_mind.py
```

### Programmatic Usage
```python
from audit_mind import AuditMind

auditor = AuditMind()
result = auditor.analyze_document("your document here", "document_type")
print(json.dumps(result, indent=2))
```

### Example Output
```json
{
  "timestamp": "2025-09-03T14:30:00",
  "document_type": "code",
  "summary": "Found 2 potential risks",
  "risks": [
    {
      "id": "SEC001",
      "category": "security", 
      "severity": "high",
      "issue": "Hardcoded credentials detected",
      "explanation": "Hardcoded credentials in source code can be exposed in version control",
      "suggested_mitigation": "Use environment variables or secure credential management systems"
    }
  ],
  "uncertain": false
}
```

## Commands

- `help` - Show available commands
- `quit` or `exit` - Exit the program
- Paste any document to analyze for risks

## Installation

No external dependencies required. Uses Python standard library only.

```bash
git clone <repository>
cd AuditMind
python audit_mind.py
```

## Examples

Run the example script to see AuditMind in action:

```bash
python example_usage.py
```

## Core Principles

- **Adversarial but Constructive**: Always look for risks but provide actionable solutions
- **Specific Mitigations**: Never provide vague advice, always give clear fixes
- **Privacy Preserving**: Masks sensitive data like API keys and passwords
- **Structured Output**: JSON format for easy integration into CI/CD pipelines