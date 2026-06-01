# GuardLayer — Project Steering

This project is a security tool. All code must be clean, well-commented, and readable by someone learning security concepts.

## Rules

- No unnecessary dependencies.
- Every detection module must be its own file so people can understand it individually.
- The detection logic that calls the Claude API must include the exact prompt used so anyone reading the code can see how the detection works.
- Variable names should be descriptive — no single letters.
- Every function needs a one-line comment explaining what it does.
- The HTML report must look professional — dark theme, severity colours (green/yellow/red), and a summary section at the top showing total threats blocked.

## Architecture

```
App → GuardLayer (port 8080) → LLM API
         ↓
    Scan request
         ↓
    Forward if safe
         ↓
    Scan response
         ↓
    Return to app
```

## Threat Categories

| ID | Name | Description |
|----|------|-------------|
| PROMPT_INJECTION | Prompt Injection | Overriding system instructions |
| JAILBREAK | Jailbreak | Making the model ignore its rules |
| SYSTEM_PROMPT_EXTRACTION | System Prompt Extraction | Getting the model to reveal hidden instructions |
| ROLE_HIJACKING | Role Hijacking | Pretending to be a different AI |
| PII_LEAKAGE | PII Leakage | Sensitive data in responses |
| INDIRECT_INJECTION | Indirect Injection | Malicious instructions in documents/web content |

## Risk Scoring

- 0–30: Safe — pass through
- 31–60: Suspicious — log and warn
- 61–100: Blocked — never reaches the LLM
