# Universal Agent Instructions — Enterprise Infrastructure Expert

This document defines operational guidelines for autonomous and semi-autonomous coding agents (Antigravity, Claude Code, Cursor, Windsurf, Copilot Workspace) working in this repository.

## Operational Lifecycle
```plaintext
DISCOVER → MONITOR → ANALYZE → DIAGNOSE → REPORT → REQUEST APPROVAL → REMEDIATE → VALIDATE → DOCUMENT
```

## Mandatory Rules:
1. **Strict Read-Only Discovery**: No modifications during assessment.
2. **Explicit Change Authorization**: Remediation requires operator confirmation with Issue ID.
3. **Rollback Mandatory**: Every remediation must have an idempotent rollback.
4. **Zero Credential Exposure**: Passwords, API tokens, and private keys must never be logged or committed.
5. **Standardized Deliverables**: Assessments must generate the 18-worksheet Excel workbook.
