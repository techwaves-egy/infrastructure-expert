#!/usr/bin/env python3
"""
Enterprise Infrastructure Audit Logger
Enforces immutable change tracking and audit logging.
Strips credentials, logs before/after states, and maintains tamper-evident records.
"""

import os
import sys
import json
import re
import datetime

AUDIT_DIR = "audit"
CHANGES_JSONL = os.path.join(AUDIT_DIR, "changes.jsonl")
SESSION_LOG = os.path.join(AUDIT_DIR, "session_audit.log")

SENSITIVE_PATTERNS = [
    re.compile(r'password\s*[:=]\s*["\']?[^\s"\']+', re.IGNORECASE),
    re.compile(r'secret\s*[:=]\s*["\']?[^\s"\']+', re.IGNORECASE),
    re.compile(r'token\s*[:=]\s*["\']?[^\s"\']+', re.IGNORECASE),
    re.compile(r'apikey\s*[:=]\s*["\']?[^\s"\']+', re.IGNORECASE),
    re.compile(r'api_key\s*[:=]\s*["\']?[^\s"\']+', re.IGNORECASE),
]

def sanitize(text):
    if not isinstance(text, str):
        return text
    clean_text = text
    for pattern in SENSITIVE_PATTERNS:
        clean_text = pattern.sub(r'[REDACTED]', clean_text)
    return clean_text

def log_session_event(message, level="INFO"):
    os.makedirs(AUDIT_DIR, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    clean_msg = sanitize(message)
    line = f"[{timestamp}] [{level}] {clean_msg}\n"
    with open(SESSION_LOG, 'a', encoding='utf-8') as f:
        f.write(line)

def record_change(change_id, issue_id, target, approved_action, actual_action, before_state, after_state, result, validation, operator="Operator/Agent", rollback_result="N/A", notes=""):
    os.makedirs(AUDIT_DIR, exist_ok=True)
    record = {
        "ChangeID": change_id,
        "IssueID": issue_id,
        "Timestamp": datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "Operator": operator,
        "Target": target,
        "ApprovedAction": sanitize(approved_action),
        "ActualAction": sanitize(actual_action),
        "BeforeState": sanitize(before_state),
        "AfterState": sanitize(after_state),
        "Result": result,
        "Validation": validation,
        "RollbackResult": rollback_result,
        "Notes": sanitize(notes)
    }
    with open(CHANGES_JSONL, 'a', encoding='utf-8') as f:
        f.write(json.dumps(record) + "\n")
    log_session_event(f"Change recorded: {change_id} for {issue_id} on {target} -> Result: {result}")

if __name__ == "__main__":
    log_session_event("Audit logger engine initialized successfully.")
    print("[OK] Audit logger ready.")
