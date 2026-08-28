"""Case Assignment & Ownership Manager.

Adds analyst ownership, status lifecycle, and investigation notes to cases.
Prevents duplicate investigation by making case ownership visible.
"""
import json
import os
import time
import threading

_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
_CASES_FILE = os.path.join(_DIR, "cases.json")
_lock = threading.Lock()

_VALID_STATUSES = {"open", "in_progress", "pending", "closed", "resolved"}


def _load_cases() -> list:
    try:
        with open(_CASES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _save_cases(cases: list):
    os.makedirs(os.path.dirname(_CASES_FILE), exist_ok=True)
    with _lock:
        with open(_CASES_FILE, "w", encoding="utf-8") as f:
            json.dump(cases, f, indent=2, ensure_ascii=False)


def _find_case(cases: list, case_id: str) -> dict | None:
    return next((c for c in cases if str(c.get("id")) == str(case_id)), None)


def assign_case(case_id: str, analyst: str, assigned_by: str = "system") -> dict | None:
    """Assign a case to an analyst."""
    cases = _load_cases()
    case = _find_case(cases, case_id)
    if not case:
        return None
    
    old_assignee = case.get("assigned_to")
    case["assigned_to"] = analyst
    case["assigned_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    case["assigned_by"] = assigned_by
    if case.get("status", "open") == "open":
        case["status"] = "in_progress"
    
    # Add assignment note
    if "notes" not in case:
        case["notes"] = []
    note_text = f"Assigned to {analyst}"
    if old_assignee:
        note_text += f" (transferred from {old_assignee})"
    note_text += f" by {assigned_by}"
    case["notes"].append({
        "author": assigned_by,
        "text": note_text,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "type": "assignment",
    })
    
    _save_cases(cases)
    return case


def claim_case(case_id: str, analyst: str) -> dict | None:
    """Self-assign (claim) a case."""
    return assign_case(case_id, analyst, assigned_by=analyst)


def transfer_case(case_id: str, to_analyst: str, by_analyst: str,
                  reason: str = "") -> dict | None:
    """Transfer a case from one analyst to another."""
    cases = _load_cases()
    case = _find_case(cases, case_id)
    if not case:
        return None
    
    old_assignee = case.get("assigned_to", "(unassigned)")
    case["assigned_to"] = to_analyst
    case["assigned_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    case["assigned_by"] = by_analyst
    
    if "notes" not in case:
        case["notes"] = []
    note = f"Transferred from {old_assignee} to {to_analyst}"
    if reason:
        note += f": {reason}"
    case["notes"].append({
        "author": by_analyst,
        "text": note,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "type": "transfer",
    })
    
    _save_cases(cases)
    return case


def update_status(case_id: str, status: str, analyst: str = "system") -> dict | None:
    """Update case status."""
    if status not in _VALID_STATUSES:
        return None
    
    cases = _load_cases()
    case = _find_case(cases, case_id)
    if not case:
        return None
    
    old_status = case.get("status", "open")
    case["status"] = status
    case["status_updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    
    if "notes" not in case:
        case["notes"] = []
    case["notes"].append({
        "author": analyst,
        "text": f"Status changed: {old_status} -> {status}",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "type": "status_change",
    })
    
    if status in ("closed", "resolved"):
        case["closed_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        case["closed_by"] = analyst
    
    _save_cases(cases)
    return case


def add_note(case_id: str, analyst: str, text: str) -> dict | None:
    """Add an investigation note to a case."""
    if not text or not text.strip():
        return None
    
    cases = _load_cases()
    case = _find_case(cases, case_id)
    if not case:
        return None
    
    if "notes" not in case:
        case["notes"] = []
    case["notes"].append({
        "author": analyst,
        "text": text.strip(),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "type": "investigation",
    })
    
    _save_cases(cases)
    return case


def get_my_cases(analyst: str) -> list:
    """Get all cases assigned to a specific analyst."""
    cases = _load_cases()
    return [c for c in cases if c.get("assigned_to") == analyst]


def get_unassigned_cases() -> list:
    """Get the triage queue — cases with no owner."""
    cases = _load_cases()
    return [
        c for c in cases
        if not c.get("assigned_to")
        and c.get("status", "open") not in ("closed", "resolved")
    ]


def get_case_with_notes(case_id: str) -> dict | None:
    """Get a single case with its full note history."""
    cases = _load_cases()
    return _find_case(cases, case_id)
