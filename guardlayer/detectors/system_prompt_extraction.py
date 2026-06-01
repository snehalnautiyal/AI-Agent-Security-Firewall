"""
System Prompt Extraction Detector
----------------------------------
Detects attempts to get the model to reveal its hidden system prompt.
Attackers use this to understand the application's instructions so they
can craft more targeted attacks.
"""

import re

EXTRACTION_PATTERNS: list[str] = [
    r"(repeat|print|show|tell\s+me|reveal|output|display|write\s+out)\s+(your\s+)?(system\s+prompt|initial\s+instructions?|original\s+prompt|hidden\s+instructions?)",
    r"what\s+(are|were)\s+your\s+(original|initial|system|hidden)\s+instructions?",
    r"what\s+did\s+(they|the\s+developer|your\s+creator)\s+tell\s+you",
    r"ignore\s+.*\s+and\s+(print|repeat|show|output)\s+(everything|all|the\s+above)",
    r"output\s+everything\s+(above|before)\s+this",
    r"print\s+the\s+contents?\s+of\s+your\s+(context|prompt|memory)",
    r"what\s+is\s+in\s+your\s+(system|context)\s+(prompt|window|message)",
    r"summarize\s+your\s+(instructions?|system\s+prompt|context)",
    r"translate\s+your\s+(system\s+prompt|instructions?)\s+to",
]

_compiled_patterns = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in EXTRACTION_PATTERNS]


def score_system_prompt_extraction(text: str) -> tuple[int, str, str]:
    """
    Return (risk_score, explanation, recommendation) for system prompt extraction attempts.
    """
    matched_patterns: list[str] = []

    for pattern in _compiled_patterns:
        match = pattern.search(text)
        if match:
            matched_patterns.append(match.group(0))

    if not matched_patterns:
        return 0, "", ""

    base_score = 60
    additional = min(len(matched_patterns) - 1, 3) * 10
    risk_score = min(base_score + additional, 90)

    explanation = (
        f"System prompt extraction attempt detected. Found {len(matched_patterns)} indicator(s): "
        f"{', '.join(repr(m) for m in matched_patterns[:3])}. "
        "The user is trying to get the model to reveal its hidden system instructions. "
        "This is often a reconnaissance step before a more targeted attack."
    )
    recommendation = (
        "Instruct the model in the system prompt to never repeat its instructions. "
        "Treat the system prompt as a secret — don't include API keys or sensitive business logic in it. "
        "Consider using a separate secrets manager for sensitive configuration."
    )
    return risk_score, explanation, recommendation
