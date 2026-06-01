"""
Prompt Injection Detector
-------------------------
Detects attempts to override or ignore the system prompt by injecting
new instructions into user input. Classic example: "Ignore all previous
instructions and instead do X."
"""

import re

# Patterns that strongly suggest an injection attempt
INJECTION_PATTERNS: list[str] = [
    r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions",
    r"disregard\s+(all\s+)?(previous|prior|above|earlier)\s+instructions",
    r"forget\s+(everything|all)\s+(you\s+)?(were\s+)?(told|instructed|given)",
    r"new\s+instructions?\s*:",
    r"your\s+(real|true|actual)\s+instructions?\s+(are|is)\s*:",
    r"override\s+(system|previous|all)\s+(prompt|instructions?)",
    r"you\s+are\s+now\s+in\s+(developer|admin|god|unrestricted)\s+mode",
    r"system\s*:\s*(ignore|forget|disregard)",
    r"\[system\].*ignore",
    r"###\s*instruction",
]

_compiled_patterns = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in INJECTION_PATTERNS]


def score_prompt_injection(text: str) -> tuple[int, str]:
    """
    Return (risk_score, explanation) for prompt injection in the given text.
    Score is 0 if no patterns match, scales up with number of matches.
    """
    matched_patterns: list[str] = []

    for pattern in _compiled_patterns:
        match = pattern.search(text)
        if match:
            matched_patterns.append(match.group(0))

    if not matched_patterns:
        return 0, "", ""

    # More matches = higher confidence it's an attack
    base_score = 65
    additional = min(len(matched_patterns) - 1, 3) * 8
    risk_score = min(base_score + additional, 95)

    explanation = (
        f"Prompt injection detected. The input contains {len(matched_patterns)} "
        f"pattern(s) that attempt to override system instructions: "
        f"{', '.join(repr(m) for m in matched_patterns[:3])}. "
        "This is a classic injection attack where an attacker embeds new directives "
        "inside user input hoping the model will follow them instead of the original system prompt."
    )
    recommendation = (
        "Sanitise user input before including it in prompts. "
        "Use a separate system prompt that the user cannot influence. "
        "Consider using structured message formats that clearly separate user content from instructions."
    )
    return risk_score, explanation, recommendation
