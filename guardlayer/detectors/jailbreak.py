"""
Jailbreak Detector
------------------
Detects attempts to make the model bypass its safety guidelines.
Common techniques: DAN (Do Anything Now), fictional framing, hypothetical
scenarios designed to extract restricted content.
"""

import re

# Patterns associated with known jailbreak techniques
JAILBREAK_PATTERNS: list[str] = [
    r"\bDAN\b",                                          # Do Anything Now
    r"do\s+anything\s+now",
    r"jailbreak",
    r"no\s+restrictions?",
    r"without\s+(any\s+)?(restrictions?|limits?|filters?|guidelines?|rules?)",
    r"pretend\s+(there\s+are\s+no|you\s+have\s+no)\s+(rules?|restrictions?|guidelines?)",
    r"in\s+this\s+(hypothetical|fictional|imaginary)\s+(scenario|world|universe)",
    r"for\s+(educational|research|fictional)\s+purposes?\s+only",
    r"as\s+a\s+(fictional|hypothetical)\s+(character|AI|assistant)",
    r"you\s+are\s+now\s+free\s+from",
    r"your\s+(true|real)\s+self\s+(has\s+no|without)\s+(restrictions?|limits?)",
    r"enable\s+(developer|god|unrestricted|jailbreak)\s+mode",
    r"act\s+as\s+if\s+you\s+(have\s+no|were\s+not)\s+(restrictions?|trained|aligned)",
]

_compiled_patterns = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in JAILBREAK_PATTERNS]


def score_jailbreak(text: str) -> tuple[int, str, str]:
    """
    Return (risk_score, explanation, recommendation) for jailbreak attempts.
    """
    matched_patterns: list[str] = []

    for pattern in _compiled_patterns:
        match = pattern.search(text)
        if match:
            matched_patterns.append(match.group(0))

    if not matched_patterns:
        return 0, "", ""

    base_score = 70
    additional = min(len(matched_patterns) - 1, 3) * 7
    risk_score = min(base_score + additional, 95)

    explanation = (
        f"Jailbreak attempt detected. Found {len(matched_patterns)} indicator(s): "
        f"{', '.join(repr(m) for m in matched_patterns[:3])}. "
        "Jailbreaks use fictional framing, roleplay, or special 'modes' to convince "
        "the model to ignore its safety training and produce restricted content."
    )
    recommendation = (
        "Reject or flag inputs containing jailbreak language. "
        "Ensure your system prompt explicitly states the model's boundaries. "
        "Consider using a model with robust RLHF alignment for sensitive use cases."
    )
    return risk_score, explanation, recommendation
