"""
Indirect Injection Detector
----------------------------
Detects malicious instructions hidden inside external content that an AI
agent reads — documents, web pages, emails, database results. The attacker
doesn't talk to the model directly; they poison the data the model reads.
"""

import re

# Patterns that look like instructions embedded in "data" content
INDIRECT_INJECTION_PATTERNS: list[str] = [
    # Instructions hidden in HTML/markdown comments
    r"<!--.*?(ignore|forget|disregard|new\s+instructions?).*?-->",
    r"\[//\]:\s*#\s*\(.*?(ignore|instructions?).*?\)",

    # White-text / invisible text tricks (common in documents)
    r"<span\s+style=['\"]color:\s*white['\"]>.*?</span>",
    r"<font\s+color=['\"]#?(?:fff(?:fff)?|ffffff)['\"]>",

    # Explicit instruction injection in document content
    r"(note\s+to\s+(AI|assistant|model)|AI\s+instruction|assistant\s+instruction)\s*:",
    r"when\s+(you\s+)?(read|process|see)\s+this\s*,?\s*(please\s+)?(ignore|forget|instead)",
    r"(this\s+document|this\s+text|this\s+content)\s+(contains?|has)\s+(hidden\s+)?(instructions?|commands?)",

    # Prompt injection via tool/function output
    r"<tool_result>.*?(ignore|instructions?|system\s*:).*?</tool_result>",
    r"\[INST\].*?(ignore|override|new\s+instructions?).*?\[/INST\]",

    # Data exfiltration via URL embedding
    r"https?://[^\s]+\?[^\s]*(?:prompt|query|q|data)=[^\s]*",
]

_compiled_patterns = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in INDIRECT_INJECTION_PATTERNS]


def score_indirect_injection(text: str) -> tuple[int, str, str]:
    """
    Return (risk_score, explanation, recommendation) for indirect injection in text.
    Particularly important when the model is reading external documents or web content.
    """
    matched_patterns: list[str] = []

    for pattern in _compiled_patterns:
        match = pattern.search(text)
        if match:
            # Truncate long matches for readability
            matched_text = match.group(0)[:80]
            matched_patterns.append(matched_text)

    if not matched_patterns:
        return 0, "", ""

    base_score = 72
    additional = min(len(matched_patterns) - 1, 3) * 8
    risk_score = min(base_score + additional, 95)

    explanation = (
        f"Indirect prompt injection detected in external content. "
        f"Found {len(matched_patterns)} suspicious pattern(s): "
        f"{', '.join(repr(m) for m in matched_patterns[:2])}. "
        "An attacker has embedded instructions inside data the AI agent is reading. "
        "This is particularly dangerous in agentic systems that browse the web, "
        "read emails, or process documents — the model may follow attacker instructions "
        "without the user ever knowing."
    )
    recommendation = (
        "Treat all external content as untrusted. "
        "Use a separate context window for external data vs. instructions. "
        "Implement a content sanitisation step before feeding external data to the model. "
        "Consider using a model that distinguishes between data and instruction contexts."
    )
    return risk_score, explanation, recommendation
