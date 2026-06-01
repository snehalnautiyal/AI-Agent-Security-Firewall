"""
PII Leakage Detector
--------------------
Scans text (usually LLM responses) for sensitive data that should never
leave the system: credit card numbers, API keys, passwords, email addresses,
social security numbers, and private keys.
"""

import re

# Each entry: (label, pattern, base_score)
PII_PATTERNS: list[tuple[str, str, int]] = [
    ("Credit card number",  r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b", 80),
    ("API key (generic)",   r"\b(?:sk-|pk-|api[-_]?key[-_]?)[a-zA-Z0-9_\-]{16,}\b", 85),
    ("AWS access key",      r"\bAKIA[0-9A-Z]{16}\b", 90),
    ("Private key header",  r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", 95),
    ("Password in text",    r"\b(password|passwd|pwd)\s*[:=]\s*\S+", 75),
    ("SSN (US)",            r"\b\d{3}-\d{2}-\d{4}\b", 80),
    ("Email address",       r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b", 35),
    ("Bearer token",        r"\bBearer\s+[a-zA-Z0-9\-._~+/]+=*\b", 85),
    ("GitHub token",        r"\bghp_[a-zA-Z0-9]{36}\b", 90),
    ("Slack token",         r"\bxox[baprs]-[0-9a-zA-Z\-]{10,}\b", 90),
]

_compiled_pii = [(label, re.compile(pattern, re.IGNORECASE), score) for label, pattern, score in PII_PATTERNS]


def score_pii_leakage(text: str) -> tuple[int, str, str]:
    """
    Return (risk_score, explanation, recommendation) for PII found in text.
    Checks responses for sensitive data that should not be exposed.
    """
    found_items: list[tuple[str, int]] = []  # (label, score)

    for label, pattern, base_score in _compiled_pii:
        if pattern.search(text):
            found_items.append((label, base_score))

    if not found_items:
        return 0, "", ""

    # Use the highest individual score as the overall score
    risk_score = max(score for _, score in found_items)
    labels = [label for label, _ in found_items]

    explanation = (
        f"Sensitive data detected in response: {', '.join(labels)}. "
        "This data should never appear in LLM output. It may indicate the model was "
        "trained on or has access to sensitive information, or that an attacker has "
        "successfully extracted it via prompt manipulation."
    )
    recommendation = (
        "Audit what data the model has access to. "
        "Apply output filtering to strip PII before returning responses to users. "
        "Use data loss prevention (DLP) tools in your pipeline. "
        "Never include real credentials or PII in prompts or training data."
    )
    return risk_score, explanation, recommendation
