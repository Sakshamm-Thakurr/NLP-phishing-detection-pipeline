def calculate_verdict(header_results, url_results, nlp_results, ml_results=None):
    """
    Combines scores from all modules into one final verdict.
    """
    header_score = header_results.get("risk_score", 0)
    url_score    = url_results.get("risk_score", 0)
    nlp_score    = nlp_results.get("risk_score", 0)
    ml_score     = ml_results.get("risk_score", 0) if ml_results else 0
    total_score  = header_score + url_score + nlp_score + ml_score

    all_flags = (
        header_results.get("risk_flags", []) +
        url_results.get("risk_flags", []) +
        nlp_results.get("risk_flags", []) +
        (ml_results.get("risk_flags", []) if ml_results else [])
    )

    verdict, confidence, recommendation = _score_to_verdict(total_score, all_flags)

    return {
        "verdict":        verdict,
        "confidence":     confidence,
        "total_score":    total_score,
        "score_breakdown": {
            "header": header_score,
            "url":    url_score,
            "nlp":    nlp_score,
            "ml":     ml_score        # ← new
        },
        "ml_label":       ml_results.get("ml_label", "N/A") if ml_results else "N/A",
        "ml_confidence":  ml_results.get("ml_confidence", 0) if ml_results else 0,
        "total_flags":    len(all_flags),
        "flags":          all_flags,
        "recommendation": recommendation
    }


def _score_to_verdict(score, flags):
    """
    Scoring thresholds:
      0  - 20  → LOW       (likely safe)
      21 - 60  → MEDIUM    (suspicious, needs review)
      61 - 120 → HIGH      (very likely phishing)
      121+     → CRITICAL  (confirmed phishing indicators)
    """

    # Hard override — if brand spoofing or URL malicious, jump to CRITICAL
    critical_codes = {"BRAND_SPOOFING", "URL_MALICIOUS", "REPLY_TO_MISMATCH"}
    flag_codes     = {f["code"] for f in flags}

    if critical_codes & flag_codes:
        return (
            "CRITICAL",
            "Very High",
            "DO NOT interact with this email. Block sender domain, report to security team, and delete immediately."
        )

    if score >= 121:
        return (
            "CRITICAL",
            "Very High",
            "DO NOT interact with this email. Block sender domain, report to security team, and delete immediately."
        )
    elif score >= 61:
        return (
            "HIGH",
            "High",
            "Very likely phishing. Do not click links or reply. Forward to SOC for investigation."
        )
    elif score >= 21:
        return (
            "MEDIUM",
            "Medium",
            "Suspicious email. Do not click links. Verify sender through a separate channel before responding."
        )
    else:
        return (
            "LOW",
            "Low",
            "Email appears legitimate but stay cautious. Verify sender if unexpected."
        )