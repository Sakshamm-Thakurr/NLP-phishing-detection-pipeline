import json
import os
from modules.email_parser   import parse_eml
from modules.header_analyzer import analyze_headers
from modules.url_extractor   import analyze_urls
from modules.nlp_scorer      import score_body
from modules.verdict_engine  import calculate_verdict
from modules.ml_classifier import classify_email
EMAIL_PATH = "sample_emails/test1.eml"

def run_analysis(email_path):

    print("\n" + "=" * 60)
    print("        PHISHSENTINEL — PHISHING ANALYSIS ENGINE")
    print("=" * 60)
    print(f"  Analyzing: {email_path}\n")

    # ── Parse ────────────────────────────────────────────────
    parsed = parse_eml(email_path)
    print(f"  From    : {parsed['from']}")
    print(f"  To      : {parsed['to']}")
    print(f"  Subject : {parsed['subject']}")
    print(f"  URLs    : {len(parsed['urls'])} found")

    # ── Analyze ──────────────────────────────────────────────
    print("\n  Running header analysis...")
    headers = analyze_headers(parsed)

    print("  Running URL reputation checks...")
    urls = analyze_urls(parsed)

    print("  Running NLP body analysis...")
    nlp = score_body(parsed)

    print("  Running ML classifier (TF-IDF + Logistic Regression)...")
    ml = classify_email(parsed)

    # ── Verdict ──────────────────────────────────────────────
    report = calculate_verdict(headers, urls, nlp, ml)
    print(f"  ML Score      : {report['score_breakdown']['ml']}  [{report['ml_label']} — {report['ml_confidence']:.0%} confidence]")

    # ── Print Report ─────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  SCORE BREAKDOWN")
    print("=" * 60)
    print(f"  Header Score  : {report['score_breakdown']['header']}")
    print(f"  URL Score     : {report['score_breakdown']['url']}")
    print(f"  NLP Score     : {report['score_breakdown']['nlp']}")
    print(f"  Total Score   : {report['total_score']}")

    print("\n" + "=" * 60)
    print("  ALL FLAGS DETECTED")
    print("=" * 60)
    for flag in report["flags"]:
        print(f"  🚩 [{flag['code']}] +{flag['score']} pts")
        print(f"     {flag['message']}")

    print("\n" + "=" * 60)
    verdict_icons = {
        "LOW":      "🟢",
        "MEDIUM":   "🟡",
        "HIGH":     "🟠",
        "CRITICAL": "🔴"
    }
    icon = verdict_icons.get(report["verdict"], "⚪")
    print(f"  FINAL VERDICT  : {icon}  {report['verdict']}")
    print(f"  CONFIDENCE     : {report['confidence']}")
    print(f"  RECOMMENDATION : {report['recommendation']}")
    print("=" * 60 + "\n")

    # ── Save JSON report ─────────────────────────────────────
    os.makedirs("reports", exist_ok=True)
    report_path = "reports/latest_report.json"
    with open(report_path, "w") as f:
        json.dump({
            "email":  {
                "from":    parsed["from"],
                "subject": parsed["subject"],
                "urls":    parsed["urls"]
            },
            "report": report
        }, f, indent=2)
    print(f"  Full report saved → {report_path}\n")


if __name__ == "__main__":
    run_analysis(EMAIL_PATH)