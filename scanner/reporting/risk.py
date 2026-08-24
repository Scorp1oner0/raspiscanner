"""Aggregazione delle severita' delle security findings in un riepilogo."""

SEVERITY_ORDER = ("critical", "high", "medium", "low")


def summarize(all_findings):
    """all_findings: lista piatta di finding {"severity": ...} da tutti i
    dispositivi di una rete. Ritorna {"critical": n, "high": n, "medium": n, "low": n}.
    """
    counts = {level: 0 for level in SEVERITY_ORDER}
    for finding in all_findings:
        severity = finding.get("severity", "low")
        if severity in counts:
            counts[severity] += 1
    return counts
