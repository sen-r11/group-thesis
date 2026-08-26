"""formatting functions that take in detection result and creates human and machine readable output"""

"""return the executable name from a full path"""
def format_process_names(path):
    if not path:
        return "unknown"
    return path.replace("/", "\\").split("\\")[-1]


"""make the weights easier to read"""
def format_weights(weights):
    if not weights:
        return "no score contribution"
    parts = [f"{family}: {value}" for family, value in weights.items()]
    return ", ".join(parts)


"""turn a detection result into a readable alert message"""
def formatHumanReadable(result):
    
    verdict = result.get("verdict", "unknown")
    family = result.get("family") or result.get("leading_family", "unknown")
    possible = result.get("possible_families", [])
    score = result.get("score", 0)
    threshold = result.get("threshold", 0)
    process = result.get("process", "unknown")
    pid = result.get("pid", "unknown")
    events_processed = result.get("events_processed", 0)
    family_scores = result.get("family_scores", {})
    evidence = result.get("evidence", [])

    lines = []
    lines.append(f"[{verdict.upper()}] {format_process_names(process)} (PID {pid})")
    lines.append(f"Family: {family} Score: {score} Threshold: {threshold}")

    if len(possible) > 1:
        lines.append(f"Possible families: {', '.join(possible)}")
    lines.append(f"Events processed: {events_processed}")

    if family_scores:
        score_parts = [f"{name}: {value}" for name, value in family_scores.items()]
        lines.append(f"Family scores: {', '.join(score_parts)}")
    lines.append("")

    if not evidence:
        if events_processed == 0:
            lines.append("No activity observed")
        else:
            lines.append("No suspicious indicators triggered")
    else:
        lines.append(f"{len(evidence)} indicator(s) triggered")
        for item in evidence:
            indicator = item.get("indicator", "unknown")
            description = item.get("description", "")
            weights = item.get("weights", {})
            lines.append(f" - {indicator}")
            lines.append(f" {description}")
            lines.append(f" weights: {format_weights(weights)}")
    return "\n".join(lines)

"""write detection results to a json file"""
def formatMachineReadable(result):
    evidence = result.get("evidence", [])

    return {
        "verdict": result.get("verdict", "unknown"),
        "family": result.get("family") or result.get("leading_family"),
        "possible_families": result.get("possible_families", []),
        "score": result.get("score", 0),
        "threshold": result.get("threshold", 0),
        "process": result.get("process", "unknown"),
        "pid": result.get("pid"),
        "events_processed": result.get("events_processed", 0),
        "family_scores": result.get("family_scores", {}),
        "indicator_count": len(evidence),
        "triggered_indicators": result.get("triggered_indicators", []),
        "indicators": [
            {
                "indicator": item.get("indicator", "unknown"),
                "description": item.get("description", ""),
                "event_id": item.get("event_id"),
                "time": item.get("time"),
                "process": item.get("process", ""),
                "details": item.get("details", {}),
                "weights": item.get("weights", {}),
            }
            for item in evidence
        ],
        "process_tree": result.get("process_tree"),

    }