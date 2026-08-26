# Behaviour-based detection engine for normalised Sysmon events

import argparse
import json
import os
import sys
from dataclasses import asdict
from typing import Dict, Iterable, List

# Lets the file work with both "python -m Detection.engine" and direct runs
FRAMEWORK_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if FRAMEWORK_ROOT not in sys.path:
    sys.path.insert(0, FRAMEWORK_ROOT)
    
import parse

from Detection.indicators import DETECTORS
from Detection.state import Evidence, FAMILIES, StateStore

DEFAULT_THRESHOLD = 0.70
FAMILY_MARGIN = 0.15

class DetectionEngine:
    def __init__(self, threshold: float = DEFAULT_THRESHOLD) -> None:
        if not 0.0 < threshold <= 1.0:
            raise ValueError("threshold must be between 0 and 1")
        
        self.threshold = float(threshold)
        self.state = StateStore()
        self.events_processed = 0
        self.alerts: List[Dict[str, object]] = []
        self._alerted = set()

    def process_event(self, event: Dict[str, object]) -> List[Dict[str, object]]:
        self.events_processed += 1
        direct_state = self.state.observe(event)
        new_alerts = []

        for detector in DETECTORS:
            findings = detector(event, self.state, direct_state)

            for finding in findings:
                if finding.target_pid is not None:
                    target = self.state.ensure(finding.target_pid)
                else:
                    target = self.state.attribution_state(direct_state.pid)

                if finding.fingerprint in target.fired:
                    continue

                target.fired.add(finding.fingerprint)
                score_key = finding.score_key or finding.fingerprint
                applied_weights = {}

                if score_key not in target.scored:
                    target.scored.add(score_key)
                    target.add_scores(finding.weights)
                    applied_weights = finding.weights

                target.evidence.append(
                    Evidence(
                        indicator=finding.indicator,
                        description=finding.description,
                        time=float(event.get("time") or 0.0),
                        event_id=int(event.get("event_id") or 0),
                        process=direct_state.process,
                        details=finding.details,
                        weights=applied_weights,
                    )
                )

                family, score, possible_families = self._family_matches(target)
                alert_key = (target.pid, family)

                if score >= self.threshold and alert_key not in self._alerted:
                    self._alerted.add(alert_key)
                    alert = self._make_alert(target.pid, family, score, possible_families)
                    self.alerts.append(alert)
                    new_alerts.append(alert)

        return new_alerts
    
    def process(self, events: Iterable[Dict[str,object]]) -> Dict[str, object]:
        for event in events:
            self.process_event(event)
        return self.result()
    
    def _family_matches(self,state):
        ranked = sorted(
            state.family_scores.items(),
            key=lambda item: item[1],
            reverse=True,
        )

        leading_family, leading_score = ranked[0]

        possible_families = [
            family 
            for family, score in ranked
            if score > 0 and leading_score - score <= FAMILY_MARGIN
        ]

        return leading_family, leading_score, possible_families
    
    def _make_alert(self, pid: int, family: str, score: float, possible_families: List[str]) -> Dict[str, object]:
        state = self.state.ensure(pid)
        return {
            "verdict": "malicious",
            "family": family,
            "possible_families": possible_families,
            "score": round(score, 3),
            "threshold": self.threshold,
            "pid": state.pid,
            "process": state.process,
            "family_scores": {name: round(value, 3) for name, value in state.family_scores.items()},
            "triggered_indicators": [item.indicator for item in state.evidence],
            "evidence": [asdict(item) for item in state.evidence],
            "process_tree": self.state.process_tree(state.pid),
        }
    
    def result(self) -> Dict[str, object]:
        candidates = []

        for state in self.state.processes.values():
            if not state.evidence:
                continue
            family, score, possible_families = self._family_matches(state)
            candidates.append((score, family, possible_families, state))

        if not candidates:
            return {
                "verdict": "benign",
                "family": None,
                "leading_family": None,
                "possible_families": [],
                "score": 0.0,
                "threshold": self.threshold,
                "events_processed": self.events_processed,
                "pid": None,
                "process": None,
                "family_scores": {family: 0.0 for family in FAMILIES},
                "triggered_indicators": [],
                "evidence": [],
                "process_tree": None,
            }
        
        score, family, possible_families, state = max(candidates, key=lambda item: item[0])
        verdict = "malicious" if score >= self.threshold else "benign"

        return{
            "verdict": verdict,
            "family": family if verdict == "malicious" else None,
            "leading_family": family,
            "possible_families": possible_families if verdict == "malicious" else [],
            "score": round(score, 3),
            "threshold": self.threshold,
            "events_processed": self.events_processed,
            "pid": state.pid,
            "process": state.process,
            "family_scores": {name: round(value, 3) for name, value in state.family_scores.items()},
            "triggered_indicators": [item.indicator for item in state.evidence],
            "evidence": [asdict(item) for item in state.evidence],
            "process_tree": self.state.process_tree(state.pid),
        }
    
def analyse_events(events: Iterable[Dict[str,object]], threshold: float = DEFAULT_THRESHOLD):
    return DetectionEngine(threshold=threshold).process(events)

def print_result(result: Dict[str,object]) -> None:
    print("\n=== Detection Result ===")
    print("Verdict: %s" % str(result["verdict"]).upper())

    if result.get("family"):
        print("Family: %s" % result["family"])

    print("Score: %.3f / %.3f" % (result["score"], result["threshold"]))

    print("Events processed: %s" % result["events_processed"])

def main(argv=None) -> int:
    arg_parser = argparse.ArgumentParser(description="Analyse normalised Sysmon telemetry")
    arg_parser.add_argument("path", help="a .jsonl parser output, or a .xml/.evtx file",)
    arg_parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD, help="score required for malicious verdict",)
    arg_parser.add_argument("--json", metavar="FILE", help="write the final result to JSON",)
    args = arg_parser.parse_args(argv)

    try: 
        events = parse.open_file(args.path)
        result = analyse_events(events, threshold=args.threshold)
    except (OSError, ValueError, RuntimeError) as problem:
        print("error: %s" % problem, file=sys.stderr)
        return 2
    
    print_result(result)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle: json.dump(result,handle, indent=2)
        print("\nwritten to %s" % args.json)

    return 0

if __name__ == "__main__":
    sys.exit(main())



        

        



