# runs labelled telemetry through the detection engine

import argparse
import json
import os
import sys
from statistics import mean

from sklearn.metrics import(accuracy_score, confusion_matrix, f1_score, precision_score, recall_score)

FRAMEWORK_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if FRAMEWORK_ROOT not in sys.path:
    sys.path.insert(0, FRAMEWORK_ROOT)

import parse

from Detection.engine import DetectionEngine, DEFAULT_THRESHOLD
from Evaluation.corpus import load_corpus

FILE_EVENT_IDS = {11, 23}

def run_sample(sample, threshold=DEFAULT_THRESHOLD):
    engine = DetectionEngine(threshold=threshold)

    first_event_time = None
    first_detection_time = None
    events_until_detection = None
    file_event_count_until_detection = 0

    events = parse.open_file(sample["path"])

    for event in events:
        event_time = float(event.get("time") or 0.0)
        event_id = int(event.get("event_id") or 0)

        if first_event_time is None:
            first_event_time = event_time

        if first_detection_time is None and event_id in FILE_EVENT_IDS:
            file_event_count_until_detection += 1

        new_alerts = engine.process_event(event)

        if new_alerts and first_detection_time is None:
            first_detection_time = event_time
            events_until_detection = engine.events_processed

    result = engine.result()

    if first_detection_time is not None:
        detection_delay = first_detection_time - first_event_time
    else:
        detection_delay = None
        file_event_count_until_detection = None

    return{
        "sample_id": sample["sample_id"],
        "telemetry_path": sample["path"],
        "expected_verdict": sample["label"],
        "predicted_verdict": result["verdict"],
        "expected_family": sample["family"],
        "predicted_family": result.get("family"),
        "score": result["score"],
        "threshold": result["threshold"],
        "family_scores": result["family_scores"],
        "possible_families": result["possible_families"],
        "triggered_indicators": result["triggered_indicators"],
        "events_processed": result["events_processed"],
        "events_until_detection": events_until_detection,
        "file_event_count_until_detection": file_event_count_until_detection,
        "first_detection_time": first_detection_time,
        "detection_delay_seconds": (
            round(detection_delay, 4)
            if detection_delay is not None
            else None
        ),
    }

def run_corpus(manifest_path, threshold=DEFAULT_THRESHOLD):
    corpus = load_corpus(manifest_path)
    results = []

    for sample in corpus:
        print("Evaluating %s..." % sample["sample_id"])
        result = run_sample(sample, threshold=threshold)
        results.append(result)

    return results

def calculate_metrics(results):
    expected = [result["expected_verdict"] for result in results]
    predicted = [result["predicted_verdict"] for result in results]

    matrix = confusion_matrix(
        expected,
        predicted,
        labels=["benign", "malicious"]
    )

    tn, fp, fn, tp = matrix.ravel()

    accuracy = accuracy_score(
        expected,
        predicted,
    )

    precision = precision_score(
        expected,
        predicted,
        pos_label="malicious",
        zero_division=0,
    )

    recall = recall_score(
        expected,
        predicted,
        pos_label="malicious",
        zero_division=0
    )

    f1 = f1_score(
        expected,
        predicted,
        pos_label="malicious",
        zero_division=0
    )

    family_results = [
        result
        for result in results
        if result["expected_verdict"] == "malicious"
        and result["predicted_verdict"] == "malicious"
    ]

    family_expected = [
            result["expected_family"]
            for result in family_results
        ]

    family_predicted = [
        result["predicted_family"]
        for result in family_results
    ]

    if family_results:
        detected_family_classification_accuracy = (
            accuracy_score(
                family_expected,
                family_predicted
            )
        )

    else:
        detected_family_classification_accuracy = None

    detection_delays = [
        result["detection_delay_seconds"]
        for result in results
        if result["expected_verdict"] == "malicious"
        and result["detection_delay_seconds"] is not None
    ]

    mean_detection_delay = (
        mean(detection_delays)
        if detection_delays
        else None
    )

    return {
        "true_positive": int(tp),
        "false_positive": int(fp),
        "true_negative": int(tn),
        "false_negative": int(fn),
        "accuracy": round(float(accuracy), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1_score": round(float(f1), 4),
        "family_evaluated": len(family_results),
        "detected_family_classification_accuracy": round(
            float(
                detected_family_classification_accuracy
            ),
            4,
        ),
        "mean_detection_delay_seconds": (
            round(mean_detection_delay, 4)
            if mean_detection_delay is not None
            else None
        ),
    }






def print_summary(metrics):
    print("\n=== Evaluation Results ===")

    print(
        "TP: %s FP: %s TN: %s FN: %s"
        % (
            metrics["true_positive"],
            metrics["false_positive"],
            metrics["true_negative"],
            metrics["false_negative"],
        )
    )

    print("Accuracy:  %.3f" % metrics["accuracy"])
    print("Precision:  %.3f" % metrics["precision"])
    print("Recall:  %.3f" % metrics["recall"])
    print("F1 Score:  %.3f" % metrics["f1_score"])
    print("Detected Family Classification Accuracy:  %.3f" % metrics["detected_family_classification_accuracy"])

    if metrics["mean_detection_delay_seconds"] is not None:
        print("Mean Detection Delay:  %.3f seconds" % metrics["mean_detection_delay_seconds"])

def main(argv=None):
    parser = argparse.ArgumentParser(
        description= "Evaluate the malware detection framework"
    )

    parser.add_argument(
        "manifest",
        help="CSV file containing the labelled evaluation corpus",
    )

    parser.add_argument(
        "--threshold",
        type=float,
        default=DEFAULT_THRESHOLD,
        help="detection threshold used during evaluation",
    )

    parser.add_argument(
        "--json",
        metavar="FILE",
        help="write evaluation results to JSON",
    )

    args = parser.parse_args(argv)

    try:
        results = run_corpus(
            args.manifest,
            threshold=args.threshold,
        )

        metrics = calculate_metrics(results)

    except (OSError, ValueError, RuntimeError) as problem:
        print("error: %s" % problem, file=sys.stderr)
        return 2

    print_summary(metrics)

    if args.json:
        output = {
            "threshold": args.threshold,
            "samples": results,
            "metrics": metrics,
        }

        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(output, handle, indent=2)

        print("\nResults written to %s" % args.json)

    return 0

if __name__ == "__main__":
    sys.exit(main())