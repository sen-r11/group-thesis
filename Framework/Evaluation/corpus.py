# Loads and checks the labelled telemetry used for evaluation

import csv
import os

VALID_LABELS = {"malicious", "benign"}
VALID_FAMILIES = {"ransomware", "spyware", "rat"}

def load_corpus(manifest_path):
    samples = []
    sample_ids = set()

    base_dir = os.path.dirname(os.path.abspath(manifest_path))

    with open(manifest_path, "r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)

        required = {"sample_id", "path", "label", "family"}
        columns = set(reader.fieldnames or [])

        missing = required - columns
        if missing:
            raise ValueError(
                "missing corpus columns: %s" % ", ".join(sorted(missing))
            )

        for row_number, row in enumerate(reader, start=2):
            sample_id = (row.get("sample_id") or "").strip()
            sample_path = (row.get("path") or "").strip()
            label = (row.get("label") or "").strip().lower()
            family = (row.get("family") or "").strip().lower()

            if not sample_id:
                raise ValueError("missing sample_id on row %s" % row_number)

            if sample_id in sample_ids:
                raise ValueError("duplicate sample_id: %s" % sample_id)

            if label not in VALID_LABELS:
                raise ValueError("invalid label for %s: %s" % (sample_id, label))

            if label == "malicious":
                if family not in VALID_FAMILIES:
                    raise ValueError("invalid malware family for %s: %s" % (sample_id, family))
            else:
                family = None

            if not sample_path:
                raise ValueError("missing telemetry path for %s" % sample_id)

            if not os.path.isabs(sample_path):
                sample_path = os.path.join(base_dir, sample_path)

            sample_path = os.path.normpath(sample_path)

            if not os.path.isfile(sample_path):
                raise FileNotFoundError("telemetry file not found for %s: %s" % (sample_id, sample_path))

            samples.append(
                {
                  "sample_id": sample_id,
                  "path": sample_path,
                  "label": label,
                  "family": family,
                }
            )

            sample_ids.add(sample_id)

        return samples
            
            