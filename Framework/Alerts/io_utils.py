import json
from pathlib import Path

"""file i/o helpers for the alrts generator"""

"""read the detection engine results and write to a json file"""
def loadDetectionResult(filepath):
        path = Path(filepath)
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)

"""Write the machine readable alerts to JSON file"""
def writeAlertsJson(filepath, alerts):
    path = Path(filepath)
    with path.open("w", encoding="utf-8") as f:
        json.dump({"alerts": alerts}, f, indent=2)
