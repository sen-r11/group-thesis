Alert Generator

Consumes detection engine output and produces alerts in two formats.
- Human readable text, printed to console.
- Machine readable JASON, written to file.

#How to run

Run from parent directory of "Alerts" so python can locate package

    python -m Alerts.main/py -m Alerts.main

Or point it at a different result file by adding 'main.py'

## Input
A detection engine result JASON file (default: 'Alerts/test_data/result.jason)

## Output

- Console: Human readable alerts
- File: 'Alerts/alerts.json' with structured alerts for evaluation