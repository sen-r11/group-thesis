from .io_utils import loadDetectionResult, writeAlertsJson
from .formatting import formatHumanReadable, formatMachineReadable

"""alert generator combines loading, formatting, and output"""
"""takes in detection engine output and creates alerts"""
class AlertGenerator:

    def __init__(self, input_filepath, output_filepath):
        self.input_filepath = input_filepath
        self.output_filepath = output_filepath


    """load detection results, print human readable alerts, write machine alerts"""
    def run(self):
        result = loadDetectionResult(self.input_filepath)

        print(formatHumanReadable(result))
        print()

        machine_alert = formatMachineReadable(result)
        writeAlertsJson(self.output_filepath, [machine_alert])


        print(f"Alert written to file {self.output_filepath}")
