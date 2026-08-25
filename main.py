from .alertGenerator import AlertGenerator

"""main for running the alert generator"""


def main():
    input_file = "Alerts/test_data/result.json"
    output_file = "Alerts/alerts.json"

    alertGen = AlertGenerator(input_file, output_file)
    alertGen.run()


if __name__ == "__main__":
    main()