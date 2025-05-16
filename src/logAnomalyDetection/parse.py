#!/usr/bin/env python

import sys
import os
sys.path.append('../../')  # Adjust path for local imports

from src.logAnomalyDetection.Brain import LogParser
from pipeline import process_logs_from_csv  # Import your pipeline function here

def parse_and_process(
    dataset='Linux',
    input_dir='../../data/logs/raw/',
    output_dir='../../data/logs/processed/',
    log_file='Linux_test.log',
    log_format="<Month> <Date> <Time> <Level> <Component>(\[<PID>\])?: <Content>",
    regex=None,
    threshold=4,
    delimeter=None
):
    if regex is None:
        regex = [r"(\d+\.){3}\d+", r"\d{2}:\d{2}:\d{2}", r"J([a-z]{2})"]
    if delimeter is None:
        delimeter = [r""]

    print(f"Starting parse_and_process for log file: {log_file}")

    parser = LogParser(
        logname=dataset,
        log_format=log_format,
        indir=input_dir,
        outdir=output_dir,
        threshold=threshold,
        delimeter=delimeter,
        rex=regex
    )

    # Parse raw logs
    print(f"Parsing raw logs from {os.path.join(input_dir, log_file)}")
    parser.parse(log_file)
    print(f"Parsing completed. Output in {output_dir}")

    # Process the structured CSV logs
    structured_csv = os.path.join(output_dir, f"{log_file}_structured.csv")
    if os.path.isfile(structured_csv):
        print(f"Processing structured logs from CSV: {structured_csv}")
        process_logs_from_csv(structured_csv)
        print("Processing completed.")
    else:
        print(f"Structured CSV file not found: {structured_csv}")

if __name__ == "__main__":
    parse_and_process()
