#!/usr/bin/env python

import sys
sys.path.append('../../')  # Adjust path for local imports

from src.logAnomalyDetection.Brain import LogParser

# === Custom Configuration for Your Dataset ===
dataset    = 'Linux'
input_dir  = '../../data/logs/raw/'     # Where your Linux.log is stored
output_dir = '../../data/logs/processed/'  # Output goes here
log_file   = 'Linux_test.log'                   # Your actual log file

# You must define the log format according to your log file pattern
# Example: '<Date> <Time>,<Millis> <Level> <Content>'
# Modify this line based on your actual log content
log_format = "<Month> <Date> <Time> <Level> <Component>(\[<PID>\])?: <Content>"

# Regular expressions for preprocessing, optional
regex = [r"(\d+\.){3}\d+", r"\d{2}:\d{2}:\d{2}", r"J([a-z]{2})"]

threshold  = 4      # Similarity threshold
delimeter  = [r""]     # Use default tree depth

# === Initialize and Run Parser ===
parser = LogParser(
    logname=dataset,
    log_format=log_format,
    indir=input_dir,
    outdir=output_dir,
    threshold=threshold,
    delimeter=delimeter,
    rex=regex
)

parser.parse(log_file)
