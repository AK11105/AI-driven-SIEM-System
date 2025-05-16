#!/usr/bin/env python

import sys
sys.path.append('../../')  # Adjust path for local imports

from Brain import LogParser  # Updated path if needed

# === Custom Configuration for Your Dataset ===
dataset    = 'Linux'
input_dir  = '../../../data/logs/raw/'     # Where your Linux.log is stored
output_dir = '../../../data/logs/processed/'  # Output goes here
log_file   = 'Linux.log'                   # Your actual log file

# You must define the log format according to your log file pattern
# Example: '<Date> <Time>,<Millis> <Level> <Content>'
# Modify this line based on your actual log content
log_format = '<Date> <Time>,<Millis> <Level> <Content>'  

# Regular expressions for preprocessing, optional
regex = [
    r'(/|)([0-9]+\.){3}[0-9]+(:[0-9]+|)(:|)',    # IP addresses
    r'(?<=[^A-Za-z0-9])(\-?\+?\d+)(?=[^A-Za-z0-9])|[0-9]+$',  # Numbers
]

threshold  = 2      # Similarity threshold
delimeter  = []     # Use default tree depth

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
