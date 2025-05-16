import os
import sys

# Add your project root or paths if needed
sys.path.append('.')  # or adjust according to your folder structure

from parse import parse_and_process  # The encapsulated parse+process function
from pipeline import process_logs_from_csv  # Just in case you want to call pipeline separately

def main():
    # Input raw log file (CSV or plain log file depending on your parser)
    raw_log_file = "Linux_test.log"  # The raw log file you want to parse
    
    # Directories (adjust if needed)
    input_dir = '../../data/logs/raw/'
    output_dir = '../../data/logs/processed/'

    # === Step 1: Parse the raw logs and process structured logs ===
    print("Starting parsing and processing pipeline...")
    parse_and_process(
        dataset='Linux',
        input_dir=input_dir,
        output_dir=output_dir,
        log_file=raw_log_file
    )

    # === Optional Step 2: If you want to call pipeline separately on CSV ===
    # This is usually handled inside parse_and_process, but here for clarity
    structured_csv = os.path.join(output_dir, f"{raw_log_file}_structured.csv")
    if os.path.isfile(structured_csv):
        print(f"Now processing structured CSV independently: {structured_csv}")
        process_logs_from_csv(structured_csv)
    else:
        print(f"Structured CSV not found at expected location: {structured_csv}")

if __name__ == "__main__":
    main()
