#!/usr/bin/env python

import sys
import os
import pandas as pd
from pathlib import Path

# Add project root to path for imports
project_root = Path(__file__).parent.parent.parent
sys.path.append(str(project_root))
sys.path.append('../../')  # Keep your original path for compatibility

from src.logAnomalyDetection.Brain import LogParser

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
    """
    Parse raw logs using Brain algorithm and prepare for anomaly detection pipeline
    """
    if regex is None:
        regex = [r"(\d+\.){3}\d+", r"\d{2}:\d{2}:\d{2}", r"J([a-z]{2})"]
    if delimeter is None:
        delimeter = [r""]

    print(f"Starting parse_and_process for log file: {log_file}")

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Initialize Brain parser
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
    input_path = os.path.join(input_dir, log_file)
    print(f"Parsing raw logs from {input_path}")
    
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input log file not found: {input_path}")
    
    parser.parse(log_file)
    print(f"Parsing completed. Output in {output_dir}")

    # Validate structured output
    structured_csv = os.path.join(output_dir, f"{log_file}_structured.csv")
    
    # Try alternative naming conventions if the expected file doesn't exist
    if not os.path.isfile(structured_csv):
        # Try without extension
        base_name = os.path.splitext(log_file)[0]
        alternative_paths = [
            os.path.join(output_dir, f"{base_name}.log_structured.csv"),
            os.path.join(output_dir, f"{dataset}.log_structured.csv"),
            os.path.join(output_dir, f"{dataset}_structured.csv")
        ]
        
        for alt_path in alternative_paths:
            if os.path.isfile(alt_path):
                structured_csv = alt_path
                break
    
    if os.path.isfile(structured_csv):
        print(f"✅ Structured logs created: {structured_csv}")
        
        # Validate the CSV file
        try:
            df = pd.read_csv(structured_csv)
            print(f"   • Validated: {len(df)} log entries parsed")
            
            # Check for required columns
            required_columns = ['EventTemplate', 'EventId']
            missing_columns = [col for col in required_columns if col not in df.columns]
            if missing_columns:
                print(f"   ⚠️  Warning: Missing required columns: {missing_columns}")
            else:
                print(f"   • Required columns present: {required_columns}")
            
            # Show available columns
            print(f"   • Available columns: {list(df.columns)}")
            
        except Exception as e:
            print(f"   ⚠️  Warning: Could not validate CSV file: {e}")
        
        return structured_csv
    else:
        print(f"❌ Structured CSV file not found at expected locations:")
        print(f"   • Primary: {os.path.join(output_dir, f'{log_file}_structured.csv')}")
        print(f"   • Alternative: {os.path.join(output_dir, f'{os.path.splitext(log_file)[0]}.log_structured.csv')}")
        raise FileNotFoundError(f"Parsing failed - no structured output found")

def validate_parsed_data(csv_path):
    """
    Validate parsed data for compatibility with anomaly detection pipeline
    """
    try:
        df = pd.read_csv(csv_path)
        
        # Check required columns for anomaly detection
        required_columns = ['EventTemplate', 'EventId']
        optional_columns = ['Content', 'Level', 'Component', 'Date', 'Time']
        
        missing_required = [col for col in required_columns if col not in df.columns]
        available_optional = [col for col in optional_columns if col in df.columns]
        
        validation_result = {
            'valid': len(missing_required) == 0,
            'total_entries': len(df),
            'columns': list(df.columns),
            'missing_required': missing_required,
            'available_optional': available_optional
        }
        
        if validation_result['valid']:
            print(f"✅ Data validation passed:")
            print(f"   • Total entries: {validation_result['total_entries']}")
            print(f"   • Required columns: ✓")
            print(f"   • Optional columns available: {available_optional}")
        else:
            print(f"❌ Data validation failed:")
            print(f"   • Missing required columns: {missing_required}")
        
        return validation_result
        
    except Exception as e:
        print(f"❌ Validation error: {e}")
        return {'valid': False, 'error': str(e)}

# Legacy compatibility function (kept for backward compatibility)
def process_logs_from_csv(csv_file_path):
    """
    Legacy function for backward compatibility
    Note: Actual processing is now handled by LogAnomalyDetectionPipeline in run.py
    """
    print(f"   • Legacy function called for: {csv_file_path}")
    print(f"   • Note: Processing is now handled by the new LogAnomalyDetectionPipeline")
    
    # Just validate the file exists and is readable
    if not os.path.exists(csv_file_path):
        raise FileNotFoundError(f"CSV file not found: {csv_file_path}")
    
    validation_result = validate_parsed_data(csv_file_path)
    
    if validation_result['valid']:
        print(f"   • CSV ready for anomaly detection pipeline")
        return True
    else:
        print(f"   • CSV validation failed - may cause issues in pipeline")
        return False

if __name__ == "__main__":
    # Test parsing with default parameters
    try:
        result = parse_and_process()
        if result:
            print(f"\n🎉 Parsing completed successfully!")
            print(f"📁 Structured data: {result}")
            
            # Validate the result
            validate_parsed_data(result)
        else:
            print("❌ Parsing failed")
    except Exception as e:
        print(f"❌ Error during parsing: {e}")
        import traceback
        traceback.print_exc()
