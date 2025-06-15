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
    dataset=None,
    input_dir=None,
    output_dir=None,
    log_file=None,
    log_format=None,
    regex=None,
    threshold=None,
    delimeter=None,
    config=None,
    verbose=False
):
    """
    Parse raw logs using Brain algorithm and prepare for anomaly detection pipeline
    Enhanced to work with configuration files and hybrid pipeline
    """
    # Load defaults from config if provided
    if config:
        parsing_config = config.get('parsing', {})
        data_paths = config.get('data_paths', {})
        
        # Use config values as defaults
        dataset = dataset or parsing_config.get('dataset', 'Linux')
        input_dir = input_dir or data_paths.get('input_dir', 'data/logs/raw/')
        output_dir = output_dir or data_paths.get('output_dir', 'data/logs/processed/')
        log_format = log_format or parsing_config.get('log_format', 
            "<Month> <Date> <Time> <Level> <Component>(\[<PID>\])?: <Content>")
        threshold = threshold or parsing_config.get('parameters', {}).get('threshold', 4)
        
        # Get regex and delimiter from config
        if regex is None:
            regex = parsing_config.get('parameters', {}).get('regex', 
                [r"(\d+\.){3}\d+", r"\d{2}:\d{2}:\d{2}", r"J([a-z]{2})"])
        if delimeter is None:
            delimeter = parsing_config.get('parameters', {}).get('delimeter', [r""])
    else:
        # Fallback to original defaults
        dataset = dataset or 'Linux'
        input_dir = input_dir or '../../data/logs/raw/'
        output_dir = output_dir or '../../data/logs/processed/'
        log_format = log_format or "<Month> <Date> <Time> <Level> <Component>(\[<PID>\])?: <Content>"
        threshold = threshold or 4
        
        if regex is None:
            regex = [r"(\d+\.){3}\d+", r"\d{2}:\d{2}:\d{2}", r"J([a-z]{2})"]
        if delimeter is None:
            delimeter = [r""]

    # Default log file if not provided
    if log_file is None:
        log_file = f"{dataset}_test.log"

    if verbose:
        print(f"🔧 Parsing Configuration:")
        print(f"   • Dataset: {dataset}")
        print(f"   • Input directory: {input_dir}")
        print(f"   • Output directory: {output_dir}")
        print(f"   • Log file: {log_file}")
        print(f"   • Log format: {log_format}")
        print(f"   • Threshold: {threshold}")

    print(f"Starting parse_and_process for log file: {log_file}")

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    try:
        # Initialize Brain parser with enhanced error handling
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
        
        # Enhanced parsing with progress indication
        print("   • Running Brain algorithm...")
        parser.parse(log_file)
        print(f"   • Parsing completed. Output in {output_dir}")

        # Enhanced output validation with multiple naming conventions
        structured_csv = find_structured_output(output_dir, log_file, dataset, verbose)
        
        if structured_csv:
            validation_result = validate_parsed_data(structured_csv, verbose)
            
            if validation_result['valid']:
                print(f"✅ Structured logs created and validated: {structured_csv}")
                return structured_csv
            else:
                print(f"⚠️  Structured logs created but validation issues found: {structured_csv}")
                return structured_csv  # Return anyway for pipeline to handle
        else:
            raise FileNotFoundError(f"Parsing failed - no structured output found")
            
    except Exception as e:
        print(f"❌ Parsing failed: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        raise

def find_structured_output(output_dir, log_file, dataset, verbose=False):
    """
    Find the structured CSV output using multiple naming conventions
    Enhanced to handle various Brain parser output formats
    """
    base_name = os.path.splitext(log_file)[0]
    
    # Comprehensive list of possible output file names
    possible_paths = [
        # Standard Brain parser outputs
        os.path.join(output_dir, f"{log_file}_structured.csv"),
        os.path.join(output_dir, f"{base_name}.log_structured.csv"),
        os.path.join(output_dir, f"{dataset}.log_structured.csv"),
        os.path.join(output_dir, f"{dataset}_structured.csv"),
        
        # Alternative formats
        os.path.join(output_dir, f"{base_name}_structured.csv"),
        os.path.join(output_dir, f"{dataset}_{base_name}_structured.csv"),
        
        # Template files (Brain parser sometimes creates these)
        os.path.join(output_dir, f"{base_name}.log_templates.csv"),
        os.path.join(output_dir, f"{dataset}.log_templates.csv"),
    ]
    
    if verbose:
        print(f"   • Searching for structured output files...")
    
    for path in possible_paths:
        if os.path.isfile(path):
            if verbose:
                print(f"   • Found: {path}")
            return path
    
    if verbose:
        print(f"   • No structured output found. Searched locations:")
        for path in possible_paths:
            print(f"     - {path}")
    
    return None

def validate_parsed_data(csv_path, verbose=False):
    """
    Enhanced validation for parsed data compatibility with hybrid anomaly detection pipeline
    """
    try:
        df = pd.read_csv(csv_path)
        
        # Enhanced validation for hybrid pipeline requirements
        required_columns = ['EventTemplate', 'EventId']
        recommended_columns = ['Content', 'Level', 'Component', 'Date', 'Time']
        hybrid_beneficial_columns = ['LineId', 'Month']  # Columns that help but aren't required
        
        missing_required = [col for col in required_columns if col not in df.columns]
        available_recommended = [col for col in recommended_columns if col in df.columns]
        available_beneficial = [col for col in hybrid_beneficial_columns if col in df.columns]
        
        # Check data quality
        data_quality_issues = []
        
        # Check for empty EventTemplate (critical for classification)
        if 'EventTemplate' in df.columns:
            empty_templates = df['EventTemplate'].isna().sum()
            if empty_templates > 0:
                data_quality_issues.append(f"{empty_templates} empty EventTemplate entries")
        
        # Check for duplicate EventIds (could indicate parsing issues)
        if 'EventId' in df.columns:
            unique_event_ids = df['EventId'].nunique()
            total_rows = len(df)
            if unique_event_ids < total_rows * 0.1:  # Less than 10% unique templates might indicate issues
                data_quality_issues.append(f"Low template diversity: {unique_event_ids} unique templates for {total_rows} logs")
        
        # Check for Content availability (important for rule-based classification)
        if 'Content' in df.columns:
            empty_content = df['Content'].isna().sum()
            if empty_content > total_rows * 0.5:  # More than 50% empty content
                data_quality_issues.append(f"High empty content ratio: {empty_content}/{total_rows}")
        
        validation_result = {
            'valid': len(missing_required) == 0,
            'total_entries': len(df),
            'columns': list(df.columns),
            'missing_required': missing_required,
            'available_recommended': available_recommended,
            'available_beneficial': available_beneficial,
            'data_quality_issues': data_quality_issues,
            'hybrid_pipeline_ready': len(missing_required) == 0 and len(available_recommended) >= 2
        }
        
        if validation_result['valid']:
            print(f"✅ Data validation passed:")
            print(f"   • Total entries: {validation_result['total_entries']}")
            print(f"   • Required columns: ✓ {required_columns}")
            print(f"   • Recommended columns available: {available_recommended}")
            
            if available_beneficial:
                print(f"   • Beneficial columns available: {available_beneficial}")
            
            if validation_result['hybrid_pipeline_ready']:
                print(f"   • ✅ Ready for hybrid anomaly detection pipeline")
            else:
                print(f"   • ⚠️  Limited functionality - missing recommended columns")
            
            if data_quality_issues:
                print(f"   • ⚠️  Data quality warnings:")
                for issue in data_quality_issues:
                    print(f"     - {issue}")
        else:
            print(f"❌ Data validation failed:")
            print(f"   • Missing required columns: {missing_required}")
            if data_quality_issues:
                print(f"   • Data quality issues:")
                for issue in data_quality_issues:
                    print(f"     - {issue}")
        
        if verbose:
            print(f"   • All available columns: {list(df.columns)}")
            
            # Show sample data for verification
            if len(df) > 0:
                print(f"   • Sample EventTemplate: {df['EventTemplate'].iloc[0] if 'EventTemplate' in df.columns else 'N/A'}")
                print(f"   • Sample Content: {df['Content'].iloc[0][:50] if 'Content' in df.columns else 'N/A'}...")
        
        return validation_result
        
    except Exception as e:
        print(f"❌ Validation error: {e}")
        return {'valid': False, 'error': str(e), 'hybrid_pipeline_ready': False}

def get_parsing_stats(csv_path):
    """
    Get detailed statistics about parsed data for pipeline optimization
    """
    try:
        df = pd.read_csv(csv_path)
        
        stats = {
            'total_logs': len(df),
            'unique_templates': df['EventTemplate'].nunique() if 'EventTemplate' in df.columns else 0,
            'unique_components': df['Component'].nunique() if 'Component' in df.columns else 0,
            'log_levels': df['Level'].value_counts().to_dict() if 'Level' in df.columns else {},
            'date_range': {
                'start': df['Date'].min() if 'Date' in df.columns else None,
                'end': df['Date'].max() if 'Date' in df.columns else None
            },
            'content_stats': {
                'avg_length': df['Content'].str.len().mean() if 'Content' in df.columns else 0,
                'max_length': df['Content'].str.len().max() if 'Content' in df.columns else 0
            }
        }
        
        return stats
        
    except Exception as e:
        print(f"⚠️  Could not generate parsing statistics: {e}")
        return {}

# Enhanced legacy compatibility function
def process_logs_from_csv(csv_file_path, verbose=False):
    """
    Enhanced legacy function for backward compatibility
    Now includes validation for hybrid pipeline compatibility
    """
    if verbose:
        print(f"   • Legacy function called for: {csv_file_path}")
        print(f"   • Note: Processing is now handled by the new HybridLogAnomalyDetectionPipeline")
    
    # Validate file exists and is readable
    if not os.path.exists(csv_file_path):
        raise FileNotFoundError(f"CSV file not found: {csv_file_path}")
    
    validation_result = validate_parsed_data(csv_file_path, verbose)
    
    if validation_result['valid']:
        if verbose:
            print(f"   • ✅ CSV ready for hybrid anomaly detection pipeline")
            
            # Show parsing statistics if verbose
            stats = get_parsing_stats(csv_file_path)
            if stats:
                print(f"   • Parsing Statistics:")
                print(f"     - Total logs: {stats['total_logs']}")
                print(f"     - Unique templates: {stats['unique_templates']}")
                print(f"     - Log levels: {stats['log_levels']}")
        return True
    else:
        if verbose:
            print(f"   • ⚠️  CSV validation issues - may cause problems in pipeline")
            print(f"   • Hybrid pipeline ready: {validation_result.get('hybrid_pipeline_ready', False)}")
        return validation_result.get('hybrid_pipeline_ready', False)

if __name__ == "__main__":
    # Enhanced test parsing with better error handling
    try:
        print("🧪 Testing parse_and_process with default parameters...")
        result = parse_and_process(verbose=True)
        
        if result:
            print(f"\n🎉 Parsing completed successfully!")
            print(f"📁 Structured data: {result}")
            
            # Enhanced validation and statistics
            validation_result = validate_parsed_data(result, verbose=True)
            
            if validation_result['hybrid_pipeline_ready']:
                print(f"\n✅ Ready for hybrid anomaly detection pipeline!")
                
                # Show parsing statistics
                stats = get_parsing_stats(result)
                if stats:
                    print(f"\n📊 Parsing Statistics:")
                    print(f"   • Total logs: {stats['total_logs']}")
                    print(f"   • Unique templates: {stats['unique_templates']}")
                    print(f"   • Unique components: {stats['unique_components']}")
                    if stats['log_levels']:
                        print(f"   • Log level distribution: {stats['log_levels']}")
            else:
                print(f"\n⚠️  Parsing successful but pipeline compatibility issues detected")
        else:
            print("❌ Parsing failed")
            
    except Exception as e:
        print(f"❌ Error during parsing: {e}")
        import traceback
        traceback.print_exc()
