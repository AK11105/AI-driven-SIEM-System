#!/usr/bin/env python3
"""
Integrated AI-driven SIEM Log Anomaly Detection Pipeline
Handles parsing and advanced anomaly detection using the new pipeline system
"""

import argparse
import sys
import os
import yaml
from pathlib import Path
import pandas as pd

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.append(str(project_root))
sys.path.append('.')  # For relative imports

# CRITICAL FIX: Import all pickled classes BEFORE importing pipeline
from src.logAnomalyDetection.LSTM_AE.severity_classifier import EnhancedSeverityManager, RuleBasedLogClassifier
from src.logAnomalyDetection.LSTM_AE.model import EnhancedEnsembleDetector, DataPreprocessor, AttentionLSTMAutoencoder
from src.logAnomalyDetection.LSTM_AE.explainer import AttentionExplainer

# Import parsing functionality
from parse import parse_and_process

# Import new pipeline components
from src.logAnomalyDetection.pipeline import LogAnomalyDetectionPipeline
from src.utils.config_loader import load_config

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='AI-driven SIEM Log Anomaly Detection - Full Pipeline')
    
    parser.add_argument('--config', '-c', 
                       default='configs/log-anomaly-detection.yml',
                       help='Configuration file path')
    
    parser.add_argument('--input', '-i',
                       help='Input raw log file path (e.g., Linux_test.log)')
    
    parser.add_argument('--dataset', '-d',
                       default='Linux',
                       help='Dataset name for parsing (default: Linux)')
    
    parser.add_argument('--input-dir',
                       default='data/logs/raw/',
                       help='Input directory for raw logs')
    
    parser.add_argument('--output-dir',
                       default='data/logs/processed/',
                       help='Output directory for processed logs')
    
    parser.add_argument('--reports-dir',
                       default='reports/logAnomalyDetection/',
                       help='Reports output directory')
    
    parser.add_argument('--mode', '-m',
                       choices=['parse', 'detect', 'full'],
                       default='full',
                       help='Pipeline mode: parse only, detect only, or full pipeline')
    
    parser.add_argument('--skip-parsing', 
                       action='store_true',
                       help='Skip parsing step (use existing structured data)')
    
    parser.add_argument('--use-existing-csv',
                       help='Use existing structured CSV file directly')
    
    parser.add_argument('--verbose', '-v',
                       action='store_true',
                       help='Enable verbose output')
    
    return parser.parse_args()

def run_parsing_stage(dataset, input_dir, output_dir, log_file, verbose=False):
    """Run log parsing stage using Brain parser"""
    print("🔍 STAGE 1: Log Parsing")
    print("-" * 25)
    
    try:
        if verbose:
            print(f"   • Dataset: {dataset}")
            print(f"   • Input directory: {input_dir}")
            print(f"   • Output directory: {output_dir}")
            print(f"   • Log file: {log_file}")
        
        # Run Brain parsing
        print("   • Starting Brain parser...")
        parse_and_process(
            dataset=dataset,
            input_dir=input_dir,
            output_dir=output_dir,
            log_file=log_file
        )
        
        # Determine the structured CSV path
        # Try different naming conventions
        possible_paths = [
            os.path.join(output_dir, f"{log_file}_structured.csv"),
            os.path.join(output_dir, f"{os.path.splitext(log_file)[0]}.log_structured.csv"),
            os.path.join(output_dir, f"{dataset}.log_structured.csv"),
            os.path.join(output_dir, f"{dataset}_structured.csv")
        ]
        
        structured_csv = None
        for path in possible_paths:
            if os.path.isfile(path):
                structured_csv = path
                break
        
        if structured_csv:
            print(f"✅ Parsing complete!")
            print(f"   • Structured logs: {structured_csv}")
            
            # Validate the CSV
            try:
                df = pd.read_csv(structured_csv)
                print(f"   • Parsed {len(df)} log entries")
                if verbose:
                    print(f"   • Columns: {list(df.columns)}")
                
                return structured_csv
            except Exception as e:
                print(f"⚠️  Warning: Could not validate CSV: {e}")
                return structured_csv
        else:
            print(f"❌ Structured CSV not found at expected locations:")
            for path in possible_paths:
                print(f"   • Tried: {path}")
            return None
        
    except Exception as e:
        print(f"❌ Parsing failed: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        return None

def run_detection_stage(config, input_data, verbose=False):
    """Run advanced anomaly detection using new pipeline"""
    print("\n🤖 STAGE 2: Advanced Anomaly Detection")
    print("-" * 40)
    
    try:
        # Initialize pipeline with detection config
        detection_config = config.get('detection', {})
        pipeline = LogAnomalyDetectionPipeline(detection_config)
        
        if verbose:
            print(f"   • Model path: {detection_config.get('model_path', 'default')}")
            print(f"   • Sequence length: {detection_config.get('seq_len', 8)}")
            print(f"   • Stride: {detection_config.get('stride', 8)}")
            print(f"   • Output path: {detection_config.get('output_path', 'default')}")
        
        # Initialize pipeline components
        if not pipeline.initialize():
            print("❌ Pipeline initialization failed")
            return None
        
        # Process logs through the pipeline
        print("   • Running ensemble anomaly detection...")
        results = pipeline.process_logs(input_data)
        
        # Save results
        output_dir = pipeline.save_results(results)
        
        # Display results summary
        print(f"✅ Detection complete!")
        print(f"   • Anomalies detected: {results['anomaly_detection']['total_anomalies']}")
        print(f"   • Anomaly rate: {results['anomaly_detection']['anomaly_rate']:.1f}%")
        
        # Show severity breakdown
        severity_dist = results['severity_analysis']['severity_distribution']
        critical_count = severity_dist['counts'].get('Critical', 0)
        high_count = severity_dist['counts'].get('High', 0)
        
        if critical_count > 0:
            print(f"   • 🚨 CRITICAL: {critical_count} critical anomalies!")
        if high_count > 0:
            print(f"   • ⚠️  HIGH: {high_count} high-severity anomalies")
        
        # Show log classification summary
        class_stats = results['log_classification']['classification_stats']
        auth_errors = class_stats['counts'].get('authentication_error', 0)
        system_critical = class_stats['counts'].get('system_critical', 0)
        
        if auth_errors > 0:
            print(f"   • 🔐 Authentication errors: {auth_errors}")
        if system_critical > 0:
            print(f"   • ⚡ System critical events: {system_critical}")
        
        print(f"   • Results saved to: {output_dir}")
        
        # Generate and display report if verbose
        if verbose:
            report = pipeline.generate_report()
            print(f"\n{report}")
        
        return results
        
    except Exception as e:
        print(f"❌ Detection failed: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        return None

def validate_inputs(args):
    """Validate input arguments and paths"""
    errors = []
    
    # Check input file/directory for parsing
    if args.mode in ['parse', 'full'] and not args.skip_parsing:
        if not args.input:
            errors.append("Input log file required for parsing mode")
        else:
            input_path = os.path.join(args.input_dir, args.input)
            if not os.path.exists(input_path):
                errors.append(f"Input log file not found: {input_path}")
    
    # Check for detection mode
    if args.mode in ['detect', 'full'] and args.skip_parsing:
        if args.use_existing_csv:
            if not os.path.exists(args.use_existing_csv):
                errors.append(f"Existing CSV file not found: {args.use_existing_csv}")
        else:
            errors.append("For detection-only mode, specify --use-existing-csv")
    
    # Check config file
    if not os.path.exists(args.config):
        errors.append(f"Configuration file not found: {args.config}")
    
    return errors

def display_anomaly_logs(results, verbose=False):
    """Display the specific logs that caused anomalies"""
    anomaly_logs = results.get('anomaly_logs', {})
    
    if not anomaly_logs:
        print("   • No anomaly logs to display")
        return
    
    print(f"\n📋 ANOMALOUS LOG SEQUENCES:")
    print("-" * 50)
    
    for seq_idx, seq_data in anomaly_logs.items():
        severity_info = None
        for severity_result in results['severity_analysis']['classified_anomalies']:
            if severity_result['index'] == seq_idx:
                severity_info = severity_result
                break
        
        severity = severity_info['severity'] if severity_info else 'Unknown'
        error = severity_info['error'] if severity_info else 0.0
        
        print(f"\n🚨 SEQUENCE {seq_idx} - {severity} Severity (Error: {error:.4f})")
        print(f"   Log Range: {seq_data['log_range']} ({seq_data['total_logs']} logs)")
        print(f"   Logs in sequence:")
        
        for i, log in enumerate(seq_data['logs']):
            icon = "🔴" if 'error' in log['content'].lower() or 'fail' in log['content'].lower() else "🟡"
            print(f"     {icon} Log {log['log_index']}: [{log['level']}] {log['component']}")
            
            if verbose:
                print(f"        Time: {log['timestamp']}")
                print(f"        Content: {log['content'][:100]}...")
                print(f"        Template: {log['event_template']}")
                print()
            else:
                print(f"        {log['content'][:80]}...")
        
        # Show explanation if available
        explanations = results.get('explanations', {}).get('explanations', {})
        if str(seq_idx) in explanations:
            explanation = explanations[str(seq_idx)]
            print(f"\n   🔍 Why this sequence is anomalous:")
            for i, feature in enumerate(explanation['top_features'][:3], 1):
                print(f"     {i}. {feature['feature_name']}: {feature['contribution_percentage']:.1f}%")


def main():
    """Main execution function"""
    args = parse_arguments()
    
    print("🚀 AI-DRIVEN SIEM LOG ANOMALY DETECTION PIPELINE")
    print("=" * 55)
    print("   Advanced Parsing + ML-Driven Detection System")
    print("=" * 55)
    
    # Validate inputs
    validation_errors = validate_inputs(args)
    if validation_errors:
        print("❌ Input validation failed:")
        for error in validation_errors:
            print(f"   • {error}")
        sys.exit(1)
    
    # Load configuration
    try:
        config = load_config(args.config)
        if args.verbose:
            print(f"📋 Loaded configuration from: {args.config}")
    except Exception as e:
        print(f"❌ Failed to load configuration: {e}")
        sys.exit(1)
    
    # Override config with command line arguments
    config.setdefault('detection', {})['output_path'] = args.reports_dir
    
    # Execute pipeline based on mode
    if args.mode == 'parse':
        # Parse only mode
        result = run_parsing_stage(
            dataset=args.dataset,
            input_dir=args.input_dir,
            output_dir=args.output_dir,
            log_file=args.input,
            verbose=args.verbose
        )
        
        if result:
            print(f"\n🎉 Parsing completed successfully!")
            print(f"📁 Structured data: {result}")
        else:
            print("❌ Parsing failed")
            sys.exit(1)
            
    elif args.mode == 'detect':
        # Detection only mode
        current_input = args.use_existing_csv
        
        if not os.path.exists(current_input):
            print(f"❌ Input file not found: {current_input}")
            sys.exit(1)
        
        result = run_detection_stage(config, current_input, args.verbose)
        if result:
            print(f"\n🎉 Detection completed successfully!")
        else:
            print("❌ Detection failed")
            sys.exit(1)
            
    elif args.mode == 'full':
        # Full integrated pipeline
        current_input = None
        
        # Stage 1: Parsing (unless skipped)
        if not args.skip_parsing:
            parsed_file = run_parsing_stage(
                dataset=args.dataset,
                input_dir=args.input_dir,
                output_dir=args.output_dir,
                log_file=args.input,
                verbose=args.verbose
            )
            
            if not parsed_file:
                print("❌ Pipeline failed at parsing stage")
                sys.exit(1)
            
            current_input = parsed_file
        else:
            print("⏭️  Skipping parsing stage")
            current_input = args.use_existing_csv
        
        # Validate current input exists
        if not current_input or not os.path.exists(current_input):
            print(f"❌ Structured data not found: {current_input}")
            sys.exit(1)
        
        # Stage 2: Advanced Detection
        result = run_detection_stage(config, current_input, args.verbose)
        if not result:
            print("❌ Pipeline failed at detection stage")
            sys.exit(1)
        
        display_anomaly_logs(result, args.verbose)
        
        # Final comprehensive summary
        print(f"\n🎉 FULL PIPELINE COMPLETED SUCCESSFULLY!")
        print("=" * 50)
        
        print(f"📊 COMPREHENSIVE ANALYSIS:")
        print(f"   • Total logs processed: {result['metadata']['total_logs_processed']}")
        print(f"   • Anomalies detected: {result['anomaly_detection']['total_anomalies']}")
        print(f"   • Anomaly rate: {result['anomaly_detection']['anomaly_rate']:.1f}%")
        
        # Detailed severity analysis
        severity_dist = result['severity_analysis']['severity_distribution']
        print(f"\n🚨 SEVERITY BREAKDOWN:")
        for severity, count in severity_dist['counts'].items():
            percentage = severity_dist['percentages'][severity]
            if count > 0:
                icon = "🔴" if severity == "Critical" else "🟠" if severity == "High" else "🟡" if severity == "Medium" else "🟢"
                print(f"   {icon} {severity}: {count} anomalies ({percentage:.1f}%)")
        
        # Log type analysis
        class_stats = result['log_classification']['classification_stats']
        print(f"\n🏷️  LOG TYPE ANALYSIS:")
        critical_types = ['authentication_error', 'system_critical', 'permission_error']
        for log_type in critical_types:
            count = class_stats['counts'].get(log_type, 0)
            if count > 0:
                percentage = class_stats['percentages'][log_type]
                print(f"   • {log_type.replace('_', ' ').title()}: {count} logs ({percentage:.1f}%)")
        
        # Threat assessment
        critical_count = severity_dist['counts'].get('Critical', 0)
        high_count = severity_dist['counts'].get('High', 0)
        anomaly_rate = result['anomaly_detection']['anomaly_rate']
        
        print(f"\n🎯 THREAT ASSESSMENT:")
        if critical_count > 0:
            print(f"   🚨 CRITICAL: {critical_count} critical anomalies - immediate investigation required!")
        elif high_count > 5:
            print(f"   ⚠️  HIGH: {high_count} high-severity anomalies - monitor closely")
        elif anomaly_rate > 10:
            print(f"   🟡 ELEVATED: High anomaly rate ({anomaly_rate:.1f}%) - increased monitoring")
        else:
            print(f"   ✅ NORMAL: System operating within acceptable parameters")
        
        print(f"\n📁 OUTPUT LOCATIONS:")
        print(f"   • Structured data: {current_input}")
        print(f"   • Analysis reports: {args.reports_dir}")
        print(f"   • Anomaly results: {args.reports_dir}/anomaly_detection_results.json")
        print(f"   • Pipeline summary: {args.reports_dir}/pipeline_summary.json")
        
        print(f"\n✅ Ready for SOC integration and real-time monitoring!")

if __name__ == "__main__":
    main()
