#!/usr/bin/env python3
"""
Integrated AI-driven SIEM Log Anomaly Detection Pipeline
Handles parsing and advanced hybrid anomaly detection
"""

import argparse
import sys
import os
import yaml
from pathlib import Path
import pandas as pd
import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Optional

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.append(str(project_root))
sys.path.append('.')

# Import all pickled classes BEFORE importing pipeline
from src.logAnomalyDetection.LSTM_AE.severity_classifier import EnhancedSeverityManager, RuleBasedLogClassifier
from src.logAnomalyDetection.LSTM_AE.model import HybridEnsembleDetector, DataPreprocessor, HybridAttentionLSTMAutoencoder

# Import parsing functionality
from parse import parse_and_process

# Import new hybrid pipeline
from src.logAnomalyDetection.pipeline import LogAnomalyDetectionPipeline
from src.utils.config_loader import load_config

class ExpressExporter:
    """Built-in Express exporter for anomaly data"""
    
    def __init__(self, config):
        self.base_url = config.get('express_backend', {}).get('base_url', 'http://localhost:5000')
        self.timeout = config.get('express_backend', {}).get('timeout', 30)
        self.retry_attempts = config.get('express_backend', {}).get('retry_attempts', 3)
        
        # Headers for your server
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
    
    def export_anomalies(self, anomalies: List[Dict]) -> bool:
        """Export anomalies to your existing /api/logs endpoint"""
        try:
            print(f"🔍 DEBUG: Starting export of {len(anomalies)} anomalies")
            
            # Convert anomalies to format expected by your server
            logs_array = []
            
            for anomaly in anomalies:
                # Handle both single log and sequential anomalies
                if 'logs' in anomaly:  # Sequential anomaly
                    # For sequential, we'll send the first log as representative
                    log_data = {
                        'log': anomaly['logs'][0] if anomaly['logs'] else {},
                        'anomaly_type': anomaly['anomaly_type'],
                        'severity': anomaly['severity'],
                        'confidence': anomaly['confidence'],
                        'anomaly_score': anomaly['anomaly_score'],
                        'processing_mode': anomaly['processing_mode'],
                        'timestamp': anomaly['timestamp']
                    }
                else:  # Single log anomaly
                    log_data = {
                        'log': anomaly['log'],
                        'anomaly_type': anomaly['anomaly_type'],
                        'severity': anomaly['severity'],
                        'confidence': anomaly['confidence'],
                        'anomaly_score': anomaly['anomaly_score'],
                        'processing_mode': anomaly['processing_mode'],
                        'timestamp': anomaly['timestamp']
                    }
                
                logs_array.append(log_data)
            
            print(f"🔍 DEBUG: Converted {len(logs_array)} anomalies for export")
            return self._send_to_logs_endpoint(logs_array)
            
        except Exception as e:
            print(f"❌ Failed to export anomalies: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _send_to_logs_endpoint(self, logs_array: List[Dict]) -> bool:
        """Send logs array to your /api/logs endpoint"""
        url = f"{self.base_url}/api/logs"
        
        print(f"🔍 DEBUG: Sending to URL: {url}")
        print(f"🔍 DEBUG: Payload size: {len(logs_array)} logs")
        if logs_array:
            print(f"🔍 DEBUG: Sample payload: {logs_array[0]}")
        
        for attempt in range(self.retry_attempts):
            try:
                print(f"🔍 DEBUG: Attempt {attempt + 1}/{self.retry_attempts}")
                
                response = requests.post(
                    url,
                    json=logs_array,  # Send as array directly
                    headers=self.headers,
                    timeout=self.timeout
                )
                
                print(f"🔍 DEBUG: Response status: {response.status_code}")
                print(f"🔍 DEBUG: Response text: {response.text}")
                
                if response.status_code == 200:
                    print(f"✅ Successfully sent {len(logs_array)} logs to Express server")
                    return True
                else:
                    print(f"⚠️  Express server returned status {response.status_code}: {response.text}")
                    
            except requests.exceptions.Timeout:
                print(f"⚠️  Request timeout (attempt {attempt + 1}/{self.retry_attempts})")
            except requests.exceptions.ConnectionError:
                print(f"⚠️  Connection error (attempt {attempt + 1}/{self.retry_attempts})")
            except Exception as e:
                print(f"⚠️  Request failed (attempt {attempt + 1}/{self.retry_attempts}): {e}")
            
            if attempt < self.retry_attempts - 1:
                time.sleep(2 ** attempt)  # Exponential backoff
        
        return False
    
    def test_connection(self) -> bool:
        """Test connection to your Express backend"""
        try:
            print(f"🔍 DEBUG: Testing connection to {self.base_url}")
            
            # Test with your system health endpoint
            response = requests.get(
                f"{self.base_url}/api/system-health",
                headers=self.headers,
                timeout=5
            )
            
            print(f"🔍 DEBUG: Health check response: {response.status_code}")
            
            if response.status_code == 200:
                print("✅ Express backend connection successful")
                return True
            else:
                print(f"❌ Express backend returned status {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Express backend connection failed: {e}")
            return False

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='AI-driven SIEM Log Anomaly Detection - Hybrid Pipeline')
    
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
    
    parser.add_argument('--processing-mode',
                       choices=['sequential', 'single', 'both'],
                       default='both',
                       help='Anomaly detection processing mode')
    
    parser.add_argument('--skip-parsing', 
                       action='store_true',
                       help='Skip parsing step (use existing structured data)')
    
    parser.add_argument('--use-existing-csv',
                       help='Use existing structured CSV file directly')
    
    parser.add_argument('--verbose', '-v',
                       action='store_true',
                       help='Enable verbose output')
    
    parser.add_argument('--export-to-express',
                       action='store_true',
                       help='Export results to Express backend')
    
    parser.add_argument('--express-url',
                       help='Express backend URL (default: http://localhost:5000)')
    
    parser.add_argument('--test-express-connection',
                       action='store_true',
                       help='Test Express backend connection only')
    
    return parser.parse_args()

def export_to_express(results, config):
    """Export results to Express backend"""
    try:
        print("🔍 DEBUG: export_to_express called")
        
        exporter = ExpressExporter(config)
        
        print("📤 Exporting anomalies to Express backend...")
        
        # Collect all anomalies from different modes
        all_anomalies = []
        
        # Add single log anomalies
        if 'single_log_results' in results and results['single_log_results']:
            all_anomalies.extend(results['single_log_results'])
            print(f"   • Added {len(results['single_log_results'])} single log anomalies")
        
        # Add sequential anomalies
        if 'sequential_results' in results and results['sequential_results']:
            all_anomalies.extend(results['sequential_results'])
            print(f"   • Added {len(results['sequential_results'])} sequential anomalies")
        
        # Add hybrid anomalies if present
        if 'hybrid_results' in results and results['hybrid_results']:
            all_anomalies.extend(results['hybrid_results'])
            print(f"   • Added {len(results['hybrid_results'])} hybrid anomalies")
        
        # Add anomaly_results for single mode processing
        if 'anomaly_results' in results and results['anomaly_results']:
            all_anomalies.extend(results['anomaly_results'])
            print(f"   • Added {len(results['anomaly_results'])} anomalies from single mode")
        
        print(f"🔍 DEBUG: Total anomalies collected: {len(all_anomalies)}")
        if all_anomalies:
            print(f"🔍 DEBUG: First anomaly sample: {all_anomalies[0]}")
            
            if exporter.export_anomalies(all_anomalies):
                print(f"✅ Successfully exported {len(all_anomalies)} anomalies to Express server")
                return True
            else:
                print("❌ Failed to export anomalies to Express server")
                return False
        else:
            print("⚠️  DEBUG: No anomalies found to export!")
            return True
        
    except Exception as e:
        print(f"❌ Express export failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_detection_stage(config, input_data, processing_mode='both', verbose=False):
    """Run hybrid anomaly detection using new pipeline"""
    print(f"\n🤖 STAGE 2: Hybrid Anomaly Detection (Mode: {processing_mode})")
    print("-" * 50)
    
    try:
        # Initialize pipeline with detection config
        detection_config = config.get('detection', {})
        
        # Remove Express exporter from pipeline since we handle it here
        detection_config_copy = detection_config.copy()
        detection_config_copy.pop('express_backend', None)
        
        pipeline = LogAnomalyDetectionPipeline(detection_config_copy)
        
        if verbose:
            print(f"   • Model path: {detection_config.get('model_path', 'default')}")
            print(f"   • Processing mode: {processing_mode}")
            print(f"   • Sequence length: {detection_config.get('seq_len', 8)}")
            print(f"   • Stride: {detection_config.get('stride', 8)}")
            print(f"   • Output path: {detection_config.get('output_path', 'default')}")
        
        # Initialize pipeline components
        if not pipeline.initialize():
            print("❌ Pipeline initialization failed")
            return None
        
        # Process logs through the hybrid pipeline
        print("   • Running hybrid ensemble anomaly detection...")
        results = pipeline.process_logs(input_data, processing_mode=processing_mode)
        
        # Export to Express if enabled
        if config.get('express_backend', {}).get('enabled', False):
            export_to_express(results, config)
        
        # Save results
        output_dir = pipeline.save_results(results)
        
        # Display results summary based on processing mode
        if processing_mode == 'both':
            print(f"✅ Hybrid detection complete!")
            print(f"   • Sequential anomalies: {results['mode_comparison']['sequential_count']}")
            print(f"   • Single log anomalies: {results['mode_comparison']['single_log_count']}")
            
            # Show severity breakdown for each mode
            for mode_name, mode_results in [
                ('Sequential', results.get('sequential_results', [])),
                ('Single Log', results.get('single_log_results', []))
            ]:
                if mode_results:
                    severities = [r['severity'] for r in mode_results]
                    from collections import Counter
                    severity_counts = Counter(severities)
                    critical_count = severity_counts.get('Critical', 0)
                    high_count = severity_counts.get('High', 0)
                    
                    if critical_count > 0:
                        print(f"   • 🚨 {mode_name} CRITICAL: {critical_count}")
                    if high_count > 0:
                        print(f"   • ⚠️  {mode_name} HIGH: {high_count}")
        else:
            print(f"✅ Detection complete ({processing_mode} mode)!")
            if 'anomaly_results' in results:
                print(f"   • Anomalies detected: {len(results['anomaly_results'])}")
        
        print(f"   • Results saved to: {output_dir}")
        
        return results
        
    except Exception as e:
        print(f"❌ Detection failed: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        return None

def display_hybrid_results(results, verbose=False):
    """Display hybrid processing results"""
    if 'mode_comparison' not in results:
        return
    
    print(f"\n📋 HYBRID PROCESSING RESULTS:")
    print("-" * 50)
    
    mode_comparison = results['mode_comparison']
    
    print(f"🔄 Mode Comparison:")
    print(f"   • Sequential processing: {mode_comparison['sequential_count']} anomalies")
    print(f"   • Single log processing: {mode_comparison['single_log_count']} anomalies")
    
    # Show thresholds
    thresholds = mode_comparison.get('thresholds', {})
    print(f"\n📊 Detection Thresholds:")
    for mode, threshold in thresholds.items():
        print(f"   • {mode.title()}: {threshold:.4f}")
    
    # Display sample results from each mode
    for mode_name, mode_key in [
        ('Sequential', 'sequential_results'),
        ('Single Log', 'single_log_results')
    ]:
        mode_results = results.get(mode_key, [])
        if mode_results:
            print(f"\n🔍 {mode_name.upper()} ANOMALIES (showing top 3):")
            for i, result in enumerate(mode_results[:3]):
                severity = result.get('severity', 'Unknown')
                anomaly_type = result.get('anomaly_type', 'unknown')
                score = result.get('anomaly_score', 0.0)
                
                icon = "🔴" if severity == "Critical" else "🟠" if severity == "High" else "🟡"
                print(f"   {icon} #{i+1}: {anomaly_type} - {severity} (Score: {score:.4f})")
                
                if verbose and 'logs' in result:
                    # Sequential results have multiple logs
                    print(f"      Sequence length: {result.get('sequence_length', 1)}")
                    if result['logs']:
                        print(f"      First log: {result['logs'][0]['content'][:60]}...")
                elif verbose and 'log' in result:
                    # Single log results
                    print(f"      Content: {result['log']['content'][:60]}...")

def main():
    """Main execution function"""
    args = parse_arguments()
    
    print("🚀 AI-DRIVEN SIEM HYBRID LOG ANOMALY DETECTION PIPELINE")
    print("=" * 65)
    print("   Advanced Parsing + Hybrid ML-Driven Detection System")
    print("=" * 65)
    
    # Load configuration
    try:
        config = load_config(args.config)
        if args.verbose:
            print(f"📋 Loaded configuration from: {args.config}")
    except Exception as e:
        print(f"❌ Failed to load configuration: {e}")
        sys.exit(1)
    
    # Override Express settings from command line (MOVED UP)
    if args.export_to_express:
        config.setdefault('express_backend', {})['enabled'] = True
        print("🔗 Express backend integration enabled via command line")
    
    if args.express_url:
        config.setdefault('express_backend', {})['base_url'] = args.express_url
        print(f"🔗 Express backend URL set to: {args.express_url}")
    
    # Test Express connection only
    if args.test_express_connection:
        if config.get('express_backend', {}).get('enabled', False):
            exporter = ExpressExporter(config)
            if exporter.test_connection():
                print("✅ Express backend connection test passed")
                sys.exit(0)
            else:
                print("❌ Express backend connection test failed")
                sys.exit(1)
        else:
            print("❌ Express backend not enabled in configuration")
            sys.exit(1)
    
    # Override config with command line arguments
    config.setdefault('detection', {})['output_path'] = args.reports_dir
    
    # Execute pipeline based on mode
    if args.mode == 'full':
        current_input = None
        
        # Stage 1: Parsing (unless skipped)
        if not args.skip_parsing:
            parsed_file = parse_and_process(
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
        
        # Stage 2: Hybrid Detection
        result = run_detection_stage(config, current_input, args.processing_mode, args.verbose)
        if not result:
            print("❌ Pipeline failed at detection stage")
            sys.exit(1)
        
        # Display hybrid results
        if args.processing_mode == 'both':
            display_hybrid_results(result, args.verbose)
        
        # Final comprehensive summary
        print(f"\n🎉 HYBRID PIPELINE COMPLETED SUCCESSFULLY!")
        print("=" * 55)
        
        if args.processing_mode == 'both':
            mode_comparison = result.get('mode_comparison', {})
            print(f"📊 HYBRID ANALYSIS SUMMARY:")
            print(f"   • Total logs processed: {result['metadata']['total_logs_processed']}")
            print(f"   • Sequential anomalies: {mode_comparison.get('sequential_count', 0)}")
            print(f"   • Single log anomalies: {mode_comparison.get('single_log_count', 0)}")
            
            # Threat assessment
            total_critical = 0
            total_high = 0
            
            for mode_results in [
                result.get('sequential_results', []),
                result.get('single_log_results', [])
            ]:
                for res in mode_results:
                    if res.get('severity') == 'Critical':
                        total_critical += 1
                    elif res.get('severity') == 'High':
                        total_high += 1
            
            print(f"\n🎯 COMPREHENSIVE THREAT ASSESSMENT:")
            if total_critical > 0:
                print(f"   🚨 CRITICAL: {total_critical} critical anomalies across all modes!")
            elif total_high > 5:
                print(f"   ⚠️  HIGH: {total_high} high-severity anomalies detected")
            else:
                print(f"   ✅ NORMAL: System operating within acceptable parameters")
        
        print(f"\n📁 OUTPUT LOCATIONS:")
        print(f"   • Structured data: {current_input}")
        print(f"   • Analysis reports: {args.reports_dir}")
        print(f"   • Hybrid results: {args.reports_dir}/hybrid_anomaly_detection_results.json")
        
        if args.processing_mode == 'both':
            print(f"   • Sequential anomalies: {args.reports_dir}/sequential_anomalies.json")
            print(f"   • Single log anomalies: {args.reports_dir}/single_log_anomalies.json")
        
        print(f"\n✅ Ready for SOC integration and real-time monitoring!")

if __name__ == "__main__":
    main()
