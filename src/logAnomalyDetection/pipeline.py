import pandas as pd
import numpy as np
import json
import pickle
from datetime import datetime
from pathlib import Path
import torch
from torch.utils.data import DataLoader
from collections import Counter

from .LSTM_AE.model import HybridEnsembleDetector, DataPreprocessor, LogDataset
from .LSTM_AE.severity_classifier import EnhancedSeverityManager, RuleBasedLogClassifier

def make_json_serializable(obj):
    """Convert numpy types to Python native types for JSON serialization"""
    if isinstance(obj, dict):
        new_obj = {}
        for k, v in obj.items():
            if isinstance(k, np.int64):
                k = int(k)
            elif isinstance(k, np.float64):
                k = float(k)
            elif isinstance(k, np.bool_):
                k = bool(k)
            
            if isinstance(v, (dict, list)):
                v = make_json_serializable(v)
            elif isinstance(v, np.int64):
                v = int(v)
            elif isinstance(v, np.float64):
                v = float(v)
            elif isinstance(v, np.bool_):
                v = bool(v)
            elif isinstance(v, np.ndarray):
                v = v.tolist()
            
            new_obj[k] = v
        return new_obj
    elif isinstance(obj, list):
        return [make_json_serializable(i) for i in obj]
    elif isinstance(obj, np.int64):
        return int(obj)
    elif isinstance(obj, np.float64):
        return float(obj)
    elif isinstance(obj, np.bool_):
        return bool(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    else:
        return obj

class LogAnomalyDetectionPipeline:
    """Production-ready log anomaly detection pipeline with hybrid processing"""
    
    def __init__(self, config):
        self.config = config
        self.model_path = config.get('model_path', 'src/logAnomalyDetection/LSTM_AE/')
        self.output_path = config.get('output_path', 'reports/logAnomalyDetection/')
        
        # Initialize components
        self.preprocessor = DataPreprocessor()
        self.ensemble_detector = HybridEnsembleDetector(enable_single_log=True)
        self.severity_manager = EnhancedSeverityManager()
        self.log_classifier = RuleBasedLogClassifier()
        
        # Pipeline state
        self.is_initialized = False
        self.results = {}
        
        # Initialize Express exporter if enabled
        self.express_exporter = None
        if config.get('express_backend', {}).get('enabled', False):
            # FIXED: Correct import path
            try:
                from src.utils.express_exporter import ExpressExporter
                self.express_exporter = ExpressExporter(config)
                print("🔗 Express backend integration enabled")
            except ImportError as e:
                print(f"⚠️  Failed to import ExpressExporter: {e}")
                print("   Continuing without Express integration")
        
    def initialize(self):
        """Initialize all pipeline components"""
        print("🚀 Initializing Hybrid Log Anomaly Detection Pipeline...")
        
        try:
            # Load preprocessing artifacts
            artifacts_path = f"{self.model_path}/hybrid_ensemble_artifacts.pkl"
            if not self.preprocessor.load_preprocessing_artifacts(artifacts_path):
                return False
            
            # Load ensemble models
            if not self.ensemble_detector.load_models(self.model_path):
                return False
            
            # Load severity thresholds
            self.severity_manager.load_thresholds(self.preprocessor.artifacts)
            
            # Test Express backend connection if enabled
            if self.express_exporter:
                if not self.express_exporter.test_connection():
                    print("⚠️  Express backend connection failed - continuing without export")
                    self.express_exporter = None
            
            self.is_initialized = True
            print("✅ Hybrid pipeline initialization complete!")
            return True
            
        except Exception as e:
            print(f"❌ Pipeline initialization failed: {e}")
            return False
    
    def process_logs(self, input_data, processing_mode='both'):
        """Main processing pipeline with hybrid capabilities"""
        if not self.is_initialized:
            raise RuntimeError("Pipeline not initialized. Call initialize() first.")
        
        print(f"📊 Processing logs through hybrid anomaly detection pipeline (mode: {processing_mode})...")
        
        # Step 1: Load and validate data
        if isinstance(input_data, str):
            df = pd.read_csv(input_data)
        elif isinstance(input_data, pd.DataFrame):
            df = input_data.copy()
        else:
            raise ValueError("Input data must be CSV path or pandas DataFrame")
        
        print(f"   • Loaded {len(df)} log entries")
        
        # Step 2: Preprocess data
        processed_data, original_df = self.preprocessor.preprocess(df)
        print(f"   • Preprocessed to {processed_data.shape[1]} features")
        
        # Step 3: Create data loader
        seq_len = self.config.get('seq_len', 8)
        stride = self.config.get('stride', 8)
        batch_size = self.config.get('batch_size', 32)
        
        dataset = LogDataset(processed_data, seq_len, stride)
        dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=False)
        
        # Step 4: Hybrid anomaly detection
        if processing_mode == 'both':
            # Process with both modes
            seq_errors, _ = self.ensemble_detector.predict(dataloader, mode='sequential')
            single_errors, _ = self.ensemble_detector.predict(dataloader, mode='single')
            
            # Calculate thresholds for each mode
            seq_threshold = np.percentile(seq_errors, 95)
            single_threshold = np.percentile(single_errors, 95)
            
            # Process outputs separately
            single_results = self.process_single_log_outputs(
                single_errors, single_threshold, original_df, seq_len, stride
            )
            
            sequential_results = self.process_sequential_outputs(
                seq_errors, seq_threshold, original_df, seq_len, stride
            )
            
            print(f"   • Sequential anomalies: {len(sequential_results)}")
            print(f"   • Single log anomalies: {len(single_results)}")
            
            # Compile comprehensive results
            self.results = {
                'metadata': {
                    'timestamp': datetime.now().isoformat(),
                    'total_logs_processed': len(df),
                    'processing_mode': 'both',
                    'pipeline_version': '2.0_hybrid',
                    'config': self.config
                },
                'single_log_results': single_results,
                'sequential_results': sequential_results,
                'mode_comparison': {
                    'sequential_count': len(sequential_results),
                    'single_log_count': len(single_results),
                    'thresholds': {
                        'sequential': float(seq_threshold),
                        'single_log': float(single_threshold)
                    }
                }
            }
            
        else:
            # Process with single mode
            ensemble_errors, _ = self.ensemble_detector.predict(dataloader, mode=processing_mode)
            threshold = np.percentile(ensemble_errors, 95)
            
            if processing_mode == 'sequential':
                results = self.process_sequential_outputs(
                    ensemble_errors, threshold, original_df, seq_len, stride
                )
            else:  # single mode
                results = self.process_single_log_outputs(
                    ensemble_errors, threshold, original_df, seq_len, stride
                )
            
            print(f"   • Detected {len(results)} anomalies")
            
            self.results = {
                'metadata': {
                    'timestamp': datetime.now().isoformat(),
                    'total_logs_processed': len(df),
                    'processing_mode': processing_mode,
                    'pipeline_version': '2.0_hybrid',
                    'config': self.config
                },
                'anomaly_results': results,
                'threshold': float(threshold)
            }
        
        # Export results to Express backend
        if self.express_exporter:
            self._export_to_express(self.results)
        
        print("✅ Hybrid pipeline processing complete!")
        return self.results
    
    def _export_to_express(self, results):
        """Export results to Express backend"""
        try:
            print("🔍 DEBUG: _export_to_express called")
            print(f"🔍 DEBUG: Express exporter exists: {self.express_exporter is not None}")
        
            if not self.express_exporter:
                print("❌ DEBUG: Express exporter is None - export not enabled")
                return
                
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
                
                if self.express_exporter.export_anomalies(all_anomalies):
                    print(f"✅ Successfully exported {len(all_anomalies)} anomalies to Express server")
                else:
                    print("❌ Failed to export anomalies to Express server")
            else:
                print("⚠️  DEBUG: No anomalies found to export!")
            
        except Exception as e:
            print(f"❌ Express export failed: {e}")
            import traceback
            traceback.print_exc()
    
    def process_single_log_outputs(self, single_errors, single_threshold, original_df, seq_len, stride):
        """Process single log anomaly outputs - only for non-normal types"""
        single_anomalies = single_errors > single_threshold
        single_results = []
        
        print(f"🔍 DEBUG: Processing single log outputs - {single_anomalies.sum()} anomalies above threshold")
        
        for seq_idx, is_anomaly in enumerate(single_anomalies):
            if is_anomaly:
                start_idx = seq_idx * stride
                for log_offset in range(seq_len):
                    log_idx = start_idx + log_offset
                    if log_idx < len(original_df):
                        log_entry = original_df.iloc[log_idx]
                        
                        # First pass - check log type classification
                        classification = self.log_classifier.classify_log(
                            log_entry.get('EventTemplate', ''),
                            log_entry.get('Content', '')
                        )
                        
                        # Only process if anomaly type is NOT normal
                        if classification['log_type'] != 'normal':
                            error = single_errors[seq_idx]
                            severity, confidence = self.severity_manager.classify_with_confidence(error)
                            
                            single_results.append({
                                'log': {
                                    'content': log_entry.get('Content', ''),
                                    'event_template': log_entry.get('EventTemplate', ''),
                                    'level': log_entry.get('Level', ''),
                                    'component': log_entry.get('Component', ''),
                                    'line_id': str(log_entry.get('LineId', log_idx))
                                },
                                'anomaly_type': classification['log_type'],
                                'severity': severity,
                                'confidence': float(confidence),
                                'timestamp': str(log_entry.get('Time', '')),
                                'anomaly_score': float(error),
                                'processing_mode': 'single_log'
                            })
        
        print(f"🔍 DEBUG: Single log processing complete - {len(single_results)} non-normal anomalies found")
        return single_results
    
    def process_sequential_outputs(self, seq_errors, seq_threshold, original_df, seq_len, stride):
        """Process sequential anomaly outputs - only for non-normal types"""
        seq_anomalies = seq_errors > seq_threshold
        sequential_results = []
        
        print(f"🔍 DEBUG: Processing sequential outputs - {seq_anomalies.sum()} sequences above threshold")
        
        for seq_idx, is_anomaly in enumerate(seq_anomalies):
            if is_anomaly:
                start_idx = seq_idx * stride
                sequence_logs = []
                sequence_classifications = []
                
                for log_offset in range(seq_len):
                    log_idx = start_idx + log_offset
                    if log_idx < len(original_df):
                        log_entry = original_df.iloc[log_idx]
                        
                        classification = self.log_classifier.classify_log(
                            log_entry.get('EventTemplate', ''),
                            log_entry.get('Content', '')
                        )
                        sequence_classifications.append(classification['log_type'])
                        
                        sequence_logs.append({
                            'content': log_entry.get('Content', ''),
                            'event_template': log_entry.get('EventTemplate', ''),
                            'level': log_entry.get('Level', ''),
                            'component': log_entry.get('Component', ''),
                            'line_id': str(log_entry.get('LineId', log_idx)),
                            'timestamp': str(log_entry.get('Time', ''))
                        })
                
                # Check if sequence has any non-normal anomaly types
                non_normal_types = [t for t in sequence_classifications if t != 'normal']
                
                # Only process if sequence contains non-normal anomaly types
                if non_normal_types:
                    error = seq_errors[seq_idx]
                    severity, confidence = self.severity_manager.classify_with_confidence(error)
                    
                    # Get most common non-normal anomaly type
                    anomaly_type_counts = Counter(non_normal_types)
                    dominant_anomaly_type = anomaly_type_counts.most_common(1)[0][0]
                    
                    sequential_results.append({
                        'logs': sequence_logs,
                        'anomaly_type': dominant_anomaly_type,
                        'severity': severity,
                        'confidence': float(confidence),
                        'timestamp': str(sequence_logs[0]['timestamp'] if sequence_logs else ''),
                        'sequence_length': len(sequence_logs),
                        'anomaly_score': float(error),
                        'processing_mode': 'sequential',
                        'non_normal_count': len(non_normal_types),
                        'total_logs_in_sequence': len(sequence_classifications)
                    })
        
        print(f"🔍 DEBUG: Sequential processing complete - {len(sequential_results)} non-normal sequences found")
        return sequential_results
    
    def save_results(self, results=None):
        """Save pipeline results to output directory"""
        if results is None:
            results = self.results
        
        if not results:
            raise ValueError("No results to save")
        
        # Create output directory
        output_dir = Path(self.output_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Make results JSON serializable
        serializable_results = make_json_serializable(results)
        
        # Save main results
        with open(output_dir / 'hybrid_anomaly_detection_results.json', 'w') as f:
            json.dump(serializable_results, f, indent=2)
        
        # Save individual result types if available
        if 'single_log_results' in results:
            with open(output_dir / 'single_log_anomalies.json', 'w') as f:
                json.dump(make_json_serializable(results['single_log_results']), f, indent=2)
        
        if 'sequential_results' in results:
            with open(output_dir / 'sequential_anomalies.json', 'w') as f:
                json.dump(make_json_serializable(results['sequential_results']), f, indent=2)
        
        print(f"📁 Hybrid results saved to {output_dir}")
        return str(output_dir)
