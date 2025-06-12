import pandas as pd
import numpy as np
import json
import pickle
from datetime import datetime
from pathlib import Path

from .LSTM_AE.model import AttentionLSTMAutoencoder
from .LSTM_AE.model import EnhancedEnsembleDetector, DataPreprocessor
from .LSTM_AE.severity_classifier import EnhancedSeverityManager, RuleBasedLogClassifier
from .LSTM_AE.explainer import AttentionExplainer

try:
    from sklearn.preprocessing import OneHotEncoder, StandardScaler
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.impute import SimpleImputer
except ImportError:
    pass

def make_json_serializable(obj):
    """Convert numpy types to Python native types for JSON serialization"""
    if isinstance(obj, dict):
        new_obj = {}
        for k, v in obj.items():
            # Convert numpy int64 keys to regular int
            if isinstance(k, np.int64):
                k = int(k)
            elif isinstance(k, np.float64):
                k = float(k)
            elif isinstance(k, np.bool_):
                k = bool(k)
            
            # Recursively convert values
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
    """Production-ready log anomaly detection pipeline"""
    
    def __init__(self, config):
        self.config = config
        self.model_path = config.get('model_path', 'src/logAnomalyDetection/LSTM-AE/')
        self.output_path = config.get('output_path', 'reports/logAnomalyDetection/')
        
        # Initialize components
        self.preprocessor = DataPreprocessor(f"{self.model_path}ensemble_artifacts.pkl")
        self.ensemble_detector = EnhancedEnsembleDetector(self.model_path)
        self.severity_manager = EnhancedSeverityManager()
        self.log_classifier = RuleBasedLogClassifier()
        self.explainer = AttentionExplainer()
        
        # Pipeline state
        self.is_initialized = False
        self.results = {}
        
    def initialize(self):
        """Initialize all pipeline components"""
        print("🚀 Initializing Log Anomaly Detection Pipeline...")
        
        try:
            # Load preprocessing artifacts
            if not self.preprocessor.load_preprocessing_artifacts():
                return False
            
            # Load ensemble models
            if not self.ensemble_detector.load_models():
                return False
            
            # Load severity thresholds
            self.severity_manager.load_thresholds(self.preprocessor.artifacts)
            
            # Load explainer feature names
            self.explainer.load_feature_names(self.preprocessor.artifacts)
            
            self.is_initialized = True
            print("✅ Pipeline initialization complete!")
            return True
            
        except Exception as e:
            print(f"❌ Pipeline initialization failed: {e}")
            return False
    
    def process_logs(self, input_data):
        """Main processing pipeline"""
        if not self.is_initialized:
            raise RuntimeError("Pipeline not initialized. Call initialize() first.")
        
        print("📊 Processing logs through anomaly detection pipeline...")
        
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
        
        # Step 3: Anomaly detection
        ensemble_errors, attention_weights = self.ensemble_detector.predict(
            processed_data, 
            seq_len=self.config.get('seq_len', 8),
            stride=self.config.get('stride', 8)
        )
        
        # Calculate thresholds
        static_threshold = np.percentile(ensemble_errors, 95)
        static_preds = (ensemble_errors > static_threshold).astype(int)
        anomaly_indices = np.where(static_preds == 1)[0]
        
        # FIXED: Get the actual logs that caused anomalies
        anomaly_logs = self.get_anomaly_logs(anomaly_indices, original_df, 
                                        self.config.get('stride', 8), 
                                        self.config.get('seq_len', 8))
        
        print(f"   • Detected {len(anomaly_indices)} anomalies ({len(anomaly_indices)/len(ensemble_errors)*100:.1f}%)")
        
        # Step 4: Severity classification
        severity_results = []
        for idx in anomaly_indices:
            error = ensemble_errors[idx]
            severity, confidence = self.severity_manager.classify_with_confidence(error)
            severity_results.append({
                'index': int(idx),
                'error': float(error),
                'severity': severity,
                'confidence': float(confidence)
            })
        
        print(f"   • Classified {len(severity_results)} anomalies by severity")
        
        # Step 5: Log type classification
        log_data_for_classification = []
        for idx in range(len(original_df)):
            log_data_for_classification.append({
                'EventTemplate': original_df.iloc[idx].get('EventTemplate', ''),
                'Content': original_df.iloc[idx].get('Content', '')
            })
        
        all_log_classifications = self.log_classifier.batch_classify(log_data_for_classification)
        
        # Classify anomalous logs specifically
        anomalous_log_data = []
        stride = self.config.get('stride', 8)
        for idx in anomaly_indices:
            original_idx = idx * stride
            if original_idx < len(original_df):
                anomalous_log_data.append({
                    'EventTemplate': original_df.iloc[original_idx].get('EventTemplate', ''),
                    'Content': original_df.iloc[original_idx].get('Content', '')
                })
            else:
                anomalous_log_data.append({'EventTemplate': '', 'Content': ''})
        
        anomalous_classifications = self.log_classifier.batch_classify(anomalous_log_data)
        
        print(f"   • Classified {len(all_log_classifications)} total logs by type")
        
        # Step 6: Generate explanations for high-severity anomalies
        high_severity_indices = [
            result['index'] for result in severity_results 
            if result['severity'] in ['High', 'Critical']
        ]
        
        explanations = {}
        if high_severity_indices and attention_weights:
            print(f"   • Generating explanations for {len(high_severity_indices)} high-severity anomalies")
            
            for i, idx in enumerate(high_severity_indices):
                if i < len(attention_weights):
                    explanation = self.explainer.explain_anomaly(attention_weights[i])
                    explanations[int(idx)] = explanation
        
        # Step 7: Compile results - FIXED: Added anomaly_logs
        self.results = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'total_logs_processed': len(df),
                'total_sequences_analyzed': len(ensemble_errors),
                'pipeline_version': '1.0',
                'config': self.config
            },
            'anomaly_detection': {
                'total_anomalies': len(anomaly_indices),
                'anomaly_rate': float(len(anomaly_indices) / len(ensemble_errors) * 100),
                'static_threshold': float(static_threshold),
                'ensemble_errors': ensemble_errors.tolist(),
                'anomaly_indices': anomaly_indices.tolist()
            },
            'anomaly_logs': anomaly_logs,  # This will be JSON serializable now
            'severity_analysis': {
                'classified_anomalies': severity_results,
                'severity_distribution': self._get_severity_distribution(severity_results)
            },
            'log_classification': {
                'total_classified': len(all_log_classifications),
                'classification_stats': self._get_classification_stats(all_log_classifications),
                'anomalous_classifications': [
                    {
                        'index': int(anomaly_indices[i]),
                        'log_type': classification['log_type'],
                        'confidence': classification['confidence'],
                        'is_critical': classification['is_critical']
                    }
                    for i, classification in enumerate(anomalous_classifications)
                ]
            },
            'explanations': {
                'total_explained': len(explanations),
                'explanations': explanations
            }
        }
        
        print("✅ Pipeline processing complete!")
        return self.results
    
    def get_anomaly_logs(self, anomaly_indices, original_df, stride=8, seq_len=8):
        """
        Retrieve the actual log entries that contributed to detected anomalies
        FIXED: Ensure all keys and values are JSON serializable
        """
        anomaly_logs = {}
        
        for seq_idx in anomaly_indices:
            # CRITICAL FIX: Convert numpy int64 to regular int
            seq_idx_int = int(seq_idx)
            
            # Calculate the log range for this sequence
            start_log_idx = seq_idx_int * stride
            end_log_idx = min(start_log_idx + seq_len, len(original_df))
            
            # Extract the logs for this anomalous sequence
            sequence_logs = []
            for log_idx in range(start_log_idx, end_log_idx):
                if log_idx < len(original_df):
                    log_entry = {
                        'log_index': int(log_idx),  # Ensure int, not numpy int64
                        'timestamp': f"{original_df.iloc[log_idx].get('Date', '')} {original_df.iloc[log_idx].get('Time', '')}",
                        'level': str(original_df.iloc[log_idx].get('Level', '')),
                        'component': str(original_df.iloc[log_idx].get('Component', '')),
                        'content': str(original_df.iloc[log_idx].get('Content', '')),
                        'event_template': str(original_df.iloc[log_idx].get('EventTemplate', '')),
                        'event_id': str(original_df.iloc[log_idx].get('EventId', ''))
                    }
                    sequence_logs.append(log_entry)
            
            # CRITICAL FIX: Use string key for JSON compatibility
            anomaly_logs[str(seq_idx_int)] = {
                'sequence_index': int(seq_idx_int),
                'log_range': f"{start_log_idx}-{end_log_idx-1}",
                'total_logs': len(sequence_logs),
                'logs': sequence_logs
            }
        
        return anomaly_logs
    
    def save_results(self, results=None):
        """Save pipeline results to output directory"""
        if results is None:
            results = self.results
        
        if not results:
            raise ValueError("No results to save")
        
        # Create output directory
        output_dir = Path(self.output_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # CRITICAL FIX: Make results JSON serializable before saving
        serializable_results = make_json_serializable(results)
        
        # Save main results
        with open(output_dir / 'anomaly_detection_results.json', 'w') as f:
            json.dump(serializable_results, f, indent=2)
        
        # Save summary
        summary = {
            'pipeline_status': 'SUCCESS',
            'timestamp': results['metadata']['timestamp'],
            'total_logs': results['metadata']['total_logs_processed'],
            'anomalies_detected': results['anomaly_detection']['total_anomalies'],
            'anomaly_rate': results['anomaly_detection']['anomaly_rate'],
            'high_severity_count': len([r for r in results['severity_analysis']['classified_anomalies'] 
                                       if r['severity'] in ['High', 'Critical']]),
            'critical_alerts': len([r for r in results['severity_analysis']['classified_anomalies'] 
                                   if r['severity'] == 'Critical']),
            'recommendation': 'INVESTIGATE' if results['anomaly_detection']['anomaly_rate'] > 10 else 'MONITOR'
        }
        
        # Make summary JSON serializable too
        serializable_summary = make_json_serializable(summary)
        
        with open(output_dir / 'pipeline_summary.json', 'w') as f:
            json.dump(serializable_summary, f, indent=2)
        
        print(f"📁 Results saved to {output_dir}")
        return str(output_dir)
    
    def _get_severity_distribution(self, severity_results):
        """Calculate severity distribution"""
        distribution = {'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0}
        for result in severity_results:
            distribution[result['severity']] += 1
        
        total = len(severity_results)
        percentages = {k: (v/total)*100 if total > 0 else 0 for k, v in distribution.items()}
        
        return {
            'counts': distribution,
            'percentages': percentages,
            'total_anomalies': total
        }
    
    def _get_classification_stats(self, classifications):
        """Calculate classification statistics"""
        stats = {}
        total_logs = len(classifications)
        
        for classification in classifications:
            log_type = classification['log_type']
            stats[log_type] = stats.get(log_type, 0) + 1
        
        percentages = {k: (v/total_logs)*100 for k, v in stats.items()}
        
        return {
            'counts': stats,
            'percentages': percentages,
            'total_logs': total_logs,
            'critical_logs': sum(1 for c in classifications if c.get('is_critical', False))
        }
    
    def generate_report(self):
        """Generate human-readable report"""
        if not self.results:
            raise ValueError("No results available. Run process_logs() first.")
        
        report = []
        report.append("🎉 LOG ANOMALY DETECTION REPORT")
        report.append("=" * 50)
        report.append(f"📊 Analysis Summary:")
        report.append(f"   • Total logs processed: {self.results['metadata']['total_logs_processed']}")
        report.append(f"   • Anomalies detected: {self.results['anomaly_detection']['total_anomalies']} ({self.results['anomaly_detection']['anomaly_rate']:.1f}%)")
        
        # Severity analysis
        severity_dist = self.results['severity_analysis']['severity_distribution']
        report.append(f"\n🚨 Severity Analysis:")
        for severity, count in severity_dist['counts'].items():
            percentage = severity_dist['percentages'][severity]
            report.append(f"   • {severity}: {count} anomalies ({percentage:.1f}%)")
        
        # Classification analysis
        class_stats = self.results['log_classification']['classification_stats']
        report.append(f"\n🏷️ Log Classification:")
        for log_type, count in class_stats['counts'].items():
            percentage = class_stats['percentages'][log_type]
            report.append(f"   • {log_type.replace('_', ' ').title()}: {count} logs ({percentage:.1f}%)")
        
        # Top anomalies
        top_anomalies = sorted(
            self.results['severity_analysis']['classified_anomalies'], 
            key=lambda x: x['error'], reverse=True
        )[:5]
        
        if top_anomalies:
            report.append(f"\n🔥 Top 5 Most Severe Anomalies:")
            for i, anomaly in enumerate(top_anomalies, 1):
                report.append(f"   {i}. Index {anomaly['index']}: {anomaly['severity']} "
                            f"(Error: {anomaly['error']:.4f}, Confidence: {anomaly['confidence']:.2f})")
        
        return "\n".join(report)
