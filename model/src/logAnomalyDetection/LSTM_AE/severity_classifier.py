import numpy as np
import re
from collections import Counter

class EnhancedSeverityManager:
    def __init__(self, percentiles=None, severity_labels=None):
        self.percentiles = percentiles or [85, 95, 99]
        self.severity_labels = severity_labels or ['Low', 'Medium', 'High', 'Critical']
        self.threshold_values = {}
        self.error_stats = {}
        
    def learn_thresholds(self, error_distribution, validation_errors=None):
        """Learn thresholds with optional validation for stability"""
        error_array = np.array(error_distribution)
        
        # Learn primary thresholds
        for p in self.percentiles:
            self.threshold_values[f'p{p}'] = np.percentile(error_array, p)
        
        # Store distribution statistics
        self.error_stats = {
            'mean': np.mean(error_array),
            'std': np.std(error_array),
            'median': np.median(error_array),
            'iqr': np.percentile(error_array, 75) - np.percentile(error_array, 25)
        }
        
        print(f"✅ Learned severity thresholds: {self.threshold_values}")
        print(f"📊 Error distribution stats: {self.error_stats}")
    
    def load_thresholds(self, artifacts):
        """Load thresholds from artifacts for inference"""
        if 'severity_manager' in artifacts:
            severity_manager = artifacts['severity_manager']
            self.threshold_values = severity_manager.threshold_values
            self.error_stats = severity_manager.error_stats
            print("✅ Loaded severity thresholds from artifacts")
        else:
            print("⚠️ No severity thresholds found in artifacts")
    
    def classify_with_confidence(self, error):
        """Classify severity with confidence score"""
        if not self.threshold_values:
            raise RuntimeError("Thresholds not learned. Call learn_thresholds() first.")
        
        # Determine severity level
        severity_idx = 0
        for i, p in enumerate(self.percentiles):
            if error > self.threshold_values[f'p{p}']:
                severity_idx = i + 1
        
        severity = self.severity_labels[severity_idx]
        
        # Calculate confidence based on distance from threshold
        if severity_idx == 0:
            threshold = self.threshold_values[f'p{self.percentiles[0]}']
            confidence = max(0.1, 1.0 - (error / threshold))
        else:
            current_threshold = self.threshold_values[f'p{self.percentiles[severity_idx-1]}']
            confidence = min(1.0, (error - current_threshold) / current_threshold + 0.5)
        
        return severity, min(1.0, max(0.1, confidence))

class RuleBasedLogClassifier:
    def __init__(self):
        self.classification_rules = {
            'memory_error': [
                r'\b(out of memory|oom|page allocation failure|dma timeout)\b',
                r'\b(malloc failed|memory leak|segfault|kernel panic)\b',
                r'\b(swap.*full|virtual memory|memory pressure)\b'
            ],
            'authentication_error': [
                r'\b(authentication failure|invalid username|login failed)\b',
                r'\b(kerberos.*failed|pam_unix.*failed|ssh.*failed)\b',
                r'\b(password.*incorrect|access denied|unauthorized)\b'
            ],
            'filesystem_error': [
                r'\b(no such file|permission denied|disk full|quota exceeded)\b',
                r'\b(failed command|status timeout|drive not ready|io error)\b',
                r'\b(filesystem.*corrupt|bad sector|read.*error)\b'
            ],
            'network_error': [
                r'\b(connection timed out|connection refused|peer died)\b',
                r'\b(network unreachable|socket error|host.*down)\b',
                r'\b(dns.*failed|routing.*error|packet.*lost)\b'
            ],
            'permission_error': [
                r'\b(permission denied|operation not supported|access forbidden)\b',
                r'\b(selinux.*denied|capability.*denied|privilege.*error)\b',
                r'\b(sudo.*failed|su.*failed|root.*access)\b'
            ],
            'system_critical': [
                r'\b(critical|fatal|panic|emergency|alert)\b',
                r'\b(system.*halt|kernel.*oops|hardware.*error)\b',
                r'\b(temperature.*critical|power.*failure)\b'
            ]
        }
        
        self.pattern_weights = {
            'memory_error': 0.9,
            'authentication_error': 0.95,
            'filesystem_error': 0.85,
            'network_error': 0.8,
            'permission_error': 0.9,
            'system_critical': 0.95
        }
    
    def classify_log(self, event_template, content=""):
        """Classify a single log entry"""
        combined_text = f"{event_template} {content}".lower()
        
        for category, patterns in self.classification_rules.items():
            for pattern in patterns:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    confidence = self._calculate_confidence(pattern, combined_text, category)
                    return {
                        'log_type': category,
                        'confidence': confidence,
                        'matched_pattern': pattern,
                        'is_critical': category in ['system_critical', 'authentication_error']
                    }
        
        return {
            'log_type': 'normal',
            'confidence': 0.7,
            'matched_pattern': None,
            'is_critical': False
        }
    
    def batch_classify(self, log_data_list):
        """Classify multiple logs at once"""
        results = []
        for log_data in log_data_list:
            event_template = log_data.get('EventTemplate', '')
            content = log_data.get('Content', '')
            result = self.classify_log(event_template, content)
            results.append(result)
        return results
    
    def _calculate_confidence(self, pattern, text, category):
        """Calculate confidence based on pattern specificity and context"""
        base_confidence = self.pattern_weights.get(category, 0.7)
        pattern_specificity = min(len(pattern) / 50.0, 0.3)
        keywords = re.findall(r'\w+', pattern.lower())
        keyword_matches = sum(1 for keyword in keywords if keyword in text)
        keyword_bonus = min(keyword_matches * 0.05, 0.2)
        final_confidence = min(base_confidence + pattern_specificity + keyword_bonus, 0.98)
        return round(final_confidence, 3)
