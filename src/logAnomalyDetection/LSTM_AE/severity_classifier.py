import numpy as np
import re
from datetime import datetime

class EnhancedSeverityManager:
    """Advanced severity classification with confidence scoring"""
    def __init__(self, percentiles=None, severity_labels=None):
        self.percentiles = percentiles or [85, 95, 99]
        self.severity_labels = severity_labels or ['Low', 'Medium', 'High', 'Critical']
        self.threshold_values = {}
        self.error_stats = {}
        
    def load_thresholds(self, artifacts):
        """Load pre-computed thresholds"""
        self.threshold_values = artifacts.get('severity_thresholds', {})
        self.error_stats = artifacts.get('severity_stats', {})
        
    def classify_with_confidence(self, error):
        """Classify severity with confidence score"""
        if not self.threshold_values:
            raise RuntimeError("Thresholds not loaded")
        
        severity_idx = 0
        for i, p in enumerate(self.percentiles):
            if error > self.threshold_values[f'p{p}']:
                severity_idx = i + 1
        
        severity = self.severity_labels[severity_idx]
        
        # Calculate confidence
        if severity_idx == 0:
            threshold = self.threshold_values[f'p{self.percentiles[0]}']
            confidence = max(0.1, 1.0 - (error / threshold))
        else:
            current_threshold = self.threshold_values[f'p{self.percentiles[severity_idx-1]}']
            confidence = min(1.0, (error - current_threshold) / current_threshold + 0.5)
        
        return severity, min(1.0, max(0.1, confidence))

class RuleBasedLogClassifier:
    """Production rule-based log classifier"""
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
    
    def _calculate_confidence(self, pattern, text, category):
        """Calculate confidence based on pattern specificity"""
        base_confidence = self.pattern_weights.get(category, 0.7)
        pattern_specificity = min(len(pattern) / 50.0, 0.3)
        keywords = re.findall(r'\w+', pattern.lower())
        keyword_matches = sum(1 for keyword in keywords if keyword in text)
        keyword_bonus = min(keyword_matches * 0.05, 0.2)
        
        final_confidence = min(base_confidence + pattern_specificity + keyword_bonus, 0.98)
        return round(final_confidence, 3)
    
    def batch_classify(self, log_data):
        """Classify multiple logs efficiently"""
        results = []
        for log_entry in log_data:
            event_template = log_entry.get('EventTemplate', '')
            content = log_entry.get('Content', '')
            classification = self.classify_log(event_template, content)
            results.append(classification)
        return results
