import torch
import numpy as np

class AttentionExplainer:
    """Production attention-based explainer"""
    def __init__(self, artifacts_path="src/logAnomalyDetection/LSTM-AE/ensemble_artifacts.pkl"):
        self.feature_names = []
        self.artifacts_path = artifacts_path
        
    def load_feature_names(self, artifacts):
        """Load feature names from artifacts"""
        self.feature_names = artifacts.get('feature_names', [])
        
    def explain_anomaly(self, attention_weights, top_k=10):
        """Generate explanation for anomaly"""
        if len(attention_weights.shape) == 4:
            avg_attention = torch.mean(attention_weights.squeeze(0), dim=0)
            sequence_attention = torch.mean(avg_attention, dim=0)
        elif len(attention_weights.shape) == 3:
            avg_attention = torch.mean(attention_weights, dim=0)
            sequence_attention = torch.mean(avg_attention, dim=0)
        else:
            sequence_attention = attention_weights.flatten()
        
        # Handle feature dimension mismatch
        expected_features = len(self.feature_names)
        actual_attention_size = len(sequence_attention)
        
        if actual_attention_size != expected_features and expected_features > 0:
            if actual_attention_size > expected_features:
                chunk_size = actual_attention_size // expected_features
                aggregated_attention = []
                for i in range(expected_features):
                    start_idx = i * chunk_size
                    end_idx = start_idx + chunk_size
                    chunk_attention = torch.mean(sequence_attention[start_idx:end_idx])
                    aggregated_attention.append(chunk_attention)
                sequence_attention = torch.stack(aggregated_attention)
        
        # Get top contributing features
        top_k = min(top_k, len(sequence_attention))
        top_indices = torch.topk(sequence_attention, top_k).indices
        top_weights = sequence_attention[top_indices]
        
        explanation = {
            'top_features': [
                {
                    'feature_name': self.feature_names[idx.item()] if idx.item() < len(self.feature_names) else f"feature_{idx.item()}",
                    'feature_index': idx.item(),
                    'attention_weight': weight.item(),
                    'contribution_percentage': (weight.item() / torch.sum(top_weights).item()) * 100 if torch.sum(top_weights).item() > 0 else 0,
                    'feature_category': self._get_feature_category(self.feature_names[idx.item()] if idx.item() < len(self.feature_names) else "unknown")
                }
                for idx, weight in zip(top_indices, top_weights)
            ],
            'explanation_coverage': (torch.sum(top_weights).item() / torch.sum(sequence_attention).item()) * 100 if torch.sum(sequence_attention).item() > 0 else 0
        }
        
        return explanation
    
    def _get_feature_category(self, feature_name):
        """Categorize feature for explanation"""
        feature_lower = feature_name.lower()
        
        if 'eventtemplate_' in feature_lower:
            return 'event_template'
        elif 'level_' in feature_lower:
            return 'log_level'
        elif 'component_' in feature_lower:
            return 'component'
        elif 'content_' in feature_lower:
            return 'content_derived'
        else:
            return 'other'
