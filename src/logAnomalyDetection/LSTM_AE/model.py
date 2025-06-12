import torch
import torch.nn as nn
import numpy as np
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.impute import SimpleImputer
import pickle
import warnings
warnings.filterwarnings('ignore')

class AttentionLSTMAutoencoder(nn.Module):
    """Enhanced LSTM Autoencoder with Multi-head Attention"""
    def __init__(self, input_dim, hidden_dim=16, dropout=0.4):
        super().__init__()
        self.hidden_dim = hidden_dim
        
        # Encoder with bidirectional LSTM
        self.encoder = nn.LSTM(input_dim, hidden_dim, batch_first=True, 
                              num_layers=2, dropout=dropout, bidirectional=True)
        
        # Multi-head attention
        self.attention = nn.MultiheadAttention(hidden_dim * 2, num_heads=4, 
                                             dropout=dropout, batch_first=True)
        
        # Decoder
        self.decoder = nn.LSTM(hidden_dim * 2, hidden_dim, batch_first=True, 
                              num_layers=2, dropout=dropout)
        
        # Output layers
        self.batch_norm = nn.BatchNorm1d(hidden_dim)
        self.output_layer = nn.Linear(hidden_dim, input_dim)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x):
        # Encoder
        enc_out, (hidden, cell) = self.encoder(x)
        
        # Self-attention
        attn_out, attn_weights = self.attention(enc_out, enc_out, enc_out)
        attn_out = self.dropout(attn_out)
        
        # Decoder
        dec_out, _ = self.decoder(attn_out)
        
        # Batch normalization and output
        batch_size, seq_len, hidden_size = dec_out.shape
        dec_out_norm = self.batch_norm(dec_out.transpose(1, 2)).transpose(1, 2)
        output = self.output_layer(dec_out_norm)
        
        return output, attn_weights

class EnhancedEnsembleDetector:
    """Production-ready ensemble anomaly detector"""
    def __init__(self, model_path="src/logAnomalyDetection/LSTM-AE/"):
        self.model_path = model_path
        self.models = []
        self.weights = []
        self.input_dim = None
        self.artifacts = None
        
    def load_models(self):
        """Load pre-trained ensemble models"""
        try:
            # Load artifacts
            with open(f"{self.model_path}ensemble_artifacts.pkl", 'rb') as f:
                self.artifacts = pickle.load(f)
            
            self.input_dim = self.artifacts['input_dim']
            self.weights = self.artifacts['ensemble_weights']
            
            # Load models
            configs = [
                {'hidden_dim': 16, 'dropout': 0.3},
                {'hidden_dim': 24, 'dropout': 0.4},
                {'hidden_dim': 32, 'dropout': 0.2}
            ]
            
            for i, config in enumerate(configs):
                model = AttentionLSTMAutoencoder(self.input_dim, **config)
                model.load_state_dict(torch.load(f"{self.model_path}ensemble_model_{i}.pth"))
                model.eval()
                self.models.append(model)
            
            print(f"✅ Loaded {len(self.models)} ensemble models")
            return True
            
        except Exception as e:
            print(f"❌ Error loading models: {e}")
            return False
    
    def predict(self, processed_data, seq_len=8, stride=8):
        """Generate anomaly predictions"""
        if not self.models:
            raise RuntimeError("Models not loaded. Call load_models() first.")
        
        # Create sequences
        sequences = []
        for i in range(0, len(processed_data) - seq_len, stride):
            sequences.append(processed_data[i:i + seq_len])
        
        if not sequences:
            return np.array([]), []
        
        sequences = torch.tensor(sequences, dtype=torch.float)
        
        # Get predictions from all models
        all_errors = []
        all_attentions = []
        
        with torch.no_grad():
            for i, model in enumerate(self.models):
                model_errors = []
                model_attentions = []
                
                for seq in sequences:
                    seq_batch = seq.unsqueeze(0)
                    reconstruction, attention = model(seq_batch)
                    error = torch.mean((seq_batch - reconstruction) ** 2).item()
                    model_errors.append(error)
                    model_attentions.append(attention)
                
                all_errors.append(model_errors)
                all_attentions.append(model_attentions)
        
        # Weighted ensemble prediction
        ensemble_errors = np.average(all_errors, axis=0, weights=self.weights)
        
        return ensemble_errors, all_attentions[np.argmin([np.mean(errors) for errors in all_errors])]

class DataPreprocessor:
    """Production data preprocessing pipeline"""
    def __init__(self, artifacts_path="src/logAnomalyDetection/LSTM-AE/ensemble_artifacts.pkl"):
        self.artifacts_path = artifacts_path
        self.artifacts = None
        
    def load_preprocessing_artifacts(self):
        """Load preprocessing components"""
        try:
            with open(self.artifacts_path, 'rb') as f:
                self.artifacts = pickle.load(f)
            print("✅ Loaded preprocessing artifacts")
            return True
        except Exception as e:
            print(f"❌ Error loading preprocessing artifacts: {e}")
            return False
    
    def preprocess(self, df):
        """Apply preprocessing pipeline"""
        if not self.artifacts:
            raise RuntimeError("Preprocessing artifacts not loaded")
        
        # Store original for reference
        original_df = df.copy()
        
        # Drop problematic columns
        columns_to_drop = ["LineId", "Time", "Date", "PID"]
        df = df.drop(columns=[col for col in columns_to_drop if col in df.columns])
        
        # Extract content features
        if "Content" in df.columns:
            df['content_length'] = df['Content'].str.len()
            df['content_word_count'] = df['Content'].str.split().str.len()
            df['content_has_error'] = df['Content'].str.contains(
                r'\b(error|fail|exception|crash|abort|fault)\b', case=False, na=False
            ).astype(int)
            df['content_has_warning'] = df['Content'].str.contains(
                r'\b(warn|alert|caution)\b', case=False, na=False
            ).astype(int)
            df['content_has_large_numbers'] = df['Content'].str.contains(
                r'\b\d{4,}\b', na=False
            ).astype(int)
            df['content_has_critical'] = df['Content'].str.contains(
                r'\b(critical|fatal|panic|segfault|timeout|killed)\b', case=False, na=False
            ).astype(int)
            df['content_has_network'] = df['Content'].str.contains(
                r'\b(connection|socket|port|network|tcp|udp)\b', case=False, na=False
            ).astype(int)
            df['content_has_memory'] = df['Content'].str.contains(
                r'\b(memory|malloc|free|leak|oom|out of memory)\b', case=False, na=False
            ).astype(int)
            df = df.drop(columns=["Content"])
        
        # Remove Month if present
        if "Month" in df.columns:
            df = df.drop(columns=["Month"])
        
        # Process categorical features
        categorical_cols = ["Level", "Component", "EventId"]
        if "EventTemplate" in df.columns:
            categorical_cols.append("EventTemplate")
        
        categorical_cols = [col for col in categorical_cols if col in df.columns]
        
        if categorical_cols and "EventTemplate" in categorical_cols:
            # Apply TF-IDF to EventTemplate
            tfidf_encoder, other_ohe = self.artifacts['ohe']
            template_features = tfidf_encoder.transform(df["EventTemplate"].astype(str)).toarray()
            
            # Process other categoricals
            other_cats = [col for col in categorical_cols if col != "EventTemplate"]
            if other_cats:
                other_features = other_ohe.transform(df[other_cats].astype(str))
                cat_features = np.hstack([template_features, other_features])
            else:
                cat_features = template_features
            
            df = df.drop(columns=categorical_cols)
        
        # Process numerical features
        numerical_cols = list(df.columns)
        if len(numerical_cols) > 0:
            num_features = self.artifacts['imputer'].transform(df[numerical_cols])
        else:
            num_features = np.array([]).reshape(len(df), 0)
        
        # Combine features
        if cat_features.shape[1] > 0 and num_features.shape[1] > 0:
            combined = np.hstack([cat_features, num_features])
        elif cat_features.shape[1] > 0:
            combined = cat_features
        else:
            combined = num_features
        
        # Apply scaling
        scaled_data = self.artifacts['scaler'].transform(combined)
        
        return scaled_data, original_df
