import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
import pandas as pd
import numpy as np
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.impute import SimpleImputer
import pickle
from tqdm import tqdm

class LogDataset(Dataset):
    def __init__(self, data, seq_len=8, stride=8, return_indices=False):
        self.seq_len = seq_len
        self.stride = stride
        self.data = data
        self.return_indices = return_indices
        self.samples = []
        self.indices = []
        
        for i in range(0, len(data)-seq_len, stride):
            self.samples.append(data[i:i+seq_len])
            self.indices.append(i)

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        sample = torch.tensor(self.samples[idx], dtype=torch.float)
        if self.return_indices:
            return sample, self.indices[idx]
        return sample

class HybridAttentionLSTMAutoencoder(nn.Module):
    def __init__(self, input_dim, hidden_dim=16, dropout=0.4, enable_single_log=True):
        super().__init__()
        self.hidden_dim = hidden_dim
        self.input_dim = input_dim
        self.enable_single_log = enable_single_log
        
        # Sequential processing components (original approach)
        self.encoder = nn.LSTM(input_dim, hidden_dim, batch_first=True, 
                              num_layers=2, dropout=dropout, bidirectional=True)
        
        self.attention = nn.MultiheadAttention(hidden_dim * 2, num_heads=4, 
                                             dropout=dropout, batch_first=True)
        
        self.decoder = nn.LSTM(hidden_dim * 2, hidden_dim, batch_first=True, 
                              num_layers=2, dropout=dropout)
        
        # Single log processing components (new approach)
        if enable_single_log:
            self.single_log_encoder = nn.Sequential(
                nn.Linear(input_dim, hidden_dim * 2),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(hidden_dim * 2, hidden_dim),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(hidden_dim, hidden_dim // 2)
            )
            
            self.single_log_decoder = nn.Sequential(
                nn.Linear(hidden_dim // 2, hidden_dim),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(hidden_dim, hidden_dim * 2),
                nn.ReLU(),
                nn.Linear(hidden_dim * 2, input_dim)
            )
        
        # Shared output layers
        self.batch_norm = nn.BatchNorm1d(hidden_dim)
        self.output_layer = nn.Linear(hidden_dim, input_dim)
        self.dropout = nn.Dropout(dropout)
        
        # Fusion layer for combining both approaches
        self.fusion_layer = nn.Linear(input_dim * 2, input_dim)
        
    def forward(self, x, mode='hybrid'):
        batch_size, seq_len, feature_dim = x.shape
        
        if mode == 'single' or (mode == 'hybrid' and self.enable_single_log):
            # Single log processing path
            single_outputs = []
            single_attentions = []
            
            for i in range(seq_len):
                log_features = x[:, i, :]
                encoded_single = self.single_log_encoder(log_features)
                decoded_single = self.single_log_decoder(encoded_single)
                single_outputs.append(decoded_single)
                dummy_attention = torch.ones(batch_size, 1, 1) / seq_len
                single_attentions.append(dummy_attention)
            
            single_reconstruction = torch.stack(single_outputs, dim=1)
            single_attention_weights = torch.cat(single_attentions, dim=2)
        
        if mode == 'sequential' or mode == 'hybrid':
            # Sequential processing path (original)
            enc_out, (hidden, cell) = self.encoder(x)
            attn_out, attn_weights = self.attention(enc_out, enc_out, enc_out)
            attn_out = self.dropout(attn_out)
            dec_out, _ = self.decoder(attn_out)
            
            # Batch normalization and output
            dec_out_norm = self.batch_norm(dec_out.transpose(1, 2)).transpose(1, 2)
            sequential_reconstruction = self.output_layer(dec_out_norm)
        
        # Return based on mode
        if mode == 'single':
            return single_reconstruction, single_attention_weights
        elif mode == 'sequential':
            return sequential_reconstruction, attn_weights
        else:  # hybrid mode
            # Combine both reconstructions
            combined_features = torch.cat([sequential_reconstruction, single_reconstruction], dim=-1)
            hybrid_reconstruction = self.fusion_layer(combined_features)
            combined_attention = 0.6 * attn_weights + 0.4 * single_attention_weights.expand_as(attn_weights)
            return hybrid_reconstruction, combined_attention

class HybridEnsembleDetector:
    def __init__(self, input_dim=None, num_models=3, enable_single_log=True, model_path=None):
        self.models = []
        self.weights = []
        self.input_dim = input_dim
        self.enable_single_log = enable_single_log
        self.model_path = model_path
        self.is_loaded = False
        
        if input_dim:
            configs = [
                {'hidden_dim': 16, 'dropout': 0.3},
                {'hidden_dim': 24, 'dropout': 0.4},
                {'hidden_dim': 32, 'dropout': 0.2}
            ]
            
            for i, config in enumerate(configs[:num_models]):
                model = HybridAttentionLSTMAutoencoder(
                    input_dim, 
                    enable_single_log=enable_single_log,
                    **config
                )
                self.models.append(model)
                self.weights.append(1.0)
    
    def load_models(self, model_path=None):
        """Load pre-trained ensemble models for inference"""
        if model_path:
            self.model_path = model_path
        
        if not self.model_path:
            raise ValueError("Model path not specified")
        
        try:
            # Load artifacts to get model configuration
            artifacts_path = f"{self.model_path}/hybrid_ensemble_artifacts.pkl"
            with open(artifacts_path, 'rb') as f:
                artifacts = pickle.load(f)
            
            self.input_dim = artifacts['input_dim']
            self.weights = artifacts.get('ensemble_weights', [1.0, 1.0, 1.0])
            
            # Initialize models with loaded configuration
            configs = [
                {'hidden_dim': 16, 'dropout': 0.3},
                {'hidden_dim': 24, 'dropout': 0.4},
                {'hidden_dim': 32, 'dropout': 0.2}
            ]
            
            self.models = []
            for i, config in enumerate(configs):
                model = HybridAttentionLSTMAutoencoder(
                    self.input_dim,
                    enable_single_log=self.enable_single_log,
                    **config
                )
                
                # Load model weights
                model_file = f"{self.model_path}/hybrid_ensemble_model_{i}.pth"
                model.load_state_dict(torch.load(model_file, map_location='cpu'))
                model.eval()
                
                self.models.append(model)
            
            self.is_loaded = True
            print(f"✅ Loaded {len(self.models)} hybrid ensemble models")
            return True
            
        except Exception as e:
            print(f"❌ Failed to load models: {e}")
            return False
    
    def predict(self, dataloader, mode='hybrid'):
        """Predict with specified mode"""
        if not self.is_loaded:
            raise RuntimeError("Models not loaded. Call load_models() first.")
        
        all_errors = []
        
        for i, model in enumerate(self.models):
            errors = self.evaluate_hybrid_model(model, dataloader, mode)
            all_errors.append(errors)
        
        # Weighted ensemble prediction
        ensemble_errors = np.average(all_errors, axis=0, weights=self.weights)
        
        return ensemble_errors, all_errors
    
    def evaluate_hybrid_model(self, model, dataloader, mode='hybrid'):
        model.eval()
        errors = []
        with torch.no_grad():
            for batch in dataloader:
                reconstructions, _ = model(batch, mode=mode)
                batch_errors = torch.mean((batch - reconstructions)**2, dim=(1,2))
                errors.extend(batch_errors.numpy())
        return np.array(errors)

class DataPreprocessor:
    def __init__(self, artifacts_path=None):
        self.artifacts_path = artifacts_path
        self.artifacts = None
        self.is_loaded = False
    
    def load_preprocessing_artifacts(self, artifacts_path=None):
        """Load preprocessing artifacts for inference"""
        if artifacts_path:
            self.artifacts_path = artifacts_path
        
        if not self.artifacts_path:
            raise ValueError("Artifacts path not specified")
        
        try:
            with open(self.artifacts_path, 'rb') as f:
                self.artifacts = pickle.load(f)
            
            self.is_loaded = True
            print("✅ Loaded preprocessing artifacts")
            return True
            
        except Exception as e:
            print(f"❌ Failed to load preprocessing artifacts: {e}")
            return False
    
    def preprocess(self, df):
        """Preprocess data using the same logic as training"""
        if not self.is_loaded:
            raise RuntimeError("Preprocessing artifacts not loaded")
        
        # Store original data for reference
        original_df = df.copy()
        
        # Apply same preprocessing as training
        # Remove problematic columns
        columns_to_drop = ["LineId", "Time"]
        
        if "Date" in df.columns:
            columns_to_drop.append("Date")
        if "PID" in df.columns:
            columns_to_drop.append("PID")
        if "Month" in df.columns:
            columns_to_drop.append("Month")
        
        df = df.drop(columns=[col for col in columns_to_drop if col in df.columns])
        
        # Define categorical columns
        categorical_cols = ["Level", "Component", "EventId"]
        
        # Handle EventTemplate
        if "EventTemplate" in df.columns:
            unique_templates = df["EventTemplate"].nunique()
            if unique_templates < 1000:
                categorical_cols.append("EventTemplate")
            else:
                df = df.drop(columns=["EventTemplate"])
        
        # Handle Content column
        if "Content" in df.columns:
            # Extract features from content
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
        
        # Process categorical features using stored artifacts
        categorical_cols = [col for col in categorical_cols if col in df.columns]
        
        if categorical_cols:
            ohe = self.artifacts['ohe']
            if isinstance(ohe, tuple):
                # Handle TF-IDF + OHE case
                tfidf, other_ohe = ohe
                if "EventTemplate" in categorical_cols and tfidf:
                    template_features = tfidf.transform(df["EventTemplate"].astype(str)).toarray()
                    df = df.drop(columns=["EventTemplate"])
                    categorical_cols.remove("EventTemplate")
                    
                    if categorical_cols and other_ohe:
                        other_features = other_ohe.transform(df[categorical_cols].astype(str))
                        cat_features = np.hstack([template_features, other_features])
                    else:
                        cat_features = template_features
                else:
                    cat_features = other_ohe.transform(df[categorical_cols].astype(str))
            else:
                # Regular OHE
                cat_features = ohe.transform(df[categorical_cols].astype(str))
            
            df = df.drop(columns=categorical_cols)
        else:
            cat_features = np.array([]).reshape(len(df), 0)
        
        # Process numerical features
        numerical_cols = list(df.columns)
        if len(numerical_cols) > 0:
            imputer = self.artifacts['imputer']
            num_features = imputer.transform(df[numerical_cols])
        else:
            num_features = np.array([]).reshape(len(df), 0)
        
        # Combine features
        if cat_features.shape[1] > 0 and num_features.shape[1] > 0:
            combined = np.hstack([cat_features, num_features])
        elif cat_features.shape[1] > 0:
            combined = cat_features
        elif num_features.shape[1] > 0:
            combined = num_features
        else:
            raise ValueError("No features remaining after preprocessing!")
        
        # Apply scaling
        scaler = self.artifacts['scaler']
        scaled_data = scaler.transform(combined)
        
        return scaled_data, original_df
