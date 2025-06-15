import pandas as pd
import numpy as np
import re
from pathlib import Path

class TrainingDataCleaner:
    """
    Comprehensive training data cleaner for anomaly detection
    Removes all known anomalous patterns to create clean baseline
    """
    
    def __init__(self):
        # Define comprehensive anomaly patterns
        self.anomaly_patterns = {
            'authentication_errors': [
                r'\b(authentication failure|invalid username|login failed)\b',
                r'\b(password.*incorrect|access denied|unauthorized)\b',
                r'\b(kerberos.*failed|pam_unix.*failed|ssh.*failed)\b',
                r'\b(failed.*login|login.*denied|bad.*password)\b',
                r'\b(authentication.*error|auth.*fail|credential.*invalid)\b'
            ],
            'memory_errors': [
                r'\b(out of memory|oom|page allocation failure|dma timeout)\b',
                r'\b(malloc failed|memory leak|segfault|kernel panic)\b',
                r'\b(swap.*full|virtual memory|memory pressure)\b',
                r'\b(memory.*error|memory.*fault|allocation.*failed)\b',
                r'\b(stack overflow|buffer overflow|heap.*corruption)\b'
            ],
            'filesystem_errors': [
                r'\b(no such file|permission denied|disk full|quota exceeded)\b',
                r'\b(failed command|status timeout|drive not ready|io error)\b',
                r'\b(filesystem.*corrupt|bad sector|read.*error)\b',
                r'\b(file.*not.*found|directory.*not.*found|path.*invalid)\b',
                r'\b(disk.*error|mount.*failed|unmount.*error)\b'
            ],
            'network_errors': [
                r'\b(connection timed out|connection refused|peer died)\b',
                r'\b(network unreachable|socket error|host.*down)\b',
                r'\b(dns.*failed|routing.*error|packet.*lost)\b',
                r'\b(connection.*reset|connection.*aborted|network.*error)\b',
                r'\b(timeout.*occurred|unreachable.*host|broken.*pipe)\b'
            ],
            'permission_errors': [
                r'\b(permission denied|operation not supported|access forbidden)\b',
                r'\b(selinux.*denied|capability.*denied|privilege.*error)\b',
                r'\b(sudo.*failed|su.*failed|root.*access.*denied)\b',
                r'\b(insufficient.*privileges|unauthorized.*access)\b'
            ],
            'system_critical': [
                r'\b(critical|fatal|panic|emergency|alert)\b',
                r'\b(system.*halt|kernel.*oops|hardware.*error)\b',
                r'\b(temperature.*critical|power.*failure)\b',
                r'\b(service.*failed|daemon.*crashed|process.*killed)\b',
                r'\b(system.*crash|kernel.*crash|fatal.*error)\b'
            ],
            'security_events': [
                r'\b(intrusion|attack|malware|virus|trojan)\b',
                r'\b(suspicious.*activity|security.*violation|breach)\b',
                r'\b(unauthorized.*attempt|illegal.*access)\b',
                r'\b(firewall.*blocked|ips.*alert|ids.*detection)\b'
            ],
            'application_errors': [
                r'\b(exception|error|fail|crash|abort|fault)\b',
                r'\b(stack.*trace|null.*pointer|index.*out.*of.*bounds)\b',
                r'\b(connection.*lost|timeout.*expired|operation.*failed)\b',
                r'\b(service.*unavailable|internal.*error|bad.*request)\b'
            ]
        }
        
        # Error level patterns
        self.error_levels = ['ERROR', 'CRITICAL', 'FATAL', 'ALERT', 'EMERGENCY']
        
        # Component patterns that often indicate issues
        self.problematic_components = [
            'kernel', 'oom-killer', 'segfault', 'audit', 'firewall',
            'fail2ban', 'sshguard', 'intrusion', 'security'
        ]
    
    def clean_training_data(self, df, aggressive=True):
        """
        Clean training data by removing anomalous patterns
        
        Args:
            df: Input DataFrame with log data
            aggressive: If True, applies stricter cleaning
        
        Returns:
            Cleaned DataFrame suitable for training
        """
        print("🧹 Starting comprehensive training data cleaning...")
        original_count = len(df)
        
        # Create a copy to work with
        clean_df = df.copy()
        
        # Step 1: Remove by log level
        print("   • Removing error-level logs...")
        clean_df = self._remove_error_levels(clean_df)
        print(f"     Removed {original_count - len(clean_df)} error-level logs")
        
        # Step 2: Remove by content patterns
        print("   • Removing anomalous content patterns...")
        clean_df = self._remove_anomalous_content(clean_df, aggressive)
        print(f"     Removed {original_count - len(clean_df)} total logs with anomalous content")
        
        # Step 3: Remove by component patterns
        print("   • Removing problematic components...")
        clean_df = self._remove_problematic_components(clean_df)
        print(f"     Removed {original_count - len(clean_df)} total logs from problematic components")
        
        # Step 4: Remove statistical outliers
        if aggressive:
            print("   • Removing statistical outliers...")
            clean_df = self._remove_statistical_outliers(clean_df)
            print(f"     Removed {original_count - len(clean_df)} total logs including outliers")
        
        # Step 5: Final validation
        clean_df = self._final_validation(clean_df)
        
        final_count = len(clean_df)
        removed_count = original_count - final_count
        removal_percentage = (removed_count / original_count) * 100
        
        print(f"✅ Cleaning complete!")
        print(f"   • Original logs: {original_count}")
        print(f"   • Clean logs: {final_count}")
        print(f"   • Removed: {removed_count} ({removal_percentage:.1f}%)")
        
        return clean_df
    
    def _remove_error_levels(self, df):
        """Remove logs with error levels"""
        if 'Level' in df.columns:
            mask = ~df['Level'].isin(self.error_levels)
            return df[mask]
        return df
    
    def _remove_anomalous_content(self, df, aggressive=True):
        """Remove logs matching anomalous content patterns"""
        if 'Content' not in df.columns and 'EventTemplate' not in df.columns:
            return df
        
        # Combine content and event template for pattern matching
        text_columns = []
        if 'Content' in df.columns:
            text_columns.append('Content')
        if 'EventTemplate' in df.columns:
            text_columns.append('EventTemplate')
        
        # Create combined text for pattern matching
        combined_text = df[text_columns].fillna('').apply(
            lambda row: ' '.join(row.astype(str)), axis=1
        ).str.lower()
        
        # Apply all anomaly patterns
        mask = pd.Series([True] * len(df), index=df.index)
        
        for category, patterns in self.anomaly_patterns.items():
            for pattern in patterns:
                pattern_mask = ~combined_text.str.contains(pattern, case=False, na=False, regex=True)
                mask = mask & pattern_mask
                
                # Debug info
                removed_by_pattern = (~pattern_mask).sum()
                if removed_by_pattern > 0:
                    print(f"     Pattern '{pattern[:30]}...' removed {removed_by_pattern} logs")
        
        return df[mask]
    
    def _remove_problematic_components(self, df):
        """Remove logs from components known to generate anomalies"""
        if 'Component' not in df.columns:
            return df
        
        # Create mask for problematic components
        mask = pd.Series([True] * len(df), index=df.index)
        
        for component in self.problematic_components:
            component_mask = ~df['Component'].str.contains(
                component, case=False, na=False, regex=True
            )
            mask = mask & component_mask
        
        return df[mask]
    
    def _remove_statistical_outliers(self, df):
        """Remove statistical outliers in content length and other metrics"""
        if 'Content' not in df.columns:
            return df
        
        # Calculate content statistics
        df_temp = df.copy()
        df_temp['content_length'] = df_temp['Content'].str.len()
        df_temp['content_word_count'] = df_temp['Content'].str.split().str.len()
        
        # Remove extreme outliers (beyond 3 standard deviations)
        for col in ['content_length', 'content_word_count']:
            if col in df_temp.columns:
                mean_val = df_temp[col].mean()
                std_val = df_temp[col].std()
                
                # Keep only logs within 3 standard deviations
                mask = (
                    (df_temp[col] >= mean_val - 3 * std_val) &
                    (df_temp[col] <= mean_val + 3 * std_val)
                )
                df_temp = df_temp[mask]
        
        return df_temp.drop(columns=['content_length', 'content_word_count'], errors='ignore')
    
    def _final_validation(self, df):
        """Final validation and cleanup"""
        # Remove any remaining rows with null critical columns
        critical_columns = ['EventTemplate', 'EventId']
        for col in critical_columns:
            if col in df.columns:
                df = df.dropna(subset=[col])
        
        # Reset index
        df = df.reset_index(drop=True)
        
        return df
    
    def analyze_removed_patterns(self, original_df, clean_df):
        """Analyze what patterns were removed during cleaning"""
        removed_df = original_df[~original_df.index.isin(clean_df.index)]
        
        if len(removed_df) == 0:
            print("No logs were removed during cleaning")
            return
        
        print(f"\n📊 Analysis of {len(removed_df)} removed logs:")
        
        # Analyze by level
        if 'Level' in removed_df.columns:
            level_counts = removed_df['Level'].value_counts()
            print(f"   • By Level: {dict(level_counts)}")
        
        # Analyze by component
        if 'Component' in removed_df.columns:
            component_counts = removed_df['Component'].value_counts().head(10)
            print(f"   • Top Components: {dict(component_counts)}")
        
        # Show sample removed content
        if 'Content' in removed_df.columns:
            print(f"   • Sample removed content:")
            for i, content in enumerate(removed_df['Content'].head(5)):
                print(f"     {i+1}. {content[:80]}...")

def clean_and_save_training_data(input_path, output_path, aggressive=True):
    """
    Main function to clean training data and save results
    """
    print(f"🚀 Loading training data from: {input_path}")
    
    # Load data
    df = pd.read_csv(input_path)
    print(f"   • Loaded {len(df)} log entries")
    
    # Initialize cleaner
    cleaner = TrainingDataCleaner()
    
    # Clean data
    clean_df = cleaner.clean_training_data(df, aggressive=aggressive)
    
    # Analyze what was removed
    cleaner.analyze_removed_patterns(df, clean_df)
    
    # Save cleaned data
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    clean_df.to_csv(output_path, index=False)
    print(f"💾 Saved clean training data to: {output_path}")
    
    # Save cleaning report
    report_path = output_path.parent / f"{output_path.stem}_cleaning_report.txt"
    with open(report_path, 'w') as f:
        f.write(f"Training Data Cleaning Report\n")
        f.write(f"============================\n\n")
        f.write(f"Original logs: {len(df)}\n")
        f.write(f"Clean logs: {len(clean_df)}\n")
        f.write(f"Removed: {len(df) - len(clean_df)} ({((len(df) - len(clean_df))/len(df))*100:.1f}%)\n")
        f.write(f"Aggressive cleaning: {aggressive}\n")
    
    print(f"📄 Saved cleaning report to: {report_path}")
    
    return clean_df

# Usage example
if __name__ == "__main__":
    # Clean your training data
    clean_training_data = clean_and_save_training_data(
        input_path="data/logs/processed/Linux.log_structured.csv",
        output_path="cleaned_3.log_structured.csv",
        aggressive=True  # Set to False for less aggressive cleaning
    )
    
    print("\n✅ Training data cleaning complete!")
    print("📋 Next steps:")
    print("   1. Use the clean data to retrain your TF-IDF vocabulary")
    print("   2. Retrain your LSTM autoencoder with clean data")
    print("   3. Test anomaly detection on your malicious logs")
