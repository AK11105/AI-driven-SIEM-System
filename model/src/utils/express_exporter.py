import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Optional

class ExpressExporter:
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
            
            return self._send_to_logs_endpoint(logs_array)
            
        except Exception as e:
            print(f"❌ Failed to export anomalies: {e}")
            return False
    
    def _send_to_logs_endpoint(self, logs_array: List[Dict]) -> bool:
        """Send logs array to your /api/logs endpoint"""
        url = f"{self.base_url}/api/logs"
        
        for attempt in range(self.retry_attempts):
            try:
                response = requests.post(
                    url,
                    json=logs_array,  # Send as array directly
                    headers=self.headers,
                    timeout=self.timeout
                )
                
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
            # Test with your system health endpoint
            response = requests.get(
                f"{self.base_url}/api/system-health",
                headers=self.headers,
                timeout=5
            )
            
            if response.status_code == 200:
                print("✅ Express backend connection successful")
                return True
            else:
                print(f"❌ Express backend returned status {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Express backend connection failed: {e}")
            return False
