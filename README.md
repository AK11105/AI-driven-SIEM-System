# AI-driven-SIEM-System
A comprehensive cybersecurity solution integrating Network-Based Intrusion Detection, log-based anomaly detection, and real-time Kafka event streaming, all visualized through an interactive dashboard. Enables scalable, real-time threat monitoring and response by unifying network traffic analysis, log insights, and centralized security management.

BASE MODEL : Linux Logs

To run: 

# Full pipeline (parse + detect)
python src/logAnomalyDetection/run.py --input Linux_test.log --verbose

# Parse only
python src/logAnomalyDetection/run.py --mode parse --input Linux_test.log

# Detect only using existing structured data
python src/logAnomalyDetection/run.py --mode detect --use-existing-csv data/logs/processed/Linux_test.log_structured.csv

# Custom configuration and paths
python src/logAnomalyDetection/run.py \
  --input Linux_test.log \
  --input-dir data/logs/raw/ \
  --output-dir data/logs/processed/ \
  --reports-dir reports/logAnomalyDetection/ \
  --config configs/custom-config.yml \
  --verbose

# Skip parsing and use existing data
python src/logAnomalyDetection/run.py \
  --skip-parsing \
  --use-existing-csv data/logs/processed/Linux.log_structured.csv \
  --verbose
