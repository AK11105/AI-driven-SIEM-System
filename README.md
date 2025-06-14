# AI-driven-SIEM-System
A comprehensive cybersecurity solution integrating Network-Based Intrusion Detection, log-based anomaly detection, and real-time Kafka event streaming, all visualized through an interactive dashboard. Enables scalable, real-time threat monitoring and response by unifying network traffic analysis, log insights, and centralized security management.

BASE MODEL : Linux Logs

# Full pipeline (parsing + detection)
python src/logAnomalyDetection/run.py --input Linux_test.log

# Parse only
python src/logAnomalyDetection/run.py --mode parse --input Linux_test.log

# Detection only (skip parsing)
python src/logAnomalyDetection/run.py --mode detect --use-existing-csv data/logs/processed/Linux.log_structured.csv

# Full pipeline with custom configuration
python src/logAnomalyDetection/run.py --config custom-config.yml --input Linux_test.log

# Sequential anomaly detection only
python src/logAnomalyDetection/run.py --processing-mode sequential --input Linux_test.log

# Single log anomaly detection only
python src/logAnomalyDetection/run.py --processing-mode single --input Linux_test.log

# Both modes (hybrid analysis) - default
python src/logAnomalyDetection/run.py --processing-mode both --input Linux_test.log

# Custom dataset and directories
python src/logAnomalyDetection/run.py \
  --dataset Apache \
  --input-dir /custom/logs/raw/ \
  --output-dir /custom/logs/processed/ \
  --reports-dir /custom/reports/ \
  --input apache_access.log

# Different log file formats
python src/logAnomalyDetection/run.py --dataset Windows --input windows_event.log
python src/logAnomalyDetection/run.py --dataset Syslog --input system.log

# Export to default Express server (localhost:5000)
python src/logAnomalyDetection/run.py --input Linux_test.log --export-to-express

# Export to custom Express server
python src/logAnomalyDetection/run.py \
  --input Linux_test.log \
  --export-to-express \
  --express-url http://production-server:3000

# Test Express connection only
python src/logAnomalyDetection/run.py --test-express-connection
python src/logAnomalyDetection/run.py --test-express-connection --express-url http://localhost:5000

# Skip parsing with existing data + Express export
python src/logAnomalyDetection/run.py \
  --mode detect \
  --processing-mode both \
  --use-existing-csv data/logs/processed/Linux.log_structured.csv \
  --export-to-express \
  --verbose

# Custom configuration + hybrid processing + Express export
python src/logAnomalyDetection/run.py \
  --config production-config.yml \
  --processing-mode both \
  --input production_logs.log \
  --export-to-express \
  --express-url http://siem-backend:5000 \
  --verbose

# Parse only with custom paths
python src/logAnomalyDetection/run.py \
  --mode parse \
  --dataset Custom \
  --input-dir /var/log/application/ \
  --output-dir /data/processed/ \
  --input app.log \
  --verbose

# Verbose debugging
python src/logAnomalyDetection/run.py --input Linux_test.log --verbose

# Quick test with existing data
python src/logAnomalyDetection/run.py \
  --skip-parsing \
  --use-existing-csv data/logs/processed/Linux.log_structured.csv \
  --processing-mode single

# Production deployment
python src/logAnomalyDetection/run.py \
  --config production.yml \
  --input-dir /var/log/security/ \
  --reports-dir /opt/siem/reports/ \
  --export-to-express \
  --express-url http://siem-dashboard:5000

