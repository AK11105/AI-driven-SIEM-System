# AI-Driven SIEM System

A comprehensive cybersecurity solution integrating Network-Based Intrusion Detection, log-based anomaly detection, and real-time Kafka event streaming, all visualized through an interactive dashboard. Enables scalable, real-time threat monitoring and response by unifying network traffic analysis, log insights, and centralized security management.

## 🚀 Features

### Core Capabilities
- **Advanced Log Anomaly Detection** - Hybrid Attention LSTM Autoencoder with ensemble learning
- **Multi-Format Log Support** - Linux, Apache, Windows, Syslog, and custom formats
- **Real-Time Processing** - Kafka event streaming for immediate threat detection
- **Interactive Dashboard** - Comprehensive visualization and monitoring interface
- **Scalable Architecture** - Designed for enterprise-level deployment

### Detection Methods
- **Sequential Analysis** - Temporal pattern detection for attack sequences
- **Individual Log Analysis** - Content-based anomaly identification
- **Hybrid Processing** - Combined approach for maximum accuracy
- **Rule-Based Classification** - Expert-defined patterns for specific threat types
- **Dynamic Severity Assessment** - Adaptive threshold learning

### Integration Features
- **Express Server Integration** - RESTful API for dashboard communication
- **Flexible Configuration** - YAML-based configuration management
- **Multiple Processing Modes** - Parse-only, detect-only, or full pipeline
- **Custom Dataset Support** - Extensible for various log formats

## 📋 Prerequisites

- Python 3.8 or higher
- PyTorch 1.9+
- CUDA-compatible GPU (recommended)
- Node.js 14+ (for dashboard)
- Apache Kafka (for real-time streaming)

## ⚡ Quick Installation

```bash
# Clone the repository
git clone https://github.com/your-org/ai-driven-siem-system.git
cd ai-driven-siem-system

# Install Python dependencies
pip install -r requirements.txt

# Initialize configuration
python setup.py --init-config

# Install dashboard dependencies (optional)
cd dashboard && npm install
```

## 🎯 Quick Start

### Basic Usage

```bash
# Full pipeline with Linux logs
python src/logAnomalyDetection/run.py --input Linux_test.log

# Quick test with existing processed data
python src/logAnomalyDetection/run.py \
  --skip-parsing \
  --use-existing-csv data/logs/processed/Linux.log_structured.csv
```

### With Dashboard Integration

```bash
# Process logs and export to dashboard
python src/logAnomalyDetection/run.py \
  --input Linux_test.log \
  --export-to-express \
  --express-url http://localhost:5000
```

## 📖 Usage Guide

### Processing Modes

#### 1. Full Pipeline (Parse + Detect)
```bash
# Default mode - complete log processing
python src/logAnomalyDetection/run.py --input Linux_test.log
```

#### 2. Parse Only
```bash
# Extract and structure logs without detection
python src/logAnomalyDetection/run.py --mode parse --input Linux_test.log
```

#### 3. Detection Only
```bash
# Skip parsing, use existing structured data
python src/logAnomalyDetection/run.py \
  --mode detect \
  --use-existing-csv data/logs/processed/Linux.log_structured.csv
```

### Detection Methods

#### Sequential Anomaly Detection
```bash
# Analyze temporal patterns and attack sequences
python src/logAnomalyDetection/run.py \
  --processing-mode sequential \
  --input Linux_test.log
```

#### Individual Log Analysis
```bash
# Content-based anomaly detection
python src/logAnomalyDetection/run.py \
  --processing-mode single \
  --input Linux_test.log
```

#### Hybrid Analysis (Recommended)
```bash
# Combined sequential and individual analysis
python src/logAnomalyDetection/run.py \
  --processing-mode both \
  --input Linux_test.log
```

### Multi-Format Support

#### Linux System Logs
```bash
python src/logAnomalyDetection/run.py --dataset Linux --input system.log
```

#### Apache Access Logs
```bash
python src/logAnomalyDetection/run.py --dataset Apache --input access.log
```

#### Windows Event Logs
```bash
python src/logAnomalyDetection/run.py --dataset Windows --input windows_event.log
```

#### Custom Log Formats
```bash
python src/logAnomalyDetection/run.py \
  --dataset Custom \
  --input-dir /path/to/logs/ \
  --output-dir /path/to/processed/ \
  --input custom.log
```

### Dashboard Integration

#### Basic Integration
```bash
# Export to default Express server (localhost:5000)
python src/logAnomalyDetection/run.py \
  --input Linux_test.log \
  --export-to-express
```

#### Production Deployment
```bash
# Custom server configuration
python src/logAnomalyDetection/run.py \
  --input production_logs.log \
  --export-to-express \
  --express-url http://siem-dashboard:5000
```

#### Connection Testing
```bash
# Test dashboard connectivity
python src/logAnomalyDetection/run.py --test-express-connection
python src/logAnomalyDetection/run.py \
  --test-express-connection \
  --express-url http://localhost:5000
```

## ⚙️ Configuration

### Custom Configuration Files

```bash
# Use custom YAML configuration
python src/logAnomalyDetection/run.py \
  --config custom-config.yml \
  --input Linux_test.log
```

### Example Configuration (`config.yml`)

```yaml
# Model Configuration
model:
  hidden_dims: [16, 24, 32]
  sequence_length: 8
  attention_heads: 4
  dropout_rate: 0.3
  learning_rate: 0.001

# Processing Configuration
processing:
  batch_size: 32
  validation_split: 0.15
  early_stopping_patience: 5

# Severity Thresholds
severity:
  low_percentile: 85
  medium_percentile: 95
  high_percentile: 99
  critical_percentile: 99.9

# Output Configuration
output:
  save_reports: true
  export_format: ["json", "csv"]
  include_visualizations: true
```

### Advanced Usage Examples

#### Production Deployment
```bash
python src/logAnomalyDetection/run.py \
  --config production.yml \
  --input-dir /var/log/security/ \
  --reports-dir /opt/siem/reports/ \
  --export-to-express \
  --express-url http://siem-dashboard:5000 \
  --verbose
```

#### Batch Processing
```bash
python src/logAnomalyDetection/run.py \
  --dataset Apache \
  --input-dir /var/log/apache/ \
  --output-dir /data/processed/ \
  --reports-dir /data/reports/ \
  --input access.log \
  --processing-mode both \
  --export-to-express
```

#### Development and Testing
```bash
# Verbose debugging
python src/logAnomalyDetection/run.py \
  --input Linux_test.log \
  --verbose

# Quick development test
python src/logAnomalyDetection/run.py \
  --skip-parsing \
  --use-existing-csv data/logs/processed/Linux.log_structured.csv \
  --processing-mode single \
  --verbose
```

## 🏗️ System Architecture

### Core Components

1. **Brain Log Parser** - Converts raw logs to structured format
2. **Hybrid Neural Network** - Dual-path LSTM-Autoencoder ensemble
3. **Rule-Based Classifier** - Semantic anomaly categorization
4. **Severity Manager** - Dynamic threshold learning and scoring
5. **Dashboard Interface** - Real-time visualization and monitoring

### Processing Pipeline

```
Raw Logs → Parser → Feature Engineering → Neural Processing → Classification → Reporting
```

### Detection Methods

- **Sequential Path**: Bidirectional LSTM with multi-head attention
- **Single Log Path**: Multi-layer perceptron with progressive reduction
- **Fusion Layer**: Learned combination of both pathways
- **Ensemble Strategy**: Multiple model configurations for robust detection

## 📊 Performance

### Detection Capabilities
- **Anomaly Types**: Memory errors, authentication failures, filesystem issues, network problems, permission violations, critical system events
- **Severity Levels**: Low (85-95th percentile), Medium (95-99th), High (99th+), Critical (top 0.1%)
- **Processing Modes**: Real-time individual analysis, temporal sequence analysis, hybrid approach

### Computational Requirements
- **Training**: GPU recommended, 8GB+ VRAM
- **Inference**: CPU sufficient, <100ms latency
- **Memory**: 4GB+ RAM for typical datasets
- **Storage**: Minimal overhead, configurable retention

## 🔧 API Reference

### Core Classes

#### HybridEnsembleDetector
```python
from model import HybridEnsembleDetector

# Initialize detector
detector = HybridEnsembleDetector(config=custom_config)

# Train on data
detector.train('data/logs/processed/Linux.csv')

# Make predictions
results = detector.predict('new_logs.csv', mode='hybrid')

# Save deployment package
detector.save_deployment_package('model.pkl')

# Load trained model
detector = HybridEnsembleDetector.load('model.pkl')
```

#### EnhancedSeverityManager
```python
from severity import EnhancedSeverityManager

# Initialize severity manager
severity_mgr = EnhancedSeverityManager()

# Learn thresholds from data
severity_mgr.learn_thresholds(error_array, percentiles=[85, 95, 99])

# Classify with confidence
severity, confidence = severity_mgr.classify_with_confidence(error_value)
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--input` | Input log file path | Required |
| `--mode` | Processing mode: `full`, `parse`, `detect` | `full` |
| `--processing-mode` | Detection mode: `sequential`, `single`, `both` | `both` |
| `--config` | Custom configuration file | `config.yml` |
| `--dataset` | Log format: `Linux`, `Apache`, `Windows`, `Syslog`, `Custom` | `Linux` |
| `--input-dir` | Custom input directory | `data/logs/raw/` |
| `--output-dir` | Custom output directory | `data/logs/processed/` |
| `--reports-dir` | Custom reports directory | `reports/` |
| `--export-to-express` | Enable dashboard export | `False` |
| `--express-url` | Dashboard server URL | `http://localhost:5000` |
| `--verbose` | Enable verbose logging | `False` |

## 🚀 Deployment

### Development Environment
```bash
# Start development server
python src/logAnomalyDetection/run.py \
  --input sample_logs.log \
  --export-to-express \
  --verbose
```

### Production Environment
```bash
# Production deployment with custom configuration
python src/logAnomalyDetection/run.py \
  --config production.yml \
  --input-dir /var/log/security/ \
  --reports-dir /opt/siem/reports/ \
  --export-to-express \
  --express-url http://siem-dashboard:5000
```

### Docker Deployment
```bash
# Build Docker image
docker build -t ai-siem-system .

# Run container
docker run -v /var/log:/app/logs -p 5000:5000 ai-siem-system
```

## 🔍 Troubleshooting

### Common Issues

#### Model Loading Errors
```bash
# Verify model file exists and permissions
ls -la model.pkl
python -c "import torch; print(torch.__version__)"
```

#### Dashboard Connection Issues
```bash
# Test Express server connection
python src/logAnomalyDetection/run.py --test-express-connection
curl -X GET http://localhost:5000/health
```

#### Memory Issues
```bash
# Reduce batch size in configuration
# Enable CPU-only mode for inference
export CUDA_VISIBLE_DEVICES=""
```

### Performance Optimization

#### GPU Acceleration
```bash
# Verify CUDA availability
python -c "import torch; print(torch.cuda.is_available())"

# Monitor GPU usage
nvidia-smi -l 1
```

#### Batch Processing
```bash
# Process large datasets in chunks
python src/logAnomalyDetection/run.py \
  --input large_dataset.log \
  --config batch-config.yml
```

## 📈 Monitoring

### Dashboard Features
- Real-time anomaly detection results
- Severity distribution visualization
- Performance metrics and trends
- Historical analysis and reporting

### Logging and Alerts
- Configurable log levels (DEBUG, INFO, WARN, ERROR)
- Structured JSON logging for integration
- Alert thresholds and notification system
- Performance monitoring and profiling

## 🤝 Contributing

### Development Setup
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Code formatting
black src/
flake8 src/
```

### Adding New Log Formats
1. Create parser in `src/parsers/`
2. Add configuration in `config/datasets/`
3. Update dataset registry in `src/core/datasets.py`
4. Add tests in `tests/parsers/`

### Performance Improvements
- Model architecture optimizations
- Feature engineering enhancements
- Computational efficiency improvements
- Memory usage optimizations

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support

### Documentation
- [API Reference](docs/api.md)
- [Configuration Guide](docs/configuration.md)
- [Deployment Guide](docs/deployment.md)
- [Troubleshooting](docs/troubleshooting.md)

### Community
- GitHub Issues: [Report bugs and request features](https://github.com/your-org/ai-driven-siem-system/issues)
- Discussions: [Community support and questions](https://github.com/your-org/ai-driven-siem-system/discussions)
- Wiki: [Additional documentation and examples](https://github.com/your-org/ai-driven-siem-system/wiki)

---

**Built with ❤️ for cybersecurity professionals and researchers**